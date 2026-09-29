// Moteur d'analyse : aucune dépendance au DOM, testable sous Node.
import TACTICS_DATA from '../rules/tactics.json' with { type: 'json' };
import D3_DATA from '../rules/d3fend.json' with { type: 'json' };
import RULES_DATA from '../rules/attack-rules.json' with { type: 'json' };

export const TACTICS = TACTICS_DATA;
export const TAC = Object.fromEntries(TACTICS.map(t => [t.key, t]));
export const D3 = D3_DATA;
export const SEV = { 4: 'Critique', 3: 'Élevée', 2: 'Moyenne', 1: 'Faible' };
export const CONFL = { 3: 'haute', 2: 'moyenne', 1: 'faible' };

export const d3Url = name => 'https://d3fend.mitre.org/technique/d3f:' + name.replace(/\s+/g, '') + '/';
export const attackUrl = id => 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';

// Une technique est retenue quand la somme des poids de ses motifs distincts atteint ce seuil.
export const THRESHOLD = 1;

export function compileRules(data) {
  return data.map(r => ({
    ...r,
    patterns: r.patterns.map(p => ({ ...p, re: new RegExp(p.regex, p.flags) })),
  }));
}
export const RULES = compileRules(RULES_DATA);

/* ---------- Authentification (brute force, spraying, succès après échecs) ---------- */
export const FAIL = /(failed password|authentication failure|invalid user|failed login|login failed|logon failure|failed to log on|\beventid[=:\s]*4625\b|\b4625\b|0xc000006[ad])/i;
export const OKAUTH = /(accepted (password|publickey|keyboard-interactive)|successfully logged on|\beventid[=:\s]*4624\b|login succeeded|authentication succeeded)/i;
const USER_RE = /(?:new user:\s*name=|for invalid user |invalid user |for user |targetusername[=:\s]+|account name:\s*|user(?:name)?[=:]\s*|for (?=\S+ from\b))([A-Za-z0-9._$@\\-]{2,})/i;
export const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const SRCIP_RE = /(?:from|rhost=|ipaddress[=:\s]+|source network address:\s*|src(?:_?ip)?[=:\s]+|client[=:\s]+)\s*((?:\d{1,3}\.){3}\d{1,3})/i;
export const userOf = l => (l.match(USER_RE) || [])[1];
export const ipOf = l => (l.match(SRCIP_RE) || [])[1] || (l.match(IP_RE) || [])[0];

export function authFindings(lines) {
  const fails = [], oks = [], out = [];
  lines.forEach((l, i) => {
    if (FAIL.test(l)) fails.push({ i, u: userOf(l), ip: ipOf(l) });
    else if (OKAUTH.test(l)) oks.push({ i, u: userOf(l), ip: ipOf(l) });
  });
  if (!fails.length) return out;

  const by = {};
  for (const f of fails) {
    const k = f.ip || '?';
    by[k] ||= { n: 0, users: new Set(), first: f.i, lines: [] };
    by[k].n++;
    if (f.u) by[k].users.add(f.u);
    by[k].lines.push(f.i);
  }
  const spray = Object.entries(by).filter(([, v]) => v.users.size >= 4 && v.n >= 4);
  const brute = Object.entries(by).filter(([, v]) => v.n >= 5 && v.users.size < 4);

  if (spray.length) {
    const [ip, v] = spray[0];
    out.push({
      id: 'T1110.003', name: 'Password Spraying', tactics: ['cred'], severity: 3, score: 3.5,
      ev: spray.flatMap(([, x]) => x.lines).map(i => ({ i, re: FAIL })), d3fend: ['ANET', 'SPP', 'MFA', 'AL'],
      note: `${v.n} échecs sur ${v.users.size} comptes différents depuis ${ip}.`,
      checks: ['Bloquer la source et lister les comptes visés.', 'Vérifier si l’un d’eux a réussi ensuite.'],
    });
  }
  if (brute.length) {
    const [ip, v] = brute[0];
    out.push({
      id: 'T1110.001', name: 'Password Guessing', tactics: ['cred'], severity: 3, score: 3.5,
      ev: brute.flatMap(([, x]) => x.lines).map(i => ({ i, re: FAIL })), d3fend: ['ANET', 'MFA', 'AL', 'ITF'],
      note: `${v.n} échecs depuis ${ip} sur ${[...v.users].slice(0, 3).join(', ') || 'compte inconnu'}.`,
      checks: ['Bloquer la source au pare-feu.', 'Vérifier l’exposition du service (SSH/RDP sur Internet ?).'],
    });
  }
  if (!spray.length && !brute.length) {
    out.push({
      id: 'T1110.001', name: 'Password Guessing', tactics: ['cred'], severity: 1, score: 1,
      ev: fails.map(f => ({ i: f.i, re: FAIL })), d3fend: ['ANET', 'AL'],
      note: `${fails.length} échec(s) isolé(s) : en dessous du seuil de brute force.`,
      checks: ['Probablement une faute de frappe ; surveiller la récurrence.'],
    });
  }
  const hits = oks.filter(o => o.ip && by[o.ip] && by[o.ip].n >= 3 && o.i > by[o.ip].first);
  if (hits.length) {
    const o = hits[0];
    out.push({
      id: 'T1078', name: 'Valid Accounts', tactics: ['ia', 'persist', 'privesc', 'defev'], severity: 4, score: 4,
      ev: hits.map(h => ({ i: h.i, re: OKAUTH })), d3fend: ['MFA', 'UGLPA', 'AL', 'CR', 'UBA'],
      note: `Connexion réussie${o.u ? ` pour ${o.u}` : ''} depuis ${o.ip} après ${by[o.ip].n} échecs : le mot de passe a probablement été trouvé.`,
      checks: ['Désactiver le compte et fermer ses sessions.', 'Examiner tout ce que ce compte a fait après cette ligne.'],
    });
  }
  return out;
}

/* ---------- Normalisation : un événement par ligne ---------- */
// Les règles lisent des lignes « clé=valeur ». JSON (tableau, objet, JSONL) et export XML Windows (EVTX) sont aplatis
// ainsi ; tout autre texte est gardé tel quel, une ligne par événement.
const TS_KEY = /^(@timestamp|timestamp|utctime|timecreated|systemtime|eventtime|time|date)$/i;

// Clé gardée : la feuille (CommandLine, Image…), sauf feuille trop générique où le parent est ajouté (host.name) ;
// quelques champs ECS / Elastic sont renommés vers leur équivalent Windows.
const ALIAS = {
  'event.code': 'EventID', 'host.name': 'host', 'host.hostname': 'host', 'user.name': 'user', 'source.ip': 'src_ip', 'destination.ip': 'DestinationIp',
  'process.command_line': 'CommandLine', 'process.executable': 'Image', 'parent.command_line': 'ParentCommandLine', 'parent.executable': 'ParentImage',
  'file.path': 'TargetFilename', 'destination.port': 'DestinationPort',
};
const GENERIC = /^(name|code|id|type|value|ip|address|hostname)$/i;
function flatten(obj, out = [], path = []) {
  if (Array.isArray(obj)) obj.forEach(v => flatten(v, out, path));
  else if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object') flatten(v, out, [...path, k]);
    else if (v !== null && v !== '') {
      const two = [path.at(-1), k].filter(Boolean).join('.');
      out.push([ALIAS[two.toLowerCase()] || (GENERIC.test(k) && path.length ? two : k), String(v)]);
    }
  }
  return out;
}
function kvLine(pairs) {
  const ts = pairs.find(([k]) => TS_KEY.test(k));
  return (ts ? ts[1] + ' ' : '') + pairs.filter(p => p !== ts).map(([k, v]) => `${k}=${/\s/.test(v) ? `"${v}"` : v}`).join(' ');
}
const records = j => (Array.isArray(j) ? j : j.Records || j.records || j.events || j.hits?.hits || [j]);
const unxml = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

function xmlEvent(ev) {
  const pairs = [];
  const ts = ev.match(/<TimeCreated[^>]*SystemTime=["']([^"']+)/i);
  if (ts) pairs.push(['TimeCreated', ts[1]]);
  for (const m of ev.matchAll(/<(EventID|Computer|Channel|Provider)\b([^>]*?)(?:\/>|>([^<]*)<\/\1>)/gi)) {
    const v = m[3] ?? (m[2].match(/Name=["']([^"']+)/) || [])[1];
    if (v) pairs.push([m[1], unxml(v.trim())]);
  }
  for (const m of ev.matchAll(/<Data\s+Name=["']([^"']+)["']\s*>([^<]*)<\/Data>/gi)) if (m[2].trim()) pairs.push([m[1], unxml(m[2].trim())]);
  return pairs;
}

// Champs d'une ligne texte, pour les règles Sigma : paires « clé=valeur » (une valeur non citée court jusqu'à la clé
// suivante, ce qui garde « C:\Program Files\… » entier) et champs W3C d'une ligne access.log (format combiné).
const KV_KEY = /(?:^|\s)([A-Za-z_][\w.-]*)=/g;
const ACCESS = /^(\S+) \S+ (\S+) \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "([^"]*)" "([^"]*)")?/;
export function textFields(line) {
  const out = {};
  const keys = [...line.matchAll(KV_KEY)];
  keys.forEach((m, k) => {
    const start = m.index + m[0].length, end = k + 1 < keys.length ? keys[k + 1].index : line.length;
    let v = line.slice(start, end).trim();
    if (/^".*"$/.test(v) || /^'.*'$/.test(v)) v = v.slice(1, -1);
    const name = m[1].toLowerCase();
    if (!(name in out)) out[name] = v;
  });
  const a = line.match(ACCESS);
  if (a) {
    const [stem, query = ''] = a[4].split(/\?(.*)/s);
    Object.assign(out, { 'c-ip': a[1], 'cs-username': a[2], 'cs-method': a[3], 'c-uri': a[4], 'cs-uri-stem': stem, 'cs-uri-query': query,
      'c-uri-query': query, 'sc-status': a[5], 'cs-referer': a[6] ?? '', 'c-useragent': a[7] ?? '', 'cs-user-agent': a[7] ?? '' });
  }
  return out;
}
const fieldsOf = pairs => { const o = {}; for (const [k, v] of pairs) { const n = k.toLowerCase(); if (!(n in o)) o[n] = v; } return o; };
const ev = pairs => ({ line: kvLine(pairs), fields: fieldsOf(pairs) });
const pack = (format, evs) => ({ format, lines: evs.map(e => e.line), fields: evs.map(e => e.fields) });

// → { format, lines : une chaîne par événement, fields : un objet { champ en minuscules: valeur } par événement }.
export function toEvents(text) {
  const t = text.trim();
  const asText = l => ({ line: l, fields: textFields(l) });
  if (/^[[{]/.test(t)) {
    try { return pack('JSON', records(JSON.parse(t)).map(r => ev(flatten(r)))); } catch { /* peut-être du JSONL */ }
    const raw = text.split(/\r?\n/);
    const parsed = raw.map(l => { try { return /^\s*\{/.test(l) ? JSON.parse(l) : null; } catch { return null; } });
    if (parsed.some(Boolean)) return pack('JSONL', raw.map((l, i) => (parsed[i] ? ev(flatten(parsed[i])) : asText(l))));
  }
  if (/<Event[\s>]/.test(t) && /<\/Event>/.test(t)) {
    return pack('XML Windows', t.match(/<Event[\s>][\s\S]*?<\/Event>/g).map(e => ev(xmlEvent(e))));
  }
  return pack('texte', text.split(/\r?\n/).map(asText));
}

/* ---------- Règles Sigma ---------- */
// Contre-mesures par défaut d'une technique inconnue des règles locales, selon sa première tactique.
const TACTIC_D3 = { recon: ['CAA', 'ITF'], resdev: ['DNRA', 'IPRA'], ia: ['ITF', 'SU'], exec: ['PSA', 'EAL'], persist: ['SICA', 'SJA'],
  privesc: ['UAP', 'SCP'], defev: ['SCP', 'PSA'], cred: ['CH', 'CR'], disc: ['UBA', 'PSA'], lm: ['RTSD', 'UAP'], coll: ['FAPA', 'RAPA'],
  c2: ['NTA', 'OTF'], exfil: ['OTF', 'PHDURA'], impact: ['RF', 'FAPA'] };
const NOHL = /$^/;

export function sigmaFindings(lines, fields, sigma, detected = new Set()) {
  const byTech = new Map();
  for (const r of sigma) {
    const ev = [];
    lines.forEach((l, i) => {
      if (!l.trim()) return;
      const hits = [];
      if (r.match(fields[i] || {}, l, hits)) ev.push({ i, re: hits[0] || NOHL });
    });
    if (!ev.length) continue;
    // Une règle peut citer plusieurs techniques : on privilégie une technique déjà détectée, puis une technique
    // que les règles locales connaissent, sinon la première citée.
    const id = r.techniques.find(t => detected.has(t)) || r.techniques.find(t => RULES.some(x => x.id === t)) || r.techniques[0];
    const native = RULES.find(x => x.id === id);
    const f = byTech.get(id) || {
      id, name: native?.name || r.title, tactics: native?.tactics || (r.tactics.length ? r.tactics : []),
      severity: 0, score: 0, ev: [], sigma: [],
      d3fend: native?.d3fend || TACTIC_D3[r.tactics[0]] || ['PSA'],
      checks: [...(native?.checks || [])],
    };
    f.severity = Math.max(f.severity, r.severity);
    f.score = Math.max(f.score, r.score);
    const seen = new Set(f.ev.map(e => e.i));
    f.ev.push(...ev.filter(e => !seen.has(e.i)));
    f.ev.sort((a, b) => a.i - b.i);
    f.sigma.push(r.title);
    if (r.falsepositives.length) f.checks.push(`Faux positifs connus (Sigma « ${r.title} ») : ${r.falsepositives.join(' ; ')}.`);
    if (!f.checks.length) f.checks.push(`Examiner les lignes qui déclenchent la règle Sigma « ${r.title} ».`);
    byTech.set(id, f);
  }
  return [...byTech.values()];
}

/* ---------- Analyse ---------- */
const confOf = s => (s >= 3 ? 3 : s >= 2 ? 2 : 1);

export function analyze(text, rules = RULES, sigma = []) {
  const { lines, format, fields } = toEvents(text);
  const found = new Map();
  for (const r of rules) {
    const hitPat = new Set(), ev = [];
    lines.forEach((l, i) => {
      if (!l.trim()) return;
      let best = null;
      r.patterns.forEach((p, j) => {
        if (p.re.test(l)) {
          hitPat.add(j);
          if (best === null || p.weight > r.patterns[best].weight) best = j;
        }
      });
      if (best !== null) ev.push({ i, re: r.patterns[best].re });
    });
    if (!ev.length) continue;
    const score = [...hitPat].reduce((a, j) => a + r.patterns[j].weight, 0) + Math.min(ev.length - 1, 2) * 0.5;
    if (score < THRESHOLD) continue;
    found.set(r.id, { id: r.id, name: r.name, tactics: r.tactics, severity: r.severity, d3fend: r.d3fend, checks: r.checks, ev, score, native: true });
  }
  for (const f of sigmaFindings(lines, fields, sigma, new Set(found.keys()))) {
    const prev = found.get(f.id);
    if (prev) {
      const seen = new Set(prev.ev.map(e => e.i));
      prev.ev = [...prev.ev, ...f.ev.filter(e => !seen.has(e.i))].sort((a, b) => a.i - b.i);
      prev.score = Math.max(prev.score, f.score);
      prev.severity = Math.max(prev.severity, f.severity);
      prev.sigma = f.sigma;
    } else found.set(f.id, f);
  }
  for (const f of authFindings(lines)) {
    const prev = found.get(f.id);
    if (prev) {
      prev.score = Math.max(prev.score, f.score);
      prev.severity = Math.max(prev.severity, f.severity);
      prev.note = f.note;
      prev.ev = [...f.ev, ...prev.ev];
      prev.native = true;
    } else found.set(f.id, { ...f, native: true });
  }
  const list = [...found.values()]
    .map(f => ({ ...f, conf: confOf(f.score) }))
    .sort((a, b) => b.severity - a.severity || b.conf - a.conf || a.ev[0].i - b.ev[0].i);
  return { lines, list, format };
}

// Niveau global : sévérité max parmi les détections de confiance moyenne ou haute, sinon sévérité max tout court.
export function overallLevel(list) {
  return list.filter(f => f.conf >= 2).reduce((m, f) => Math.max(m, f.severity), 0)
    || list.reduce((m, f) => Math.max(m, f.severity), 0);
}

/* ---------- Priorisation D3FEND ---------- */
export function prioritize(list) {
  const agg = {};
  for (const f of list) {
    const w = f.severity * [0, 0.5, 0.75, 1][f.conf];
    f.d3fend.forEach((k, idx) => {
      agg[k] ||= { k, score: 0, techs: [] };
      agg[k].score += w * (1 - idx * 0.12);
      if (!agg[k].techs.includes(f.id)) agg[k].techs.push(f.id);
    });
  }
  return Object.values(agg).sort((a, b) => b.score - a.score || b.techs.length - a.techs.length);
}

/* ---------- Indicateurs ---------- */
// Machine source : champ explicite (host=, Computer=…), sinon le mot qui suit l'horodatage en tête de ligne (syslog, Sysmon texte).
const HOST_KV = /\b(?:host(?:name)?|computer(?:name)?|machine name|workstationname|dvc_host|device)[=:]\s*"?([A-Za-z0-9][\w.-]{1,62})/i;
const HOST_LEAD = /^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d[.,\d]*(?:Z|[+-]\d\d:?\d\d)?)\s+([A-Za-z][\w.-]{1,62})\s/;
export const hostOf = l => {
  const h = (l.match(HOST_KV) || l.match(HOST_LEAD) || [])[1];
  return h && !IP_RE.test(h) && !/^(host|eventid|sysmon|security|info|warn|error|debug)\b/i.test(h) ? h : undefined;
};

export const isPrivateIp = ip => /^(10\.|127\.|192\.168\.|169\.254\.|0\.|255\.)/.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
const TLDS = 'com|net|org|io|ru|cn|xyz|top|info|biz|fr|de|uk|sh|nz|me|cc|tk|onion|site|online|club|live|app|dev|su|pw|icu|ws';

export function extractIOC(input) {
  const text = toEvents(input).lines.join('\n');
  const uniq = a => [...new Set(a)];
  const ips = uniq(text.match(new RegExp(IP_RE.source, 'g')) || []);
  const urls = uniq((text.match(/\bhttps?:\/\/[^\s"'<>)\]]+/gi) || []).map(u => u.replace(/[.,;]+$/, '')));
  const hashes = uniq((text.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) || []).map(h => h.toLowerCase()));
  const files = uniq((text.match(/[\w.-]+\.(?:exe|dll|ps1|bat|vbs|js|hta|scr|dmp|7z|docm|xlsm|lnk|iso|php|aspx|sh)\b/gi) || []).map(f => f.toLowerCase()))
    .filter(f => !/^(cmd|powershell|rundll32|svchost|lsass|conhost)\.exe$/.test(f) || /users|public|temp/i.test(text));
  // Un nom de fichier (x.sh, update.sh) n'est pas un domaine.
  const doms = uniq((text.match(new RegExp(`\\b(?:[a-z0-9-]+\\.)+(?:${TLDS})\\b`, 'gi')) || [])
    .map(d => d.toLowerCase()).filter(d => !/\.(exe|dll|ps1)$/.test(d) && !files.includes(d)));
  const users = uniq(text.split(/\r?\n/).map(userOf).filter(u => u && !/^(invalid|user|the|root\.)$/i.test(u)));
  const hosts = uniq(text.split(/\r?\n/).map(hostOf).filter(Boolean));
  return { ips, urls, doms, hashes, files, users, hosts };
}
