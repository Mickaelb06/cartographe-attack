// Règles Sigma (https://sigmahq.io) : lecture YAML, compilation, évaluation sur les champs des événements.
// Sous-ensemble pris en charge : sélections (champs ou mots-clés), modificateurs contains / startswith / endswith /
// all / re (i, m, s) / windash / cidr / exists, jokers * et ?, conditions and / or / not / parenthèses / « 1 of » / « all of ».
// Non pris en charge (règle ignorée, raison affichée) : agrégations « | count() », base64, fieldref, corrélations.
import yaml from 'js-yaml';

const LEVEL_SEV = { critical: 4, high: 3, medium: 2, low: 1, informational: 1 };
const LEVEL_SCORE = { critical: 3, high: 3, medium: 2, low: 1, informational: 1 };
// Tags de tactique Sigma → clés de rules/tactics.json. Stealth et defense-impairment (découpage récent de
// Defense Evasion dans ATT&CK) sont rattachés à Defense Evasion.
const TACTIC_TAG = {
  reconnaissance: 'recon', resource_development: 'resdev', initial_access: 'ia', execution: 'exec',
  persistence: 'persist', privilege_escalation: 'privesc', defense_evasion: 'defev', stealth: 'defev',
  defense_impairment: 'defev', credential_access: 'cred', discovery: 'disc', lateral_movement: 'lm',
  collection: 'coll', command_and_control: 'c2', exfiltration: 'exfil', impact: 'impact',
};

const reEsc = s => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
// Valeur Sigma → source de regex : * et ? sont des jokers, \* \? \\ des caractères littéraux.
function wildcard(v) {
  let out = '';
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '\\' && i + 1 < v.length && '*?\\'.includes(v[i + 1])) out += reEsc(v[++i]);
    else if (c === '*') out += '.*';
    else if (c === '?') out += '.';
    else out += reEsc(c);
  }
  return out;
}
const DASHES = ['-', '/', '–', '—', '―'];

function ipv4(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return m ? m.slice(1).reduce((a, b) => a * 256 + Number(b), 0) : null;
}
function cidrTest(cidr) {
  if (String(cidr).includes(':')) return () => false; // IPv6 : non évalué, la valeur ne correspond jamais
  const [net, bits = '32'] = String(cidr).split('/');
  const base = ipv4(net), n = Number(bits);
  if (base === null || !(n >= 0 && n <= 32)) throw new Error(`CIDR invalide : ${cidr}`);
  const size = 2 ** (32 - n), start = base - (base % size);
  return v => { const x = ipv4(v); return x !== null && x >= start && x < start + size; };
}

// Un test de valeur : { test(fieldValue) → bool, hl : regex non ancrée pour surligner la ligne }.
function valueTests(raw, mods) {
  if (raw === null) return [{ nullTest: true }];
  const v = String(raw);
  if (mods.includes('cidr')) return [{ test: cidrTest(v), hl: new RegExp(reEsc(v.split('/')[0].split('.').slice(0, 2).join('.')), 'i') }];
  if (mods.includes('re')) {
    // Drapeaux en tête « (?i) », fréquents dans SigmaHQ (syntaxe Python/PCRE), convertis en drapeaux JavaScript.
    const lead = v.match(/^\(\?([ims]+)\)/);
    const flags = [...new Set([...['i', 'm', 's'].filter(f => mods.includes(f)), ...(lead ? lead[1] : '')])].join('');
    const re = new RegExp(lead ? v.slice(lead[0].length) : v, flags);
    return [{ test: x => re.test(x), hl: re }];
  }
  const variants = mods.includes('windash') ? [...new Set(DASHES.map(d => v.replace(/(^|\s)-/g, `$1${d}`)))] : [v];
  return variants.map(s => {
    const body = wildcard(s);
    const src = mods.includes('contains') ? body : mods.includes('startswith') ? `^${body}` : mods.includes('endswith') ? `${body}$` : `^${body}$`;
    const re = new RegExp(src, 'is');
    return { test: x => re.test(x), hl: body && body !== '.*' ? new RegExp(body, 'i') : null };
  });
}

const KNOWN_MODS = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'i', 'm', 's', 'windash', 'cidr', 'exists']);

function fieldMatcher(key, value) {
  const [field, ...mods] = key.split('|');
  for (const m of mods) if (!KNOWN_MODS.has(m)) throw new Error(`modificateur « ${m} » non pris en charge`);
  const name = field.toLowerCase();
  if (mods.includes('exists')) return (fields) => ((name in fields) === (value !== false) ? { ok: true } : { ok: false });
  const values = Array.isArray(value) ? value : [value];
  const tests = values.map(v => valueTests(v, mods));
  const all = mods.includes('all');
  return (fields) => {
    const fv = fields[name];
    const one = t => t.some(x => (x.nullTest ? fv === undefined || fv === '' : fv !== undefined && x.test(fv)));
    const ok = all ? tests.every(one) : tests.some(one);
    if (!ok) return { ok: false };
    const hit = tests.find(one)?.find(x => !x.nullTest && fv !== undefined && x.test(fv));
    return { ok: true, re: hit?.hl || null };
  };
}

function keywordMatcher(words) {
  const tests = words.flatMap(w => valueTests(w, ['contains']));
  return (fields, line) => {
    const t = tests.find(x => x.test(line));
    return t ? { ok: true, re: t.hl } : { ok: false };
  };
}

function selectionMatcher(sel) {
  if (sel === null || typeof sel !== 'object') return keywordMatcher([sel]);
  if (Array.isArray(sel)) {
    const words = sel.filter(x => x === null || typeof x !== 'object');
    const maps = sel.filter(x => x && typeof x === 'object').map(selectionMatcher);
    const parts = [...(words.length ? [keywordMatcher(words)] : []), ...maps];
    return (f, l) => { for (const p of parts) { const r = p(f, l); if (r.ok) return r; } return { ok: false }; };
  }
  const parts = Object.entries(sel).map(([k, v]) => fieldMatcher(k, v));
  return (f, l) => {
    let re = null;
    for (const p of parts) { const r = p(f, l); if (!r.ok) return r; re ||= r.re; }
    return { ok: true, re };
  };
}

/* ---------- Condition ---------- */
function tokenize(cond) {
  if (/\|/.test(cond)) throw new Error('agrégation (« | count() … ») non prise en charge');
  return cond.match(/\(|\)|[^\s()]+/g) || [];
}
function parseCondition(cond, names) {
  const tk = tokenize(cond);
  let i = 0;
  const peek = () => tk[i]?.toLowerCase();
  const expect = t => { if (peek() !== t) throw new Error(`condition illisible : « ${cond} »`); i++; };
  const expand = pat => {
    if (pat === 'them') return names.filter(n => !n.startsWith('_'));
    const re = new RegExp('^' + wildcard(pat) + '$');
    const m = names.filter(n => re.test(n));
    if (!m.length) throw new Error(`aucune sélection ne correspond à « ${pat} »`);
    return m;
  };
  function primary() {
    const t = peek();
    if (t === '(') { i++; const e = orExpr(); expect(')'); return e; }
    if (t === 'not') { i++; const e = primary(); return { not: e }; }
    if ((t === '1' || t === 'all' || t === 'any') && tk[i + 1]?.toLowerCase() === 'of') {
      const q = t === 'all' ? 'all' : 'any'; i += 2;
      const pat = tk[i++];
      if (!pat) throw new Error(`condition incomplète : « ${cond} »`);
      return { [q]: expand(pat) };
    }
    if (!tk[i]) throw new Error(`condition incomplète : « ${cond} »`);
    const name = tk[i++];
    if (!names.includes(name)) throw new Error(`sélection inconnue « ${name} »`);
    return { sel: name };
  }
  function andExpr() { let e = primary(); while (peek() === 'and') { i++; e = { and: [e, primary()] }; } return e; }
  function orExpr() { let e = andExpr(); while (peek() === 'or') { i++; e = { or: [e, andExpr()] }; } return e; }
  const ast = orExpr();
  if (i < tk.length) throw new Error(`condition illisible : « ${cond} »`);
  return ast;
}
function evalAst(ast, ctx, hits) {
  if (ast.sel) { const r = ctx(ast.sel); if (r.ok && r.re) hits.push(r.re); return r.ok; }
  if (ast.not) return !evalAst(ast.not, ctx, []);
  if (ast.and) return ast.and.every(a => evalAst(a, ctx, hits));
  if (ast.or) return ast.or.some(a => evalAst(a, ctx, hits));
  if (ast.all) return ast.all.every(n => evalAst({ sel: n }, ctx, hits));
  if (ast.any) return ast.any.some(n => evalAst({ sel: n }, ctx, hits));
  return false;
}

/* ---------- Règle ---------- */
export function compileSigma(doc, origin = 'importée') {
  const { detection } = doc;
  if (!doc.title) throw new Error('pas de titre');
  if (!detection || typeof detection !== 'object') throw new Error('pas de section detection');
  if (doc.correlation) throw new Error('règle de corrélation non prise en charge');
  const names = Object.keys(detection).filter(k => k !== 'condition' && k !== 'timeframe');
  const sels = Object.fromEntries(names.map(n => [n, selectionMatcher(detection[n])]));
  const conds = Array.isArray(detection.condition) ? detection.condition : [detection.condition];
  if (!conds[0]) throw new Error('pas de condition');
  const ast = conds.length > 1 ? { or: conds.map(c => parseCondition(String(c), names)) } : parseCondition(String(conds[0]), names);
  const tags = (doc.tags || []).map(t => String(t).toLowerCase());
  const techniques = tags.filter(t => /^attack\.t\d{4}(\.\d{3})?$/.test(t)).map(t => t.slice(7).toUpperCase());
  const tactics = [...new Set(tags.map(t => TACTIC_TAG[t.slice(7).replace(/-/g, '_')]).filter(Boolean))];
  const level = String(doc.level || 'medium').toLowerCase();
  return {
    id: doc.id || doc.title, title: String(doc.title), origin, level,
    severity: LEVEL_SEV[level] || 2, score: LEVEL_SCORE[level] || 2,
    techniques, tactics,
    falsepositives: (doc.falsepositives || []).map(String).filter(f => !/^unknown$/i.test(f)),
    match(fields, line, hits) {
      const cache = {};
      return evalAst(ast, n => (cache[n] ||= sels[n](fields, line)), hits);
    },
  };
}

// Texte YAML (un ou plusieurs documents séparés par ---) → règles compilées et erreurs lisibles.
export function parseSigma(text, origin = 'importée') {
  const rules = [], errors = [];
  let docs;
  try { docs = yaml.loadAll(text); } catch (e) { return { rules, errors: [{ title: origin, reason: 'YAML invalide : ' + String(e.message).split('\n')[0] }] }; }
  for (const d of docs) {
    if (!d || typeof d !== 'object') continue;
    try {
      const r = compileSigma(d, origin);
      if (!r.techniques.length) errors.push({ title: r.title, reason: 'aucune technique ATT&CK dans les tags' });
      else rules.push(r);
    } catch (e) { errors.push({ title: d.title || origin, reason: e.message }); }
  }
  return { rules, errors };
}
