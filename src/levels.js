// Lecture par niveau SOC : N1 qualifie, N2 investigue, N3 reconstitue et chasse, le responsable décide.
// Aucune dépendance au DOM : chaque fonction prend l'état d'analyse ({ res, prio, ioc }) et renvoie des données ou du Markdown.
import { TACTICS, D3, SEV, CONFL, overallLevel, isPrivateIp } from './engine.js';

export const LEVELS = [
  { key: 'n1', label: 'N1 · Triage', role: 'Analyste N1', goal: 'Qualifier l’alerte, décider : clore ou escalader.' },
  { key: 'n2', label: 'N2 · Investigation', role: 'Analyste N2', goal: 'Établir le périmètre et la chronologie, contenir.' },
  { key: 'n3', label: 'N3 · Expertise', role: 'Analyste N3', goal: 'Reconstituer la chaîne d’attaque, chasser la suite, durcir la détection.' },
  { key: 'chef', label: 'Responsable SOC', role: 'Responsable SOC', goal: 'Décider, mobiliser les équipes, informer la direction.' },
];

const plural = (n, w) => `${n} ${w}${n > 1 ? 's' : ''}`;
const nonEmpty = res => res.lines.filter(l => l.trim()).length;

/* ---------- N1 : qualification ---------- */
// Délais indicatifs : à aligner sur les SLA du SOC.
const TRIAGE = {
  4: { prio: 'P1', decision: 'Escalader au N2 immédiatement', delay: '15 min', tone: 4 },
  3: { prio: 'P2', decision: 'Escalader au N2', delay: '1 h', tone: 3 },
  2: { prio: 'P3', decision: 'Qualifier, puis escalader si l’activité est confirmée', delay: '4 h', tone: 2 },
  1: { prio: 'P4', decision: 'Faux positif probable : documenter et clore', delay: '1 jour ouvré', tone: 1 },
};

export function triage({ res }) {
  const list = res.list;
  if (!nonEmpty(res)) return { prio: '—', decision: 'Aucun log à qualifier', delay: '—', tone: 0, reasons: [], checks: [] };
  const lvl = overallLevel(list);
  if (!lvl) return { prio: '—', decision: 'Clore : aucune technique reconnue', delay: '—', tone: 0, reasons: ['Aucune règle ne correspond à ces logs.'], checks: ['Vérifier que la source de logs est la bonne (journal d’activité, pas journal d’outil).'] };
  const t = TRIAGE[lvl];
  const reasons = list.filter(f => f.severity === lvl).slice(0, 3)
    .map(f => `${f.id} ${f.name} — sévérité ${SEV[f.severity].toLowerCase()}, confiance ${CONFL[f.conf]}`);
  if (list.length > 1) reasons.push(`${plural(list.length, 'technique')} sur ${plural(new Set(list.flatMap(f => f.tactics)).size, 'tactique')}.`);
  const checks = [
    'Identifier le propriétaire de la machine et du compte concernés.',
    'Vérifier la réputation des IP et domaines externes (threat intel).',
    ...list.slice(0, 4).map(f => `${f.id} : ${f.checks[0]}`),
  ];
  return { ...t, reasons, checks };
}

/* ---------- N2 : périmètre, chronologie, confinement ---------- */
const TS = [
  /\b\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d/,
  /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d/,
  /\[\d\d\/[A-Z][a-z]{2}\/\d{4}:\d\d:\d\d:\d\d/,
];
export const timeOf = l => { for (const re of TS) { const m = l.match(re); if (m) return m[0].replace(/^\[/, '').replace('T', ' '); } return ''; };

export function timeline({ res }) {
  const byLine = new Map();
  for (const f of res.list) for (const e of f.ev) {
    if (!byLine.has(e.i)) byLine.set(e.i, { i: e.i, time: timeOf(res.lines[e.i]), line: res.lines[e.i].trim(), techs: [], sev: 0 });
    const x = byLine.get(e.i);
    if (!x.techs.includes(f.id)) x.techs.push(f.id);
    x.sev = Math.max(x.sev, f.severity);
  }
  return [...byLine.values()].sort((a, b) => a.i - b.i);
}

export function scope({ ioc }) {
  return {
    hosts: ioc.hosts || [],
    users: ioc.users,
    extIps: ioc.ips.filter(ip => !isPrivateIp(ip)),
    intIps: ioc.ips.filter(isPrivateIp),
    doms: ioc.doms,
    files: ioc.files,
  };
}

// Confinement : contre-mesures qui agissent tout de suite (Evict, Isolate), dans l'ordre de priorité.
export const containment = ({ prio }) => prio.filter(p => ['Evict', 'Isolate'].includes(D3[p.k].tactic)).slice(0, 5);

/* ---------- N3 : chaîne d'attaque, chasse, qualité de détection ---------- */
export function chain({ res }) {
  const hit = new Set(res.list.flatMap(f => f.tactics));
  const idx = TACTICS.map((t, i) => (hit.has(t.key) ? i : -1)).filter(i => i >= 0);
  if (!idx.length) return { reached: [], furthest: null, hunts: [] };
  const first = idx[0], last = idx[idx.length - 1];
  // Pistes de chasse : tactiques non vues entre la première observée et la fin de la chaîne, les plus proches d'abord.
  const hunts = TACTICS.slice(first).filter(t => !hit.has(t.key)).slice(0, 5)
    .map(t => ({ key: t.key, name: t.name, id: t.id, text: t.hunt, gap: TACTICS.indexOf(t) < last }));
  return { reached: TACTICS.filter(t => hit.has(t.key)), furthest: TACTICS[last], hunts };
}

export function detectionQuality({ res }) {
  return {
    weak: res.list.filter(f => f.conf === 1),
    single: res.list.filter(f => f.conf > 1 && f.ev.length === 1),
    sigmaOnly: res.list.filter(f => f.sigma && !f.native),
    confirmed: res.list.filter(f => f.sigma && f.native),
  };
}

/* ---------- Responsable SOC : synthèse de décision ---------- */
const IMPACTS = [
  ['cred', 'Des identifiants sont compromis : réinitialisation des mots de passe à prévoir.'],
  ['lm', 'Plusieurs machines sont potentiellement touchées : le périmètre peut s’étendre.'],
  ['persist', 'L’attaquant peut revenir : un simple redémarrage ne suffit pas, nettoyage complet nécessaire.'],
  ['exfil', 'Risque de fuite de données : vérifier si des données personnelles sont concernées (notification CNIL sous 72 h le cas échéant).'],
  ['coll', 'Des données ont été rassemblées : identifier lesquelles et leur sensibilité.'],
  ['impact', 'Risque d’interruption d’activité (chiffrement, destruction, sauvegardes supprimées).'],
];

export function executive(state) {
  const { res } = state;
  const t = triage(state);
  const lvl = overallLevel(res.list);
  const hit = new Set(res.list.flatMap(f => f.tactics));
  const sc = scope(state);
  const headline = !nonEmpty(res) ? 'Aucune donnée analysée'
    : lvl >= 4 ? 'Incident de sécurité probable, critique'
    : lvl === 3 ? 'Incident de sécurité probable'
    : lvl === 2 ? 'Activité suspecte à qualifier'
    : lvl === 1 ? 'Signaux faibles, pas d’incident avéré'
    : 'Rien à signaler';
  const story = TACTICS.filter(x => hit.has(x.key)).map(x => x.plain);
  const impacts = IMPACTS.filter(([k]) => hit.has(k)).map(([, s]) => s);
  const decisions = lvl >= 4 ? [
    'Déclencher le plan de réponse à incident et désigner un responsable de l’incident.',
    'Autoriser l’isolement réseau des machines touchées, même en production.',
    'Informer le RSSI et la direction ; préparer la communication de crise.',
    ...(hit.has('cred') ? ['Valider la réinitialisation des comptes exposés, y compris à privilèges.'] : []),
    ...(hit.has('exfil') || hit.has('coll') ? ['Associer le DPO et le juridique pour l’évaluation des obligations de notification.'] : []),
  ] : lvl === 3 ? [
    'Mobiliser un analyste N2/N3 sur l’investigation dès maintenant.',
    'Préparer l’isolement des machines touchées si l’activité est confirmée.',
    'Informer le RSSI.',
  ] : lvl ? ['Aucune décision de direction : suivi par l’équipe SOC dans les délais normaux.'] : [];
  return {
    headline, tone: lvl, prio: t.prio, story, impacts, decisions,
    figures: [
      [sc.hosts.length, 'machines'], [sc.users.length, 'comptes'], [sc.extIps.length, 'IP externes'],
      [res.list.length, 'techniques'], [hit.size, 'phases d’attaque sur 14'],
    ],
  };
}

/* ---------- Rapports Markdown par niveau ---------- */
const bullet = a => a.map(x => `- ${x}`).join('\n') || '_Aucun._';

export function levelReport(level, state, date = new Date()) {
  const { res, prio } = state;
  const when = date.toLocaleString('fr-FR');
  const t = triage(state);
  if (level === 'n1') {
    return `# Ticket N1 — ${when}\n\n**Priorité :** ${t.prio} · **Décision :** ${t.decision} · **Délai :** ${t.delay}\n\n## Motifs\n${bullet(t.reasons)}\n\n## Vérifications faites / à faire\n${t.checks.map(c => `- [ ] ${c}`).join('\n')}\n\n## Indicateurs\n${bullet(iocLines(state))}\n`;
  }
  if (level === 'n2') {
    const sc = scope(state), tl = timeline(state), ct = containment(state);
    return `# Investigation N2 — ${when}\n\n**Priorité :** ${t.prio} · ${plural(res.list.length, 'technique')}\n\n## Périmètre\n- Machines : ${sc.hosts.join(', ') || '—'}\n- Comptes : ${sc.users.join(', ') || '—'}\n- IP externes : ${sc.extIps.join(', ') || '—'}\n- IP internes : ${sc.intIps.join(', ') || '—'}\n- Domaines : ${sc.doms.join(', ') || '—'}\n- Fichiers : ${sc.files.join(', ') || '—'}\n\n## Chronologie\n${tl.map(x => `- ${x.time || 'L' + (x.i + 1)} — ${x.techs.join(', ')} — \`${x.line.slice(0, 160)}\``).join('\n') || '_Aucune._'}\n\n## Confinement\n${ct.map((p, i) => `${i + 1}. **${D3[p.k].name}** (${D3[p.k].id}) — ${D3[p.k].benefit}`).join('\n') || '_Aucun._'}\n\n## Vérifications par technique\n${res.list.map(f => `- **${f.id} ${f.name}** : ${f.checks.join(' ')}`).join('\n') || '_Aucune._'}\n`;
  }
  if (level === 'n3') {
    const c = chain(state), q = detectionQuality(state);
    return `# Analyse N3 — ${when}\n\n## Chaîne d'attaque\n${c.reached.map(x => `- ${x.id} ${x.name} : ${res.list.filter(f => f.tactics.includes(x.key)).map(f => f.id).join(', ')}`).join('\n') || '_Aucune tactique observée._'}\n${c.furthest ? `\nPhase la plus avancée observée : **${c.furthest.name}**.\n` : ''}\n## Hypothèses de chasse\n${c.hunts.map(h => `- **${h.name}** (${h.id})${h.gap ? ' — trou dans la chaîne observée' : ''} : ${h.text}`).join('\n') || '_Aucune._'}\n\n## Qualité de détection\n- À confirmer (confiance faible) : ${q.weak.map(f => f.id).join(', ') || '—'}\n- Une seule ligne de preuve : ${q.single.map(f => f.id).join(', ') || '—'}\n- Confirmées par Sigma : ${q.confirmed.map(f => f.id).join(', ') || '—'}\n- Vues uniquement par Sigma : ${q.sigmaOnly.map(f => f.id).join(', ') || '—'}\n\n## Contre-mesures D3FEND (durcissement)\n${prio.slice(0, 8).map((p, i) => `${i + 1}. ${D3[p.k].id} ${D3[p.k].name} (${D3[p.k].tactic}) — contre ${p.techs.join(', ')}`).join('\n') || '_Aucune._'}\n`;
  }
  const x = executive(state);
  return `# Note au responsable SOC — ${when}\n\n**${x.headline}** · priorité ${x.prio}\n\n${x.figures.map(([n, l]) => `${n} ${l}`).join(' · ')}\n\n## Ce qui s'est passé\n${bullet(x.story)}\n\n## Risques pour l'entreprise\n${bullet(x.impacts)}\n\n## Décisions attendues\n${bullet(x.decisions)}\n`;
}

function iocLines({ ioc }) {
  return [
    ioc.hosts?.length && `Machines : ${ioc.hosts.join(', ')}`,
    ioc.users.length && `Comptes : ${ioc.users.join(', ')}`,
    ioc.ips.length && `IP : ${ioc.ips.join(', ')}`,
    ioc.doms.length && `Domaines : ${ioc.doms.join(', ')}`,
    ioc.urls.length && `URL : ${ioc.urls.join(' ')}`,
    ioc.hashes.length && `Hash : ${ioc.hashes.join(', ')}`,
  ].filter(Boolean);
}
