// Exports texte : rapport Markdown et couche ATT&CK Navigator.
import { D3, SEV, CONFL, TAC, overallLevel } from './engine.js';

const lineNos = f => f.ev.slice(0, 8).map(e => e.i + 1).join(', ');

export function reportMD({ res, prio, ioc }, date = new Date()) {
  const L = res.list;
  const top = overallLevel(L);
  let md = `# Triage ATT&CK — ${date.toLocaleString('fr-FR')}\n\n`;
  md += `**Niveau global :** ${top ? SEV[top] : 'Rien de notable'} · ${L.length} techniques · ${new Set(L.flatMap(f => f.tactics)).size}/14 tactiques\n\n`;
  md += '## Techniques ATT&CK\n';
  md += L.map(f => `- **[${SEV[f.severity]}] ${f.id} ${f.name}** (${f.tactics.map(k => TAC[k].name).join(', ')}) — confiance ${CONFL[f.conf]} — lignes ${lineNos(f)}${f.note ? `\n  - ${f.note}` : ''}${f.sigma ? `\n  - Sigma : ${f.sigma.join(' ; ')}` : ''}`).join('\n') || '_Aucune._';
  md += '\n\n## Contre-mesures D3FEND prioritaires\n';
  md += prio.slice(0, 8).map((p, i) => `${i + 1}. **${D3[p.k].id} ${D3[p.k].name}** (${D3[p.k].tactic}) — contre ${p.techs.join(', ')}`).join('\n') || '_Aucune._';
  md += `\n\n## Indicateurs\n- IP : ${ioc.ips.join(', ') || '—'}\n- Domaines : ${ioc.doms.join(', ') || '—'}\n- URL : ${ioc.urls.join(' ') || '—'}\n- Hash : ${ioc.hashes.join(', ') || '—'}\n- Comptes : ${ioc.users.join(', ') || '—'}\n`;
  return md;
}

const SEV_COLOR = { 4: '#e5484d', 3: '#f07f36', 2: '#e8b931', 1: '#4fb286' };

export function navigatorLayer({ res }, date = new Date()) {
  return JSON.stringify({
    name: 'Triage ' + date.toISOString().slice(0, 16),
    versions: { layer: '4.5', navigator: '5.1.0' },
    domain: 'enterprise-attack',
    description: 'Généré par Cartographe ATT&CK',
    techniques: res.list.map(f => ({
      techniqueID: f.id, score: f.severity, color: SEV_COLOR[f.severity], enabled: true,
      comment: `Confiance ${CONFL[f.conf]} · lignes ${lineNos(f)}`,
    })),
    gradient: { colors: ['#4fb286', '#e8b931', '#e5484d'], minValue: 1, maxValue: 4 },
    legendItems: [],
  }, null, 2);
}
