// Prompt de l'analyse approfondie avec Claude (capacité `sample`).
import { SEV, CONFL } from './engine.js';

export const MAX_CHARS = 60000;

export function buildPrompt(logs, list) {
  const cut = logs.length > MAX_CHARS ? logs.slice(0, MAX_CHARS) : logs;
  const local = list.map(f => `${f.id} ${f.name} (${SEV[f.severity]}, confiance ${CONFL[f.conf]})`).join('; ') || 'aucune';
  return `Tu es analyste SOC niveau 3. Analyse les logs ci-dessous et mappe l'activité sur MITRE ATT&CK Enterprise, puis recommande les contre-mesures MITRE D3FEND les plus utiles.
Un moteur de règles local a déjà détecté : ${local}. Confirme, corrige ou complète (techniques manquées, faux positifs probables). N'invente rien : chaque technique doit citer une preuve tirée des logs.
Réponds en français, uniquement avec un objet JSON de cette forme :
{"verdict":"malveillant|suspect|bénin","confiance":0-100,"resume":"3 phrases maximum","chronologie":[{"moment":"horodatage","evenement":"..."}],"techniques":[{"id":"T1059.001","nom":"PowerShell","tactique":"Execution","confiance":0-100,"preuve":"extrait court du log","explication":"une phrase"}],"d3fend":[{"id":"D3-PSA","nom":"Process Spawn Analysis","tactique":"Detect","pourquoi":"une phrase"}],"actions_immediates":["..."],"faux_positifs":["..."]}
Classe d3fend du plus utile au moins utile (5 maximum). chronologie : 8 étapes maximum.
${cut.length < logs.length ? `(Logs tronqués aux ${MAX_CHARS} premiers caractères.)\n` : ''}
LOGS :
<<<
${cut}
>>>`;
}
