// Interface : lecture des logs, rendu, exports, analyse approfondie avec Claude.
import { RULES, TACTICS, TAC, D3, SEV, CONFL, d3Url, attackUrl, analyze, prioritize, extractIOC, overallLevel, isPrivateIp } from './engine.js';
import { reportMD, navigatorLayer } from './exports.js';
import { buildPrompt } from './prompt.js';
import demoLog from '../samples/demo.log';
import sigmaBuiltin from '../rules/sigma.yml';
import { parseSigma } from './sigma.js';
import { LEVELS, triage, timeline, scope, containment, chain, detectionQuality, executive, levelReport } from './levels.js';

const RULE_COUNT = RULES.length;
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = { get: k => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* stockage indisponible */ } } };
const savedLevel = store.get('cartographe.level');
const state = { res: null, prio: [], filter: null, ioc: null, level: LEVELS.some(l => l.key === savedLevel) ? savedLevel : 'n1' };

/* ---------- Rendu ---------- */
function hl(line, re) {
  const m = line.match(re);
  if (!m) return esc(line.length > 220 ? line.slice(0, 220) + '…' : line);
  const a = m.index, b = a + m[0].length, s = Math.max(0, a - 90), e = Math.min(line.length, b + 110);
  return (s > 0 ? '…' : '') + esc(line.slice(s, a)) + '<mark>' + esc(line.slice(a, b)) + '</mark>' + esc(line.slice(b, e)) + (e < line.length ? '…' : '');
}
const d3chip = k => {
  const d = D3[k];
  if (!d) return '';
  return `<a class="d3chip t-${d.tactic.toLowerCase()}" href="${d3Url(d.name)}" target="_blank" rel="noopener" title="${esc(d.benefit)}"><b>${d.id}</b>${esc(d.name)}</a>`;
};
const confHTML = c => `<span class="conf" title="Confiance ${CONFL[c]}">${[1, 2, 3].map(n => `<i class="${n <= c ? 'on' : ''}"></i>`).join('')}<em>${CONFL[c]}</em></span>`;

function render() {
  const { res, prio, filter } = state;
  const list = res.list;
  const shown = filter ? list.filter(f => f.tactics.includes(filter)) : list;
  const top = overallLevel(list);
  const tacHit = new Set(list.flatMap(f => f.tactics));
  const flagged = new Set(list.flatMap(f => f.ev.map(e => e.i)));
  const counts = [4, 3, 2, 1].map(s => [s, list.filter(f => f.severity === s).length]).filter(([, n]) => n);
  const nLines = res.lines.filter(l => l.trim()).length;

  // Synthèse
  const p1 = prio[0], d1 = p1 && D3[p1.k];
  $('#summary').innerHTML = `
    <div class="verdict">
      <span class="eyebrow">Niveau global</span>
      <span class="lvl c-s${top}"><i></i>${top ? SEV[top] : nLines ? 'Aucune détection' : 'En attente'}</span>
      <div class="sevcount">${counts.map(([s, n]) => `<span class="sev s${s}">${n} ${SEV[s].toLowerCase()}</span>`).join('')}</div>
    </div>
    <div class="stats">
      <div class="stat"><b>${list.length}</b><span>techniques</span></div>
      <div class="stat"><b>${tacHit.size}<small style="font-size:13px;color:var(--muted)">/14</small></b><span>tactiques</span></div>
      <div class="stat"><b>${nLines}</b><span>${res.format === 'texte' ? 'lignes analysées' : 'événements ' + res.format}</span></div>
      <div class="stat"><b>${flagged.size}</b><span>lignes signalées</span></div>
    </div>
    <div class="top1">
      <span class="eyebrow">Contre-mesure n°1</span>
      ${d1 ? `<a href="${d3Url(d1.name)}" target="_blank" rel="noopener">${esc(d1.name)}</a>
      <span class="did">${d1.id} · ${d1.tactic}</span>
      <span class="why">Couvre ${p1.techs.length} technique${p1.techs.length > 1 ? 's' : ''} détectée${p1.techs.length > 1 ? 's' : ''}.</span>` : '<span class="why">Aucune détection à contrer.</span>'}
    </div>`;

  // Chaîne des tactiques
  $('#chain').innerHTML = TACTICS.map(t => {
    const fs = list.filter(f => f.tactics.includes(t.key));
    const mx = fs.reduce((m, f) => Math.max(m, f.severity), 0);
    return `<button type="button" class="tc ${fs.length ? 'hit s' + mx : ''} ${filter === t.key ? 'sel' : ''}" data-tac="${t.key}" ${fs.length ? '' : 'tabindex="-1" aria-disabled="true"'} title="${t.name} (${t.id})">
      <span class="tn">${t.name}</span><span class="cnt">${fs.length}</span><span class="ti">${t.id}</span></button>`;
  }).join('');
  $('#filterNote').innerHTML = filter
    ? `Filtre : ${TAC[filter].name} · <button class="linkbtn" id="unfilter" type="button">tout afficher</button>`
    : (list.length ? 'Cliquez une tactique pour filtrer' : '');
  $('#techCount').textContent = list.length ? `${shown.length} affichée${shown.length > 1 ? 's' : ''}` : '';

  // Fiches techniques
  $('#techs').innerHTML = shown.length ? shown.map((f, idx) => {
    const ev = f.ev.slice(0, 4), more = f.ev.length - ev.length;
    return `<article class="panel tech">
      <div class="tech-h">
        <span class="sev s${f.severity}">${SEV[f.severity]}</span>
        <a class="tid" href="${attackUrl(f.id)}" target="_blank" rel="noopener">${f.id}</a>
        <h3>${esc(f.name)}</h3>
        ${confHTML(f.conf)}
      </div>
      <div class="tacs">${f.tactics.map(k => `<span class="tac">${TAC[k].name}</span>`).join('')}</div>
      ${f.note ? `<p class="note">${esc(f.note)}</p>` : ''}
      ${f.sigma ? `<p class="note"><span class="src">Sigma</span>${f.sigma.slice(0, 4).map(esc).join(' · ')}${f.sigma.length > 4 ? ` · +${f.sigma.length - 4}` : ''}</p>` : ''}
      <ol class="ev">${ev.map(e => `<li><span class="ln">L${e.i + 1}</span><code>${hl(res.lines[e.i], e.re)}</code></li>`).join('')}</ol>
      ${more > 0 ? `<span class="more">+ ${more} autre${more > 1 ? 's' : ''} ligne${more > 1 ? 's' : ''} : ${f.ev.slice(4, 14).map(e => 'L' + (e.i + 1)).join(', ')}${more > 10 ? '…' : ''}</span>` : ''}
      <div class="row"><span class="lbl">D3FEND</span>${f.d3fend.map(d3chip).join('')}</div>
      <details class="tech-more" ${idx < 3 ? 'open' : ''}><summary>À vérifier</summary><ul class="chk">${f.checks.map(c => `<li>${esc(c)}</li>`).join('')}</ul></details>
    </article>`;
  }).join('') : `<div class="panel none">${list.length ? '<b>Aucune technique pour ce filtre</b>'
    : nLines ? `<b>Analyse terminée : aucune technique ATT&amp;CK reconnue</b>${nLines} ligne${nLines > 1 ? 's' : ''} lue${nLines > 1 ? 's' : ''}, aucune ne correspond aux ${RULE_COUNT} règles locales. Les règles cherchent des traces d’attaque (commandes, processus, authentifications, requêtes web) : un journal d’outil ou d’application sans ces traces ne donne rien.`
    : '<b>Aucun log à analyser</b>Collez des logs à gauche, déposez un fichier ou utilisez « Fichier… ».'}</div>`;

  // Priorités D3FEND
  const mx = prio[0]?.score || 1;
  $('#prio').innerHTML = prio.length ? prio.slice(0, 8).map((p, i) => {
    const d = D3[p.k];
    return `<li class="pi ${i === 0 ? 'first' : ''} t-${d.tactic.toLowerCase()}">
      <span class="rk">${i + 1}</span>
      <div>
        <div class="pi-h"><a href="${d3Url(d.name)}" target="_blank" rel="noopener">${esc(d.name)}</a><span class="did">${d.id}</span><span class="dtac">${d.tactic}</span></div>
        <p>${esc(d.benefit)}</p>
        <div class="bar"><i style="width:${Math.max(6, Math.round(p.score / mx * 100))}%"></i></div>
        <div class="covers">contre ${p.techs.join(' · ')}</div>
      </div></li>`;
  }).join('') : '<li class="empty">Aucune contre-mesure à proposer sans détection.</li>';

  renderLevel();
}

/* ---------- Niveaux SOC ---------- */
const listHTML = (a, cls = 'olist', empty = 'Rien à signaler.') => a.length ? `<ul class="${cls}">${a.map(x => `<li>${x}</li>`).join('')}</ul>` : `<span class="empty">${empty}</span>`;
const tidLink = id => `<a class="tid" href="${attackUrl(id)}" target="_blank" rel="noopener">${esc(id)}</a>`;

function renderLevels() {
  $('#levels').innerHTML = LEVELS.map(l => `<button type="button" class="lv" role="tab" id="tab-${l.key}" aria-controls="levelPanel" data-lv="${l.key}" aria-selected="${state.level === l.key}"><b>${esc(l.label)}</b><span>${esc(l.goal)}</span></button>`).join('');
  $('.wrap').dataset.level = state.level;
  $('#levelPanel').setAttribute('aria-labelledby', 'tab-' + state.level);
}

function renderLevel() {
  const L = LEVELS.find(l => l.key === state.level);
  const head = `<div class="level-h"><div><h2 id="lv-h">Fiche ${esc(L.role)}</h2><p class="sub">${esc(L.goal)}</p></div>
    <button class="btn" id="copyLevel" type="button">Copier la fiche (Markdown)</button></div>`;
  $('#levelPanel').innerHTML = head + ({ n1: levelN1, n2: levelN2, n3: levelN3, chef: levelChef }[state.level])();
}

function levelN1() {
  const t = triage(state);
  return `<div class="decision s${t.tone}"><span class="p">${esc(t.prio)}</span><strong>${esc(t.decision)}</strong><span class="delay">Délai indicatif : ${esc(t.delay)}</span></div>
  <div class="lgrid">
    <div><h4>Pourquoi</h4>${listHTML(t.reasons.map(esc))}</div>
    <div><h4>À vérifier avant de décider</h4>${t.checks.length ? `<ul class="checklist">${t.checks.map(c => `<li><label><input type="checkbox"><span>${esc(c)}</span></label></li>`).join('')}</ul>` : '<span class="empty">—</span>'}</div>
  </div>`;
}

function levelN2() {
  const sc = scope(state), tl = timeline(state), ct = containment(state);
  const kv = (k, a) => `<dt>${k}</dt><dd>${a.length ? a.map(esc).join(', ') : '—'}</dd>`;
  return `<div class="lgrid">
    <div><h4>Périmètre</h4><dl class="kv">${kv('Machines', sc.hosts)}${kv('Comptes', sc.users)}${kv('IP externes', sc.extIps)}${kv('IP internes', sc.intIps)}${kv('Domaines', sc.doms)}${kv('Fichiers', sc.files)}</dl></div>
    <div><h4>Confinement prioritaire</h4>${ct.length ? `<ol class="olist">${ct.map(p => `<li>${d3chip(p.k)} <span class="did">contre ${p.techs.map(esc).join(', ')}</span></li>`).join('')}</ol>` : '<span class="empty">Aucune action de confinement proposée.</span>'}</div>
  </div>
  <div><h4>Chronologie des lignes signalées · ${tl.length}</h4>${tl.length ? `<ol class="tl">${tl.map(x => `<li><span class="t">${esc(x.time || 'L' + (x.i + 1))}</span><span class="ids">${x.techs.map(id => `<span class="pill c-s${x.sev}">${esc(id)}</span>`).join('')}</span><code title="${esc(x.line)}">${esc(x.time ? x.line.replace(/^\[?\S+(\s+\d{1,2})?\s+[\d:.,]+\S*\]?\s*/, '') : x.line)}</code></li>`).join('')}</ol>` : '<span class="empty">Aucune ligne signalée.</span>'}</div>`;
}

function levelN3() {
  const c = chain(state), q = detectionQuality(state);
  const techsOf = k => state.res.list.filter(f => f.tactics.includes(k));
  return `<div class="lgrid">
    <div><h4>Chaîne d'attaque observée${c.furthest ? ` · jusqu'à ${esc(c.furthest.name)}` : ''}</h4>${c.reached.length ? `<ol class="steps">${c.reached.map(x => `<li><strong>${esc(x.name)}</strong> <span class="did">${x.id}</span><span class="tn">${techsOf(x.key).map(f => tidLink(f.id) + ' ' + esc(f.name)).join(' · ')}</span></li>`).join('')}</ol>` : '<span class="empty">Aucune tactique observée.</span>'}</div>
    <div><h4>Hypothèses de chasse</h4>${c.hunts.length ? `<ul class="hunts">${c.hunts.map(h => `<li><strong>${esc(h.name)}</strong>${h.gap ? '<span class="gap">trou dans la chaîne</span>' : ''}<br>${esc(h.text)}</li>`).join('')}</ul>` : '<span class="empty">Aucune piste : pas de tactique observée.</span>'}</div>
  </div>
  <div><h4>Qualité de détection</h4>
    <dl class="kv"><dt>À confirmer (confiance faible)</dt><dd>${q.weak.map(f => tidLink(f.id)).join(', ') || '—'}</dd><dt>Une seule ligne de preuve</dt><dd>${q.single.map(f => tidLink(f.id)).join(', ') || '—'}</dd><dt>Confirmées par Sigma</dt><dd>${q.confirmed.map(f => tidLink(f.id)).join(', ') || '—'}</dd><dt>Vues uniquement par Sigma</dt><dd>${q.sigmaOnly.map(f => tidLink(f.id)).join(', ') || '—'}</dd></dl>
    <p class="sub" style="margin:8px 0 0;font-size:12px;color:var(--muted)">La couche ATT&amp;CK Navigator (en haut à droite) et l'analyse approfondie avec Claude complètent cette vue.</p>
  </div>`;
}

function levelChef() {
  const x = executive(state);
  return `<div class="exec-head"><span class="lvl c-s${x.tone}"><i></i>${esc(x.headline)}</span>${x.prio !== '—' ? `<span class="sev s${x.tone}">Priorité ${esc(x.prio)}</span>` : ''}</div>
  <div class="figs">${x.figures.map(([n, l]) => `<div><b>${n}</b><span>${esc(l)}</span></div>`).join('')}</div>
  <div class="lgrid">
    <div><h4>Ce qui s'est passé</h4>${listHTML(x.story.map(esc), 'plainlist', 'Aucune activité malveillante reconnue.')}</div>
    <div><h4>Risques pour l'entreprise</h4>${listHTML(x.impacts.map(esc), 'plainlist', 'Aucun risque majeur identifié à ce stade.')}</div>
  </div>
  <div><h4>Décisions attendues</h4>${listHTML(x.decisions.map(esc), 'plainlist', 'Aucune décision requise.')}</div>`;
}

$('#levels').addEventListener('click', e => {
  const b = e.target.closest('.lv');
  if (!b || b.dataset.lv === state.level) return;
  state.level = b.dataset.lv;
  store.set('cartographe.level', state.level);
  renderLevels();
  renderLevel();
});
$('#levels').addEventListener('keydown', e => {
  if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
  const i = LEVELS.findIndex(l => l.key === state.level), n = LEVELS.length;
  const next = LEVELS[(i + (e.key === 'ArrowRight' ? 1 : n - 1)) % n].key;
  $(`#tab-${next}`).click();
  $(`#tab-${next}`).focus();
});
$('#levelPanel').addEventListener('click', e => { if (e.target.closest('#copyLevel')) copy(levelReport(state.level, state), 'Fiche'); });

function renderIOC(ioc) {
  const g = (title, items, fmt = x => esc(x), tag) => `<div class="ioc-g"><h4>${title} <span class="n">${items.length}</span></h4>${items.length
    ? `<div class="ioc-list">${items.slice(0, 30).map(x => `<button type="button" class="ioc-item" data-copy="${esc(x)}" title="${esc(x)}">${fmt(x)}${tag ? tag(x) : ''}</button>`).join('')}</div>`
    : '<span class="empty">—</span>'}</div>`;
  $('#iocs').innerHTML =
    g('Adresses IP', ioc.ips, undefined, x => `<span class="tag">${isPrivateIp(x) ? 'interne' : 'externe'}</span>`) +
    g('Domaines', ioc.doms) + g('URL', ioc.urls) +
    g('Hash', ioc.hashes, x => esc(x.slice(0, 12) + '…' + x.slice(-6)), x => `<span class="tag">${x.length === 64 ? 'SHA256' : x.length === 40 ? 'SHA1' : 'MD5'}</span>`) +
    g('Comptes', ioc.users) + g('Fichiers', ioc.files);
}

function run() {
  const text = $('#logs').value;
  const res = analyze(text, undefined, sigma.rules);
  state.res = res;
  state.prio = prioritize(res.list);
  state.filter = null;
  state.ioc = extractIOC(text);
  render();
  renderIOC(state.ioc);
  updateCount();
  resetClaude();
}

/* ---------- Règles Sigma ---------- */
// Règles intégrées (rules/sigma.yml) + règles importées, mémorisées dans ce navigateur quand la place le permet.
const SIGMA_KEY = 'cartographe.sigma';
const builtin = parseSigma(sigmaBuiltin, 'intégrée');
const sigma = { imported: [], rules: builtin.rules, errors: [] };
function loadImported() {
  try { const v = JSON.parse(store.get(SIGMA_KEY) || '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}
function applySigma(files) {
  sigma.imported = files;
  const parsed = files.map(f => parseSigma(f.text, f.name));
  sigma.rules = [...builtin.rules, ...parsed.flatMap(p => p.rules)];
  sigma.errors = parsed.flatMap(p => p.errors);
  renderSigma();
}
function renderSigma() {
  const nImp = sigma.rules.length - builtin.rules.length;
  $('#sigmaCount').textContent = `${sigma.rules.length} active${sigma.rules.length > 1 ? 's' : ''}`;
  $('#sigmaInfo').innerHTML = nImp
    ? `${builtin.rules.length} intégrées + <strong>${nImp}</strong> importée${nImp > 1 ? 's' : ''} (${sigma.imported.length} fichier${sigma.imported.length > 1 ? 's' : ''}).`
    : `${builtin.rules.length} règles intégrées. Importez les vôtres ou celles de <a href="https://github.com/SigmaHQ/sigma/tree/master/rules" target="_blank" rel="noopener">SigmaHQ</a> : elles s'ajoutent aux règles de l'outil.`;
  $('#sigmaClear').hidden = !nImp && !sigma.errors.length;
  const d = $('#sigmaErr');
  d.hidden = !sigma.errors.length;
  d.querySelector('summary').textContent = `${sigma.errors.length} règle${sigma.errors.length > 1 ? 's' : ''} ignorée${sigma.errors.length > 1 ? 's' : ''}`;
  d.querySelector('ul').innerHTML = sigma.errors.slice(0, 200).map(e => `<li>${esc(e.title)} <em>— ${esc(e.reason)}</em></li>`).join('')
    + (sigma.errors.length > 200 ? `<li><em>… et ${sigma.errors.length - 200} autres</em></li>` : '');
}
async function importSigma(fileList) {
  const picked = [...fileList].filter(f => /\.ya?ml$/i.test(f.name));
  if (!picked.length) { toast('Aucun fichier .yml dans la sélection'); return; }
  const added = await Promise.all(picked.map(async f => ({ name: f.webkitRelativePath || f.name, text: await f.text() })));
  const byName = new Map([...sigma.imported, ...added].map(f => [f.name, f]));
  const before = sigma.rules.length;
  applySigma([...byName.values()]);
  let kept = true;
  try { localStorage.setItem(SIGMA_KEY, JSON.stringify(sigma.imported)); } catch { kept = false; }
  run();
  const n = Math.max(0, sigma.rules.length - before), t = state.res.list.length;
  toast(`${n} règle${n > 1 ? 's' : ''} Sigma ajoutée${n > 1 ? 's' : ''} · ${t} technique${t > 1 ? 's' : ''}${kept ? '' : ' · active pour cette session seulement (trop volumineux pour être mémorisé)'}`);
}
$('#sigmaFiles').onchange = e => { importSigma(e.target.files); e.target.value = ''; };
$('#sigmaDir').onchange = e => { importSigma(e.target.files); e.target.value = ''; };
$('#sigmaClear').onclick = () => {
  try { localStorage.removeItem(SIGMA_KEY); } catch { /* stockage indisponible */ }
  applySigma([]);
  run();
  toast('Règles importées retirées');
};

/* ---------- Interactions ---------- */
function updateCount() {
  const n = $('#logs').value.split(/\r?\n/).filter(l => l.trim()).length;
  $('#lineCount').textContent = n + ' ligne' + (n > 1 ? 's' : '');
}
function summaryText(prefix) {
  const { lines, list, format } = state.res;
  const n = lines.filter(l => l.trim()).length, t = list.length;
  const unit = format === 'texte' ? 'ligne' : 'événement';
  return `${prefix} · ${n} ${unit}${n > 1 ? 's' : ''}${format === 'texte' ? '' : ` ${format}`} · ${t} technique${t > 1 ? 's' : ''}`;
}
function runAndReport() {
  run();
  toast(state.res.lines.some(l => l.trim()) ? summaryText('Analyse terminée') : 'Aucun log à analyser');
}
$('#demo').onclick = () => {
  $('#logs').value = demoLog.trimEnd();
  run();
  toast(summaryText('Scénario fictif chargé'));
};
$('#run').onclick = runAndReport;
$('#clear').onclick = () => { $('#logs').value = ''; run(); $('#logs').focus(); };
$('#logs').addEventListener('input', updateCount);
$('#logs').addEventListener('paste', () => setTimeout(runAndReport, 0));
$('#logs').addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runAndReport(); } });

function readFile(f) {
  if (!f) return;
  const r = new FileReader();
  r.onload = () => { $('#logs').value = String(r.result); run(); toast(summaryText(`${f.name} analysé`)); };
  r.readAsText(f);
}
$('#file').onchange = e => readFile(e.target.files[0]);
const drop = $('#drop');
['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, () => drop.classList.remove('over')));
drop.addEventListener('drop', e => { e.preventDefault(); readFile(e.dataTransfer.files[0]); });

$('#chain').addEventListener('click', e => {
  const b = e.target.closest('.tc.hit');
  if (!b) return;
  state.filter = state.filter === b.dataset.tac ? null : b.dataset.tac;
  render();
});
$('#filterNote').addEventListener('click', e => { if (e.target.id === 'unfilter') { state.filter = null; render(); } });
$('#iocs').addEventListener('click', e => { const b = e.target.closest('.ioc-item'); if (b) copy(b.dataset.copy, 'Indicateur'); });

let tt;
function toast(m) {
  const t = $('#toast');
  t.textContent = m;
  t.hidden = false;
  clearTimeout(tt);
  tt = setTimeout(() => (t.hidden = true), 2600);
}
async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(label + ' copié');
  } catch {
    $('#modalTitle').textContent = label;
    $('#modalText').value = text;
    $('#modal').hidden = false;
    $('#modalText').focus();
    $('#modalText').select();
  }
}
$('#modalClose').onclick = () => ($('#modal').hidden = true);
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') $('#modal').hidden = true; });
$('#copyReport').onclick = () => copy(reportMD(state), 'Rapport');
$('#copyLayer').onclick = () => copy(navigatorLayer(state), 'Couche Navigator');

/* ---------- Analyse approfondie avec Claude ---------- */
let sampleFn = null, ctl = null;
(async () => {
  try { sampleFn = window.claude ? await window.claude.use('sample') : null; } catch { sampleFn = null; }
  if (sampleFn) $('#claudePanel').hidden = false;
})();

function resetClaude() {
  if (ctl) ctl.abort();
  $('#claudeOut').hidden = true;
  $('#claudeOut').innerHTML = '';
  $('#claudeStatus').hidden = true;
}
const ERR = {
  not_granted: 'Accès à Claude refusé pour cette page.',
  sampling_disabled: 'Claude n’est pas disponible pour ce compte.',
  rate_limited: 'Trop de demandes pour le moment. Réessayez dans quelques minutes.',
  session_expired: 'Session expirée : reconnectez-vous à claude.ai.',
  prompt_too_large: 'Logs trop volumineux : gardez la fenêtre de temps pertinente.',
  invalid_json: 'Réponse illisible. Relancez l’analyse.',
  refused: 'Claude a refusé cette demande.',
  empty_completion: 'Réponse vide. Relancez l’analyse.',
};
const FATAL = ['not_granted', 'sampling_disabled', 'not_declared', 'capability_disabled', 'capability_removed'];
$('#stopClaude').onclick = () => ctl?.abort();
$('#askClaude').onclick = async () => {
  const logs = $('#logs').value.trim();
  if (!logs) { toast('Collez des logs d’abord'); return; }
  ctl = new AbortController();
  const st = $('#claudeStatus');
  st.hidden = false;
  st.innerHTML = '<span class="spin"></span> Claude analyse les logs… (souvent 20 à 60 s)';
  $('#askClaude').disabled = true;
  $('#stopClaude').hidden = false;
  $('#claudeOut').hidden = true;
  try {
    const r = await sampleFn.json(buildPrompt(logs, state.res.list), {
      signal: ctl.signal,
      onText: ({ text }) => { st.innerHTML = `<span class="spin"></span> Rédaction en cours… ${text.length} caractères`; },
    });
    st.hidden = true;
    renderClaude(r || {});
  } catch (e) {
    if (e?.code === 'cancelled') st.textContent = 'Analyse arrêtée.';
    else if (FATAL.includes(e?.code)) { $('#claudePanel').hidden = true; toast(ERR[e.code] || 'Claude indisponible'); }
    else st.textContent = ERR[e?.code] || 'La connexion à Claude a échoué. Relancez l’analyse.';
  } finally {
    $('#askClaude').disabled = false;
    $('#stopClaude').hidden = true;
  }
};

function renderClaude(r) {
  const known = new Set(state.res.list.map(f => f.id));
  const vmap = { malveillant: 4, suspect: 2, 'bénin': 1, benin: 1 };
  const arr = x => (Array.isArray(x) ? x : []);
  const out = $('#claudeOut');
  out.hidden = false;
  out.innerHTML = `
    <div class="row"><span class="sev s${vmap[String(r.verdict).toLowerCase()] || 2}">${esc(r.verdict || 'indéterminé')}</span><span class="did">confiance ${esc(r.confiance ?? '?')} %</span></div>
    ${r.resume ? `<p>${esc(r.resume)}</p>` : ''}
    ${arr(r.techniques).length ? `<div><h4>Techniques</h4><div class="tbl-scroll"><table class="ctable"><thead><tr><th>ID</th><th>Technique</th><th>Preuve</th><th>Conf.</th></tr></thead><tbody>
      ${arr(r.techniques).map(t => `<tr><td><a class="tid" href="${attackUrl(String(t.id || ''))}" target="_blank" rel="noopener">${esc(t.id || '')}</a>${known.has(t.id) ? '' : '<span class="new">nouveau</span>'}</td>
      <td><strong>${esc(t.nom || '')}</strong><br><span class="did">${esc(t.tactique || '')}</span><br>${esc(t.explication || '')}</td><td><code>${esc(t.preuve || '')}</code></td><td>${esc(t.confiance ?? '')}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}
    ${arr(r.d3fend).length ? `<div><h4>D3FEND recommandé</h4><ol class="olist">${arr(r.d3fend).map(d => `<li><a href="${d3Url(String(d.nom || ''))}" target="_blank" rel="noopener"><strong>${esc(d.nom || '')}</strong></a> <span class="did">${esc(d.id || '')} · ${esc(d.tactique || '')}</span> — ${esc(d.pourquoi || '')}</li>`).join('')}</ol></div>` : ''}
    ${arr(r.actions_immediates).length ? `<div><h4>Actions immédiates</h4><ol class="olist">${arr(r.actions_immediates).map(a => `<li>${esc(a)}</li>`).join('')}</ol></div>` : ''}
    ${arr(r.chronologie).length ? `<div><h4>Chronologie</h4><div class="tbl-scroll"><table class="ctable"><tbody>${arr(r.chronologie).map(c => `<tr><td class="did" style="white-space:nowrap">${esc(c.moment || '')}</td><td>${esc(c.evenement || '')}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
    ${arr(r.faux_positifs).length ? `<div><h4>Faux positifs possibles</h4><ul class="olist">${arr(r.faux_positifs).map(a => `<li>${esc(a)}</li>`).join('')}</ul></div>` : ''}`;
}

applySigma(loadImported());
renderLevels();
run();
