import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { parseSigma, compileSigma } from '../src/sigma.js';
import { analyze, toEvents, textFields } from '../src/engine.js';

const BUILTIN = fs.readFileSync(new URL('../rules/sigma.yml', import.meta.url), 'utf8');
const rule = (detection, extra = {}) => compileSigma({ title: 't', tags: ['attack.execution', 'attack.t1059'], detection, ...extra });
const hit = (r, fields, line = '') => r.match(Object.fromEntries(Object.entries(fields).map(([k, v]) => [k.toLowerCase(), String(v)])), line, []);

test('règles intégrées : toutes compilées, avec technique ATT&CK', () => {
  const { rules, errors } = parseSigma(BUILTIN, 'intégrée');
  assert.deepEqual(errors, []);
  assert.equal(rules.length, 6);
  for (const r of rules) assert.ok(r.techniques.length && r.tactics.length, r.title);
});

describe('valeurs et modificateurs', () => {
  test('égalité insensible à la casse, jokers * et ?', () => {
    assert.ok(hit(rule({ s: { Image: 'C:\\Windows\\Sys*\\CMD.EXE' }, condition: 's' }), { Image: 'c:\\windows\\system32\\cmd.exe' }));
    // En Sigma, \* est une étoile littérale, pas un joker.
    assert.ok(!hit(rule({ s: { Image: 'C:\\Windows\\*\\cmd.exe' }, condition: 's' }), { Image: 'C:\\Windows\\System32\\cmd.exe' }));
    assert.ok(!hit(rule({ s: { Image: 'cmd.exe' }, condition: 's' }), { Image: 'C:\\cmd.exe' }));
    assert.ok(hit(rule({ s: { Code: '4?25' }, condition: 's' }), { Code: '4625' }));
  });
  test('contains, startswith, endswith, valeur finissant par une barre oblique inverse', () => {
    assert.ok(hit(rule({ s: { 'CommandLine|contains': 'mimikatz' }, condition: 's' }), { CommandLine: 'x MimiKatz y' }));
    assert.ok(hit(rule({ s: { 'Image|startswith': 'C:\\Windows\\System32\\' }, condition: 's' }), { Image: 'C:\\Windows\\System32\\a.exe' }));
    assert.ok(hit(rule({ s: { 'Image|endswith': ['\\a.exe', '\\b.exe'] }, condition: 's' }), { Image: 'C:\\x\\b.exe' }));
  });
  test('contains|all exige toutes les valeurs', () => {
    const r = rule({ s: { 'CommandLine|contains|all': ['-enc', 'hidden'] }, condition: 's' });
    assert.ok(hit(r, { CommandLine: 'powershell -w hidden -enc AAA' }));
    assert.ok(!hit(r, { CommandLine: 'powershell -enc AAA' }));
  });
  test('windash : tiret, barre oblique, tirets typographiques', () => {
    const r = rule({ s: { 'CommandLine|windash|contains': ' -urlcache ' }, condition: 's' });
    for (const c of ['certutil -urlcache -f', 'certutil /urlcache /f', 'certutil \u2013urlcache x'.replace('\u2013', ' \u2013')]) assert.ok(hit(r, { CommandLine: c + ' ' }), c);
  });
  test('re, y compris le drapeau en tête (?i)', () => {
    assert.ok(hit(rule({ s: { 'CommandLine|re': '(?i)invoke-\\w+' }, condition: 's' }), { CommandLine: 'INVOKE-Mimikatz' }));
    assert.ok(!hit(rule({ s: { 'CommandLine|re': 'invoke-\\w+' }, condition: 's' }), { CommandLine: 'INVOKE-Mimikatz' }));
  });
  test('cidr IPv4 ; IPv6 jamais vrai sans casser la règle', () => {
    const r = rule({ s: { 'DestinationIp|cidr': ['10.0.0.0/8', '::1/128'] }, condition: 's' });
    assert.ok(hit(r, { DestinationIp: '10.2.3.4' }));
    assert.ok(!hit(r, { DestinationIp: '11.2.3.4' }));
  });
  test('null = champ absent ou vide ; exists', () => {
    assert.ok(hit(rule({ s: { OriginalFileName: null }, condition: 's' }), {}));
    assert.ok(hit(rule({ s: { 'User|exists': true }, condition: 's' }), { User: 'x' }));
    assert.ok(!hit(rule({ s: { 'User|exists': true }, condition: 's' }), {}));
  });
  test('mots-clés : cherchés dans la ligne entière', () => {
    const r = rule({ keywords: ['history -c', 'unset HISTFILE'], condition: 'keywords' });
    assert.ok(r.match({}, 'bash[1]: HISTORY -c', []));
    assert.ok(!r.match({}, 'ls -la', []));
  });
});

describe('conditions', () => {
  const det = { sel: { A: '1' }, filter_a: { B: '1' }, filter_b: { C: '1' } };
  test('and not 1 of filter_*', () => {
    const r = rule({ ...det, condition: 'sel and not 1 of filter_*' });
    assert.ok(hit(r, { A: 1 }));
    assert.ok(!hit(r, { A: 1, C: 1 }));
  });
  test('all of them, parenthèses, or, liste de conditions', () => {
    assert.ok(hit(rule({ ...det, condition: 'all of them' }), { A: 1, B: 1, C: 1 }));
    assert.ok(!hit(rule({ ...det, condition: 'all of them' }), { A: 1, B: 1 }));
    assert.ok(hit(rule({ ...det, condition: '(sel or filter_a) and not filter_b' }), { B: 1 }));
    assert.ok(hit(rule({ ...det, condition: ['sel', 'filter_b'] }), { C: 1 }));
  });
  test('liste de sélections = OU', () => {
    const r = rule({ s: [{ A: '1' }, { B: '2' }], condition: 's' });
    assert.ok(hit(r, { B: 2 }));
    assert.ok(!hit(r, { B: 1 }));
  });
});

describe('règles refusées, avec une raison lisible', () => {
  const reason = y => parseSigma(y).errors[0]?.reason || '';
  test('agrégation, modificateur inconnu, sélection inconnue, pas de technique, YAML invalide', () => {
    const base = 'title: x\ntags: [attack.t1059]\ndetection:\n  sel:\n    A: 1\n';
    assert.match(reason(base + '  condition: sel | count() > 5\n'), /agrégation/);
    assert.match(reason('title: x\ntags: [attack.t1059]\ndetection:\n  sel:\n    A|base64: x\n  condition: sel\n'), /base64/);
    assert.match(reason(base + '  condition: nope\n'), /inconnue/);
    assert.match(reason('title: x\ndetection:\n  sel:\n    A: 1\n  condition: sel\n'), /technique ATT&CK/);
    assert.match(reason('title: [x\n'), /YAML invalide/);
  });
});

describe('intégration au moteur', () => {
  const { rules } = parseSigma(BUILTIN, 'intégrée');
  test('export XML Windows : Kerberoasting et ajout au groupe Administrateurs', () => {
    const xml = `<Events>
<Event><System><EventID>4769</EventID><TimeCreated SystemTime="2026-09-29T10:00:00Z"/><Computer>DC01</Computer></System>
<EventData><Data Name="ServiceName">svc_sql</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>
<Event><System><EventID>4769</EventID><Computer>DC01</Computer></System>
<EventData><Data Name="ServiceName">WKS-042$</Data><Data Name="TicketEncryptionType">0x17</Data></EventData></Event>
<Event><System><EventID>4732</EventID><Computer>DC01</Computer></System>
<EventData><Data Name="TargetUserName">Administrators</Data><Data Name="MemberName">CN=helpdesk</Data></EventData></Event>
</Events>`;
    const res = analyze(xml, undefined, rules);
    assert.ok(res.list.find(f => f.id === 'T1558.003')?.sigma?.length, 'Kerberoasting');
    const kerb = rules.find(r => r.techniques.includes('T1558.003'));
    const { lines, fields } = toEvents(xml);
    assert.ok(kerb.match(fields[0], lines[0], []), 'svc_sql en RC4');
    assert.ok(!kerb.match(fields[1], lines[1], []), 'le compte machine WKS-042$ est filtré');
    assert.ok(res.list.find(f => f.id === 'T1098')?.sigma);
  });
  test('Sysmon texte clé=valeur : chemins avec espaces gardés entiers', () => {
    const line = '2026-09-29 09:41:12 WIN-PC01 Sysmon EventID=1 ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd /c whoami"';
    assert.equal(textFields(line).parentimage, 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE');
    assert.equal(textFields(line).commandline, 'cmd /c whoami');
    const f = analyze(line, undefined, rules).list.find(x => x.id === 'T1204.002');
    assert.deepEqual(f.sigma, ['Office lançant un interpréteur ou un binaire proxy']);
  });
  test('access.log : champs W3C pour les règles web', () => {
    const f = textFields('203.0.113.7 - - [28/Sep/2026:10:02:11 +0200] "GET /a.php?id=1 HTTP/1.1" 200 51 "-" "sqlmap/1.8"');
    assert.equal(f['cs-uri-query'], 'id=1');
    assert.equal(f['c-useragent'], 'sqlmap/1.8');
    assert.equal(f['sc-status'], '200');
  });
  test('champs JSON (ECS) renommés pour Sigma', () => {
    const { fields } = toEvents(JSON.stringify({ process: { executable: 'C:\\x\\cmd.exe', parent: { executable: 'C:\\o\\WINWORD.EXE' } } }));
    assert.equal(fields[0].image, 'C:\\x\\cmd.exe');
    assert.equal(fields[0].parentimage, 'C:\\o\\WINWORD.EXE');
  });
  test('sans règles Sigma, le résultat ne change pas', () => {
    const t = fs.readFileSync(new URL('../samples/windows-sysmon.log', import.meta.url), 'utf8');
    assert.deepEqual(analyze(t).list.map(f => f.id), analyze(t, undefined, []).list.map(f => f.id));
  });
});

test('origine des détections : règles locales, Sigma, ou les deux', () => {
  const { rules } = parseSigma(BUILTIN, 'intégrée');
  const line = '2026-09-29 WIN-PC01 EventID=1 ParentImage=C:\\Office16\\WINWORD.EXE Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd /c whoami"';
  const f = analyze(line, undefined, rules).list.find(x => x.id === 'T1204.002');
  assert.ok(f.native && f.sigma, 'vue par les deux');
  const k = analyze('EventID=4769 ServiceName=svc TicketEncryptionType=0x12 x', undefined, [...rules]).list;
  assert.ok(k.every(x => x.native || x.sigma));
});
