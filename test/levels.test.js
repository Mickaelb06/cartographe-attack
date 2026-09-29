import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { analyze, prioritize, extractIOC, hostOf, D3 } from '../src/engine.js';
import { LEVELS, triage, timeline, timeOf, scope, containment, chain, detectionQuality, executive, levelReport } from '../src/levels.js';
import tactics from '../rules/tactics.json' with { type: 'json' };

const sample = name => fs.readFileSync(new URL(`../samples/${name}.log`, import.meta.url), 'utf8');
const stateOf = text => { const res = analyze(text); return { res, prio: prioritize(res.list), ioc: extractIOC(text) }; };
const S = Object.fromEntries(['windows-sysmon', 'linux-auth', 'web-access', 'ransomware'].map(n => [n, stateOf(sample(n))]));
const EMPTY = stateOf('');
const BENIGN = stateOf('[2025-09-03 00:53:06.19 | INF] Copied 18 out of 18 files. See C:\\Windows\\Temp\\artifacts\\CopyLog.csv for copy details');

test('chaque tactique a un texte direction et une piste de chasse', () => {
  for (const t of tactics) assert.ok(t.plain && t.hunt, t.key);
});

test('quatre niveaux, du N1 au responsable', () => {
  assert.deepEqual(LEVELS.map(l => l.key), ['n1', 'n2', 'n3', 'chef']);
});

describe('N1 : triage', () => {
  test('scénarios critiques → P1, escalade immédiate', () => {
    for (const [name, st] of Object.entries(S)) {
      const t = triage(st);
      assert.equal(t.prio, 'P1', name);
      assert.match(t.decision, /Escalader/, name);
      assert.ok(t.reasons.length && t.checks.length > 2, name);
    }
  });
  test('logs sans détection → clore ; aucun log → rien à qualifier', () => {
    assert.match(triage(BENIGN).decision, /^Clore/);
    assert.equal(triage(EMPTY).prio, '—');
    assert.match(triage(EMPTY).decision, /Aucun log/);
  });
});

describe('N2 : investigation', () => {
  test('machines extraites des formats courants', () => {
    assert.equal(hostOf('Sep 28 03:14:01 web-02 sshd[20411]: Failed password'), 'web-02');
    assert.equal(hostOf('2026-09-27T23:40:11Z host=SRV-APP03 EventID=4720'), 'SRV-APP03');
    assert.equal(hostOf('2026-09-29 09:41:12 WIN-PC01 Sysmon EventID=1'), 'WIN-PC01');
    assert.equal(hostOf('203.0.113.77 - - [28/Sep/2026:10:02:11 +0200] "GET / HTTP/1.1"'), undefined);
    assert.deepEqual(scope(S['windows-sysmon']).hosts, ['WKS-042', 'SRV-FILE01']);
  });
  test('IP séparées internes / externes', () => {
    const sc = scope(S['linux-auth']);
    assert.ok(sc.extIps.includes('45.155.205.233'));
    assert.ok(sc.intIps.every(ip => /^(10\.|192\.168\.|172\.)/.test(ip)));
  });
  test('chronologie dans l’ordre du log, horodatée, sans doublon', () => {
    const tl = timeline(S['ransomware']);
    assert.ok(tl.length > 3);
    assert.deepEqual(tl.map(x => x.i), [...tl.map(x => x.i)].sort((a, b) => a - b));
    assert.equal(new Set(tl.map(x => x.i)).size, tl.length);
    assert.ok(tl.every(x => x.time && x.techs.length));
  });
  test('formats d’horodatage', () => {
    assert.equal(timeOf('2026-09-27T23:40:11Z host=x'), '2026-09-27 23:40:11');
    assert.equal(timeOf('Sep 28 03:14:01 web-02 sshd'), 'Sep 28 03:14:01');
    assert.equal(timeOf('1.2.3.4 - - [28/Sep/2026:10:02:11 +0200] "GET /"'), '28/Sep/2026:10:02:11');
  });
  test('confinement = uniquement Evict / Isolate', () => {
    const ct = containment(S['windows-sysmon']);
    assert.ok(ct.length);
    for (const p of ct) assert.ok(['Evict', 'Isolate'].includes(D3[p.k].tactic), p.k);
  });
});

describe('N3 : chaîne et chasse', () => {
  test('phase la plus avancée et pistes sur les tactiques non vues', () => {
    const c = chain(S['web-access']);
    assert.ok(c.reached.length);
    assert.ok(c.furthest);
    const seen = new Set(c.reached.map(t => t.key));
    assert.ok(c.hunts.length && c.hunts.every(h => !seen.has(h.key) && h.text));
  });
  test('aucune détection → aucune piste', () => {
    assert.deepEqual(chain(BENIGN), { reached: [], furthest: null, hunts: [] });
  });
  test('qualité de détection : partitions disjointes', () => {
    const q = detectionQuality(S['windows-sysmon']);
    assert.ok(q.weak.every(f => f.conf === 1));
    assert.ok(q.single.every(f => f.conf > 1 && f.ev.length === 1));
  });
});

describe('Responsable SOC', () => {
  test('incident critique : récit, risques, décisions de crise', () => {
    const x = executive(S['ransomware']);
    assert.match(x.headline, /critique/);
    assert.ok(x.story.length >= 3);
    assert.ok(x.impacts.some(s => /interruption/.test(s)));
    assert.ok(x.decisions.some(s => /plan de réponse/.test(s)));
  });
  test('rien de détecté : pas de décision', () => {
    const x = executive(BENIGN);
    assert.equal(x.headline, 'Rien à signaler');
    assert.deepEqual(x.decisions, []);
  });
});

test('rapport Markdown pour chaque niveau, y compris sans données', () => {
  for (const l of LEVELS) for (const st of [S['linux-auth'], EMPTY]) {
    const md = levelReport(l.key, st, new Date('2026-09-29T10:00:00Z'));
    assert.match(md, /^# /);
    assert.doesNotMatch(md, /undefined|NaN/);
  }
});
