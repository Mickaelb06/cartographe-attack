// Intégrité des référentiels : une règle mal formée casse la page sans erreur visible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import rules from '../rules/attack-rules.json' with { type: 'json' };
import d3 from '../rules/d3fend.json' with { type: 'json' };
import tactics from '../rules/tactics.json' with { type: 'json' };

const TAC_KEYS = new Set(tactics.map(t => t.key));
const D3_TACTICS = new Set(['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore']);

test('14 tactiques ATT&CK Enterprise, IDs uniques', () => {
  assert.equal(tactics.length, 14);
  assert.equal(new Set(tactics.map(t => t.id)).size, 14);
  for (const t of tactics) assert.match(t.id, /^TA\d{4}$/);
});

test('catalogue D3FEND bien formé', () => {
  for (const [k, v] of Object.entries(d3)) {
    assert.match(v.id, /^D3-[A-Z]+$/, k);
    assert.ok(D3_TACTICS.has(v.tactic), `${k} : tactique ${v.tactic}`);
    assert.ok(v.name && v.benefit, k);
  }
});

test('IDs de règles uniques', () => {
  const ids = rules.map(r => r.id);
  assert.equal(new Set(ids).size, ids.length, ids.filter((x, i) => ids.indexOf(x) !== i).join(', '));
});

for (const r of rules) {
  test(`règle ${r.id} ${r.name}`, () => {
    assert.match(r.id, /^T\d{4}(\.\d{3})?$/);
    assert.ok([1, 2, 3, 4].includes(r.severity), 'sévérité 1 à 4');
    assert.ok(r.tactics.length, 'au moins une tactique');
    for (const t of r.tactics) assert.ok(TAC_KEYS.has(t), `tactique inconnue : ${t}`);
    assert.ok(r.d3fend.length, 'au moins une contre-mesure');
    for (const k of r.d3fend) assert.ok(d3[k], `contre-mesure inconnue : ${k}`);
    assert.ok(r.checks.length, 'au moins un point à vérifier');
    assert.ok(r.patterns.some(p => p.weight >= 1), 'au moins un motif capable de déclencher seul');
    for (const p of r.patterns) {
      assert.ok(!p.flags.includes('g'), `drapeau g interdit : ${p.regex}`);
      assert.doesNotThrow(() => new RegExp(p.regex, p.flags), p.regex);
      assert.ok([0.5, 1, 2, 3].includes(p.weight), `poids ${p.weight}`);
    }
  });
}
