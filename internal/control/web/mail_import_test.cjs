const test = require('node:test');
const assert = require('node:assert/strict');
const ui = require('./static/mail-import.js');
test('mail import polls only active states', () => {
  for (const state of ['queued','discovering','copying','verifying']) assert.equal(ui.running(state), true);
  for (const state of ['complete','attention_required','cancelled','paused']) assert.equal(ui.running(state), false);
});
test('mail counters never display untrusted strings as progress', () => {
  assert.equal(ui.count(5), '5');
  assert.equal(ui.count('<img>'), '0');
  assert.equal(ui.count(-1), '0');
});
