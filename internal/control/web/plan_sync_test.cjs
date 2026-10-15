const test = require('node:test');
const assert = require('node:assert/strict');
const ui = require('./static/plan-sync.js');
const fs = require('node:fs');

test('sync rows use a two-column layout rather than icon-slot object rows', () => {
  const source = fs.readFileSync(__dirname + '/static/plan-sync.js', 'utf8');
  assert.match(source, /row.className = "np-plan-sync-row"/);
});

test('WordPress validation rejects enabled zero capacity without changing input', () => {
  const value = {enabled:true, limit:0, unlimited:false, lifecycle:'active'};
  assert.match(ui.wordPressError(value), /positive/);
  assert.equal(value.limit, 0);
  assert.equal(ui.wordPressError({...value, limit:5}), '');
  assert.equal(ui.wordPressError({...value, unlimited:true}), '');
  assert.equal(ui.wordPressError({...value, enabled:false}), '');
  assert.equal(ui.wordPressError({...value, lifecycle:'draft'}), '');
});

test('sync summary distinguishes excluded subscriptions from failures', () => {
  assert.match(ui.summary({synced:2,pending:1,failed:1,excluded:1}), /2 updated.*1 applying.*1 failed.*1 excluded/);
  assert.equal(ui.summary({synced:0,pending:0,failed:0,excluded:0}), 'No linked subscriptions');
  assert.equal(ui.shouldPoll({state:'pending'}), true);
  assert.equal(ui.shouldPoll({state:'failed'}), false);
  assert.equal(ui.shouldPoll({state:'in_sync'}), false);
});

test('sync row labels never claim a pending service is fully applied', () => {
  assert.equal(ui.stateLabel({state:'applying'}), 'Applying services');
  assert.equal(ui.stateLabel({state:'pending'}), 'Waiting for plan update');
  assert.equal(ui.stateLabel({state:'excluded',mode:'locked'}), 'Excluded (locked)');
  assert.equal(ui.stateLabel({state:'failed'}), 'Needs attention');
});
