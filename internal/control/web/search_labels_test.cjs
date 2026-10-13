const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

test('global search uses readable object names rather than storage enums', () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function searchKindLabel(');
  assert.ok(start >= 0);
  const end = source.indexOf('\n  function ', start + 1);
  const context = vm.createContext({});
  vm.runInContext(source.slice(start, end), context);
  for (const [kind, label] of Object.entries({site: 'Website', customer: 'Customer', subscription: 'Subscription', database: 'Database', mail_domain: 'Mail domain', mailbox: 'Mailbox'})) {
    assert.equal(context.searchKindLabel(kind), label);
  }
  assert.equal(context.searchKindLabel('future_internal_enum'), 'Resource');
});
