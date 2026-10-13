const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function run({failure, busy = false} = {}) {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function submitSitePolicyForm(');
  const end = source.indexOf('\n  async function ', start + 1);
  const requests = [], errors = [], navigation = [];
  const attributes = new Map(busy ? [['aria-busy', 'true']] : []);
  const form = {action: 'https://panel.test/sites/1/policy', dataset: {npDirty: 'true'},
    getAttribute: name => attributes.get(name), setAttribute: (name, value) => attributes.set(name, value),
    removeAttribute: name => attributes.delete(name), querySelector: () => null};
  class Fields extends FormData {constructor() {super(); this.append('reset_scope', 'php');}}
  const context = vm.createContext({URLSearchParams, clearSitePolicyError: () => {}, csrfToken: () => 'csrf',
    showSitePolicyError: (form, error) => errors.push(error),
    window: {FormData: Fields, location: {assign: url => navigation.push([url, form.dataset.npDirty]), reload: () => navigation.push(['reload', form.dataset.npDirty])}},
    fetch: async (url, options) => {requests.push(options); if (failure) throw failure; return {ok: true, redirected: true, url: 'https://panel.test/sites/1?tab=php&notice=policy-saved'};}});
  vm.runInContext(source.slice(start, end), context);
  return {requests, errors, navigation, result: context.submitSitePolicyForm(form, null)};
}

test('PHP/policy reset accepts its safe native redirect and clears the dirty guard before navigation', async () => {
  const f = run(); await f.result;
  assert.equal(f.requests[0].allowPageResponse, true);
  assert.equal(f.requests[0].body.get('reset_scope'), 'php');
  assert.deepEqual(f.navigation, [['https://panel.test/sites/1?tab=php&notice=policy-saved', 'false']]);
});

test('policy forms reject a second pending mutation', async () => {
  const f = run({busy: true}); await f.result;
  assert.equal(f.requests.length, 0);
});

test('policy errors retain field information and never navigate or replay', async () => {
  const payload = {error: 'Provider memory ceiling', field: 'site_php_memory'};
  const f = run({failure: Object.assign(new Error(payload.error), {payload})}); await f.result;
  assert.deepEqual(f.errors, [payload]);
  assert.deepEqual(f.navigation, []);
  assert.equal(f.requests.length, 1);
});
