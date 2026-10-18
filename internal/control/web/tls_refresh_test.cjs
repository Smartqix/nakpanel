const installLifecycle = require('./lifecycle_harness.cjs');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function tlsRefreshHarness(options = {}) {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initTLSRefresh(root)');
  assert(start >= 0, 'TLS refresh initializer exists');
  const end = source.indexOf('\n  function databaseActionForm', start);
  assert(end > start);
  const timers = new Map();
  const feedback = { hidden: true, textContent: '' };
  const listeners = new Map();
  const panel = { dataset: { npTlsState: options.initialState || 'pending', npTlsSiteId: '7' }, querySelector: () => feedback, addEventListener: (name, fn) => listeners.set(name, fn), contains: () => true };
  const nextPanel = { dataset: { npTlsState: options.nextState || 'active', npTlsSiteId: '7' } };
  const url = options.url || 'https://panel.test/support/customers/88/sites/7?tab=ssl&notice=certificate-queued';
  let currentPanel = panel;
  let nextTimerId = 1;
  let calls = 0;
  let navigated = '';
  const document = {
    hidden: false,
    addEventListener: (name, fn) => listeners.set(name, fn),
    querySelector(selector) {
      return selector === '[data-np-tls-workspace]' ? currentPanel : options.busy ? {} : null;
    }
  };
  const context = vm.createContext({
    AbortController,
    document,
    window: {
      location: { href: url, replace: target => { navigated = target; } },
      setTimeout(fn, delay) { const id = nextTimerId++; timers.set(id, { fn, delay }); return id; },
      clearTimeout(id) { timers.delete(id); }
    },
    fetch: async (target, init) => {
      calls++;
      assert.equal(target, url, 'status checks retain the current customer-scoped URL');
      assert.equal(init.method, 'GET', 'status checks must not replay certificate issuance');
      assert.equal(init.credentials, 'same-origin');
      assert.equal(init.cache, 'no-store');
      if (options.afterFetch) options.afterFetch(document);
      return { ok: true, redirected: false, status: 200, text: async () => '<html>current TLS workspace</html>', ...options.response };
    },
    DOMParser: class {
      parseFromString() { return { querySelector: () => nextPanel }; }
    }
  });
  context.window.fetch = context.fetch;
  installLifecycle(context);
  vm.runInContext(source.slice(start, end) + '\ninitTLSRefresh();', context);
  return {
    feedback, document, timers,
    get calls() { return calls; },
    get navigated() { return navigated; },
    replacePanel() { currentPanel = {}; },
    submit(defaultPrevented = false) { listeners.get('submit')({ target: { method: 'post' }, defaultPrevented }); },
    async tick() {
      const entry = Array.from(timers.entries()).find(([, timer]) => timer.delay !== 10000);
      assert(entry, 'a status check is scheduled');
      timers.delete(entry[0]);
      await entry[1].fn();
    }
  };
}

for (const state of ['active', 'failed']) {
  test(`pending TLS refresh picks up ${state} via a scoped GET`, async () => {
    const h = tlsRefreshHarness({ nextState: state });
    await h.tick();
    assert.equal(h.calls, 1);
    assert.equal(h.navigated, 'https://panel.test/support/customers/88/sites/7?tab=ssl&notice=certificate-queued');
    assert.equal(h.timers.size, 0, 'terminal state stops polling');
  });
}

test('terminal TLS workspaces do not start polling', () => {
  const h = tlsRefreshHarness({ initialState: 'active' });
  assert.equal(h.timers.size, 0);
  assert.equal(h.calls, 0);
});

test('TLS status checks are bounded while issuance remains pending', async () => {
  const h = tlsRefreshHarness({ nextState: 'pending' });
  for (let i = 0; i < 61; i++) await h.tick();
  assert.equal(h.calls, 60);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 0);
  assert.equal(h.feedback.hidden, false);
  assert.match(h.feedback.textContent, /still pending/i);
});

test('TLS status checks retry a transient HTTP failure', async () => {
  const h = tlsRefreshHarness({ response: { ok: false, status: 503 } });
  await h.tick();
  assert.equal(h.calls, 1);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 1);
});

for (const response of [{ redirected: true }, { ok: false, status: 401 }, { ok: false, status: 403 }, { ok: false, status: 404 }]) {
  test(`TLS status checks stop when access changes: ${JSON.stringify(response)}`, async () => {
    const h = tlsRefreshHarness({ response });
    await h.tick();
    assert.equal(h.calls, 1);
    assert.equal(h.navigated, '');
    assert.equal(h.timers.size, 0);
  });
}

test('obsolete TLS workspace timers cannot fetch or navigate', async () => {
  const h = tlsRefreshHarness();
  h.replacePanel();
  await h.tick();
  assert.equal(h.calls, 0);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 0);
});

test('TLS checks defer while a dialog or dirty form is open', async () => {
  const h = tlsRefreshHarness({ busy: true });
  await h.tick();
  assert.equal(h.calls, 0);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 1);
});

test('TLS result does not navigate if the page becomes hidden during a check', async () => {
  const h = tlsRefreshHarness({ afterFetch: document => { document.hidden = true; } });
  await h.tick();
  assert.equal(h.calls, 1);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 1);
});

test('TLS refresh cannot interrupt a native certificate form submission', async () => {
  let h;
  h = tlsRefreshHarness({ afterFetch: () => h.submit() });
  await h.tick();
  assert.equal(h.calls, 1);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 0);
});

test('a progressive dialog form does not permanently stop TLS status checks', async () => {
  const h = tlsRefreshHarness({ nextState: 'pending' });
  h.submit(true);
  await h.tick();
  assert.equal(h.calls, 1);
  assert.equal(h.navigated, '');
  assert.equal(h.timers.size, 1);
});
