const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/navigation.js', 'utf8');
const base = 'https://panel.test';
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function envelope(title, main = '<h1>' + title + '</h1>', shell = {}) {
  return '<template data-np-shell="meta" data-title="' + title + '"></template>' +
    ['sidebar', 'topbar', 'support', 'site-dialog', 'customer-dialog'].map(part =>
      '<template data-np-shell="' + part + '">' + (shell[part] || '') + '</template>').join('') +
    '<div data-np-fragment="main">' + main + '</div>';
}
function response(path, html = envelope(path)) {
  return {ok: true, status: 200, url: base + path, redirected: false,
    headers: {get: name => name === 'Content-Type' ? 'text/html' : null},
    text: async () => html};
}
// A scripting-disabled DOM boundary, including separate template content trees.
// Only platform DOM/history are doubled; every navigation runs the full controller.
class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag; this.attrs = {...attrs}; this.childNodes = []; this.dataset = {};
    this.scrollTop = 0; this.classes = new Set(); this.isConnected = true;
    this.classList = {add: (...names) => names.forEach(name => this.classes.add(name)),
      remove: (...names) => names.forEach(name => this.classes.delete(name)),
      contains: name => this.classes.has(name), toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name)};
    for (const [name, value] of Object.entries(attrs)) this.setAttribute(name, value);
    if (tag === 'template') this.content = new Element('fragment');
  }
  get attributes() { return Object.entries(this.attrs).map(([name, value]) => ({name, value})); }
  get firstElementChild() { return this.childNodes[0] || null; }
  get parentElement() { return this.parent; }
  get open() { return this.hasAttribute('open'); }
  set open(value) { if (value) this.setAttribute('open', ''); else this.removeAttribute('open'); }
  setAttribute(name, value) {
    this.attrs[name] = value;
    if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase())] = value;
  }
  getAttribute(name) { return this.attrs[name] ?? null; }
  hasAttribute(name) { return Object.hasOwn(this.attrs, name); }
  removeAttribute(name) { delete this.attrs[name]; }
  appendChild(child) { this.childNodes.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  prepend(child) { this.childNodes.unshift(child); child.parent = this; }
  replaceChildren(...children) { this.childNodes = []; this.append(...children); }
  replaceWith(next) { this.parent.childNodes.splice(this.parent.childNodes.indexOf(this), 1, next); next.parent = this.parent; this.parent = null; }
  remove() { if (this.parent) this.parent.childNodes.splice(this.parent.childNodes.indexOf(this), 1); this.parent = null; }
  before(node) { if (this.parent) { this.parent.childNodes.splice(this.parent.childNodes.indexOf(this), 0, node); node.parent = this.parent; } }
  contains(node) { return this.childNodes.some(child => child === node || child.contains(node)); }
  matches(selector) {
    return selector.split(',').some(part => {
      part = part.trim();
      const tag = part.match(/^[\w-]+/), id = part.match(/#([\w-]+)/), cls = part.match(/\.([\w-]+)/);
      if (tag && tag[0] !== this.tagName || id && this.getAttribute('id') !== id[1] || cls && !(this.getAttribute('class') || '').split(' ').includes(cls[1])) return false;
      return Array.from(part.matchAll(/\[([\w-]+)(?:="([^"]*)")?\]/g)).every(([, name, value]) => value === undefined ? this.hasAttribute(name) : this.getAttribute(name) === value);
    });
  }
  closest(selector) { return this.matches(selector) ? this : this.parent && this.parent.closest(selector); }
  querySelectorAll(selector) {
    const found = [];
    for (const child of this.childNodes) {
      if (child.matches(selector)) found.push(child);
      found.push(...child.querySelectorAll(selector));
    }
    return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener() {}
  focus() { this.focused = true; }
  reset() {
    this.resetCalled = true;
    this.querySelectorAll('input').forEach(input => { input.value = input.getAttribute('value') || ''; });
  }
}
function parse(html) {
  const doc = new Element('document'), stack = [doc];
  for (const token of html.matchAll(/<\/?([\w-]+)\b([^>]*)>|([^<]+)/g)) {
    if (!token[1]) { stack.at(-1).textContent = (stack.at(-1).textContent || '') + token[3]; continue; }
    if (token[0].startsWith('</')) { stack.pop(); continue; }
    const attrs = {};
    for (const [, name, value] of token[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[name] = value || '';
    const node = new Element(token[1], attrs);
    if (node.tagName === 'input') node.value = node.getAttribute('value') || '';
    stack.at(-1).appendChild(node);
    if (!['input', 'br', 'hr', 'meta'].includes(node.tagName)) stack.push(node.content || node);
  }
  doc.body = doc;
  return doc;
}
function harness() {
  const windowEvents = {}, documentEvents = {}, assignments = [], pushes = [], goCalls = [], requests = [];
  const body = parse('<body><aside class="np-routed-side"></aside><header class="np-routed-top"></header><main id="main-content"><h1>Dashboard</h1></main></body>').firstElementChild;
  body.dataset.npNav = 'on';
  const main = body.querySelector('#main-content');
  const document = {body, title: 'Dashboard', querySelector: selector => body.querySelector(selector),
    querySelectorAll: selector => body.querySelectorAll(selector), createElement: tag => new Element(tag),
    createTextNode: text => Object.assign(new Element('text'), {textContent: text}),
    addEventListener: (type, listener) => { documentEvents[type] = listener; }, dispatchEvent() {}};
  const location = {href: base + '/dashboard', origin: base, assign: url => assignments.push(url)};
  const entries = [{url: location.href, state: null}];
  let position = 0;
  const traversals = [];
  const history = {
    get state() { return entries[position].state; },
    replaceState(state, _, url) { entries[position] = {url: new URL(url, location.href).href, state}; location.href = entries[position].url; },
    pushState(state, _, url) { entries.splice(++position); entries.push({url: new URL(url, location.href).href, state}); location.href = entries[position].url; pushes.push(url); },
    go(delta) {
      goCalls.push(delta);
      // Traversals take effect asynchronously, just like browser history.go().
      traversals.push(() => {
        const target = position + delta;
        if (target < 0 || target >= entries.length) return;
        position = target; location.href = entries[position].url;
        windowEvents.popstate({state: history.state});
      });
    }
  };
  const ui = {fetch: async (url, options) => { requests.push({url, options}); return response(new URL(url).pathname); },
    confirm: async () => true, setBusy() {}, dialogs: {close: dialog => { dialog.open = false; }, capture: () => null, restore: () => false}};
  const window = {document, location, history, NakpanelUI: ui, navigator: {}, scrollY: 0,
    scrollTo: (_, value) => { window.scrollY = value; }, setTimeout: () => 1, clearTimeout() {},
    addEventListener: (type, listener) => { windowEvents[type] = listener; }};
  class Fields extends FormData { constructor(form) { super(); for (const entry of form.entries || []) this.append(...entry); } }
  vm.runInNewContext(source, {window, URL, URLSearchParams, FormData: Fields, AbortController,
    DOMParser: class {parseFromString(html) { return parse(html); }}, CustomEvent: class {}});
  windowEvents.DOMContentLoaded();
  return {ui, document, main, history, location, entries, pushes, goCalls, requests, assignments, documentEvents,
    get position() { return position; },
    async flush() { while (traversals.length) { traversals.shift()(); await tick(); } },
    async back() { history.go(-1); await this.flush(); },
    async forward() { history.go(1); await this.flush(); },
    submit: form => windowEvents.submit({target: form, preventDefault() {}})};
}

test('D1 fragment discards noscript required controls in main and every shell template', async () => {
  const h = harness(), fallback = '<noscript><input name="confirm" type="checkbox" required></noscript>';
  h.ui.fetch = async () => response('/git', envelope('Git', '<h1>Git</h1>' + fallback, {
    sidebar: '<aside class="np-routed-side">' + fallback + '</aside>',
    topbar: '<header class="np-routed-top">' + fallback + '</header>',
    support: '<section class="np-support-banner">' + fallback + '</section>',
    'site-dialog': '<dialog id="site-dialog">' + fallback + '</dialog>',
    'customer-dialog': '<dialog id="customer-dialog">' + fallback + '</dialog>'
  }));
  await h.ui.navigate('/git');
  assert.equal(h.document.title, 'Git');
  assert.equal(h.document.querySelectorAll('noscript').length, 0);
  assert.equal(h.document.querySelectorAll('input[required]').length, 0);
});

test('D2 two pending Backs render final target and preserve all Forward entries', async () => {
  const h = harness();
  for (const path of ['/sites', '/subscriptions', '/databases']) await h.ui.navigate(path);
  const pending = deferred();
  h.ui.fetch = async url => url.endsWith('/subscriptions') ? pending.promise : response('/sites');
  await h.back();
  await h.back();
  pending.resolve(response('/subscriptions')); await tick();
  assert.equal(h.document.title, '/sites');
  assert.deepEqual(h.entries.map(entry => entry.url), ['/dashboard', '/sites', '/subscriptions', '/databases'].map(path => base + path));
  assert.equal(h.position, 1);
  assert.deepEqual(h.entries.map(entry => entry.state.npIndex), [0, 1, 2, 3]);
  h.ui.fetch = async url => response(new URL(url).pathname);
  await h.forward(); assert.equal(h.document.title, '/subscriptions');
  await h.forward(); assert.equal(h.document.title, '/databases');
});

test('D2 declined dirty Back returns to rendered entry with Forward intact', async () => {
  const h = harness();
  for (const path of ['/sites', '/subscriptions']) await h.ui.navigate(path);
  await h.back();
  h.main.appendChild(new Element('form', {'data-np-dirty-guard': '', 'data-np-dirty': 'true'}));
  h.ui.confirm = async () => false;
  await h.back();
  assert.equal(h.location.href, base + '/sites');
  assert.equal(h.document.title, '/sites');
  assert.equal(h.position, 1);
  assert.equal(h.entries.length, 3);
  assert.equal(h.entries[2].url, base + '/subscriptions');
  assert.equal(h.pushes.length, 2);
  assert.deepEqual(h.goCalls, [-1, -1, 1]);
  h.ui.confirm = async () => true;
  await h.forward(); assert.equal(h.document.title, '/subscriptions');
});

test('D2 failed click during pending Back returns to rendered entry without adding history', async () => {
  const h = harness();
  for (const path of ['/sites', '/subscriptions', '/databases']) await h.ui.navigate(path);
  const pending = deferred();
  h.ui.fetch = async url => { if (url.endsWith('/subscriptions')) return pending.promise; throw new Error('offline'); };
  await h.back();
  // Aborting the Back must not itself traverse; the click may still commit.
  const next = h.ui.navigate('/customers');
  assert.deepEqual(h.goCalls, [-1]);
  await next; await h.flush();
  assert.equal(h.location.href, base + '/databases');
  assert.equal(h.document.title, '/databases');
  assert.equal(h.position, 3);
  assert.equal(h.entries.length, 4);
  assert.equal(h.pushes.length, 3);
  pending.resolve(response('/subscriptions')); await tick();
  assert.equal(h.location.href, base + '/databases');
});

test('D4 commit replaces filled customer dialog and mounts fresh controls', async () => {
  const h = harness();
  const stale = parse('<dialog id="customer-dialog" open><form><input name="name" value="Customer A"><input name="password" type="password" value="secret"></form></dialog>').firstElementChild;
  h.document.body.appendChild(stale);
  const signal = h.ui.lifecycle.signal(stale), mounted = [];
  h.ui.lifecycle.onMount(root => mounted.push(root));
  h.ui.fetch = async () => response('/customers', envelope('Customers', '<h1>Customers</h1>', {
    'customer-dialog': '<dialog id="customer-dialog"><form><input name="name"><input type="password" name="password"></form></dialog>'
  }));
  await h.ui.navigate('/customers');
  const fresh = h.document.querySelector('#customer-dialog');
  assert.notEqual(fresh, stale);
  assert.equal(stale.open, false);
  assert.equal(signal.aborted, true);
  assert.ok(mounted.includes(fresh));
  assert.equal(fresh.querySelector('[name="name"]').value, '');
  assert.equal(fresh.querySelector('[type="password"]').value, '');
});

for (const fragment of [true, false]) test('D4 successful ' + (fragment ? 'fragment' : 'legacy') + ' dialog submit resets fields and clears passwords before swap', async () => {
  const h = harness();
  const dialog = parse('<dialog id="customer-dialog" open><form method="post" action="/customers"><input name="name"><input name="password" type="password" value="default-secret"></form></dialog>').firstElementChild;
  const form = dialog.querySelector('form'), password = form.querySelector('[type="password"]');
  form.querySelector('[name="name"]').value = 'Customer A'; password.value = 'entered-secret';
  h.document.body.appendChild(dialog);
  let swapped = false;
  h.ui.lifecycle.onUnmount(root => {
    if (root !== h.main) return;
    swapped = true;
    assert.equal(form.resetCalled, true);
    assert.equal(form.querySelector('[name="name"]').value, '');
    assert.equal(password.value, '');
  });
  h.ui.fetch = async () => response('/customers', fragment ? envelope('Saved') : '<p>Saved</p>');
  await h.submit(form);
  assert.equal(swapped, true);
  assert.equal(password.value, '');
});

test('D2 failed submit during pending Back recovers the rendered entry', async () => {
  const h = harness();
  for (const path of ['/sites', '/subscriptions']) await h.ui.navigate(path);
  const form = parse('<form method="post" action="/save"><input name="name"></form>').firstElementChild;
  h.main.appendChild(form);
  const pending = deferred();
  h.ui.fetch = async (url, options) => { if (options.method !== 'POST') return pending.promise; throw new Error('offline'); };
  await h.back();
  await h.submit(form); await h.flush();
  assert.equal(h.location.href, base + '/subscriptions');
  assert.equal(h.document.title, '/subscriptions');
  assert.equal(h.entries.length, 3);
  assert.equal(h.pushes.length, 2);
  pending.resolve(response('/sites')); await tick();
});

test('D2 successful click from a traversed entry keeps positional indexes usable for recovery', async () => {
  const h = harness();
  for (const path of ['/sites', '/subscriptions', '/databases']) await h.ui.navigate(path);
  const pending = deferred();
  h.ui.fetch = async url => url.endsWith('/subscriptions') ? pending.promise : response('/customers');
  await h.back();
  await h.ui.navigate('/customers');
  assert.deepEqual(h.entries.map(entry => entry.state.npIndex), [0, 1, 2, 3]);
  assert.deepEqual(h.entries.map(entry => entry.url), ['/dashboard', '/sites', '/subscriptions', '/customers'].map(path => base + path));
  h.ui.fetch = async () => { throw new Error('offline'); };
  await h.back();
  assert.equal(h.location.href, base + '/customers');
  assert.equal(h.position, 3);
  pending.resolve(response('/subscriptions')); await tick();
});

test('D2 same-URL entries retain their identity when a click fails during pending Back', async () => {
  const h = harness();
  h.ui.fetch = async () => response('/sites', envelope('First sites'));
  await h.ui.navigate('/sites');
  h.ui.fetch = async () => response('/sites', envelope('Second sites'));
  await h.ui.navigate('/sites');
  const keys = h.entries.map(entry => entry.state.npKey), pending = deferred();
  h.ui.fetch = async url => { if (url.endsWith('/sites')) return pending.promise; throw new Error('offline'); };
  await h.back();
  await h.ui.navigate('/customers'); await h.flush();
  assert.deepEqual(h.entries.map(entry => entry.state.npIndex), [0, 1, 2]);
  assert.deepEqual(h.entries.map(entry => entry.state.npKey), keys);
  assert.equal(h.position, 2);
  assert.equal(h.document.title, 'Second sites');
  assert.deepEqual(h.goCalls, [-1, 1]);
  pending.resolve(response('/sites', envelope('First sites'))); await tick();
  assert.equal(h.position, 2);
});
