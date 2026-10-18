const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {createDialogController} = require('./static/interaction.js');
const {createLifecycle, linkEligible} = require('./static/navigation.js');

test('drawer fallback mount promotes the selected dialog and its link opens without navigation', () => {
  const listeners = {}, attributes = new Map(), classes = new Set();
  const location = new URL('https://panel.test/subscriptions/42?tab=access&drawer=subscription-sftp-dialog-42');
  const document = {
    activeElement: null,
    documentElement: {classList: {add() {}}},
    body: {classList: {toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }}},
    querySelector: () => null,
    querySelectorAll: selector => selector === 'dialog[data-np-dialog]' ? [dialog] : [],
    getElementById: id => id === dialog.id ? dialog : null,
    addEventListener(name, listener) { (listeners[name] ||= []).push(listener); }
  };
  const field = {tagName: 'INPUT', disabled: false, hidden: false, isConnected: true,
    closest: () => null, matches: () => false, getClientRects: () => [{}],
    focus() { document.activeElement = this; }};
  const dialogListeners = {};
  const dialog = {
    id: 'subscription-sftp-dialog-42', open: true, modal: false, modalCalls: 0, isConnected: true,
    getAttribute: name => attributes.get(name) || null,
    setAttribute: (name, value) => attributes.set(name, value),
    removeAttribute(name) { attributes.delete(name); if (name === 'open') this.open = false; },
    closest: () => null,
    matches(selector) { return selector === ':modal' ? this.modal : selector === 'dialog[data-np-dialog]'; },
    querySelector: () => null,
    querySelectorAll: selector => selector.startsWith('a[href]') ? [field] : [],
    addEventListener(name, listener) { dialogListeners[name] = listener; },
    removeEventListener(name) { delete dialogListeners[name]; },
    showModal() { assert.equal(this.open, false, 'native showModal rejects an already-open nonmodal dialog'); this.open = this.modal = true; this.modalCalls++; },
    close() { this.open = this.modal = false; dialogListeners.close?.(); },
    focus() { document.activeElement = this; }
  };
  const anchor = {
    dataset: {}, isConnected: true,
    matches: () => false,
    getAttribute: name => ({'data-np-dialog-open': dialog.id, href: '/subscriptions/42?tab=access&drawer=subscription-sftp-dialog-42', target: null}[name] ?? null),
    hasAttribute: () => false,
    closest(selector) { return selector === '[data-np-dialog-open]' || selector === 'a[href]' ? this : null; },
    focus() { document.activeElement = this; }
  };
  const window = {document, location, addEventListener() {}, fetch() { throw new Error('drawer must not request a page'); },
    NakpanelUI: {createDialogController, lifecycle: createLifecycle()}};
  vm.runInNewContext(fs.readFileSync(__dirname + '/static/app.js', 'utf8'), {window, document, URL, URLSearchParams, AbortController});
  assert.equal(dialog.modal, true, 'the server-open fallback must become a native modal on mount');
  assert.equal(dialog.modalCalls, 1);
  assert.equal(document.activeElement, field);
  assert.equal(classes.has('np-modal-open'), true);
  window.NakpanelUI.dialogs.close(dialog);
  const event = {target: anchor, button: 0, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
  listeners.click.forEach(listener => listener(event));
  assert.equal(dialog.modalCalls, 2);
  assert.equal(event.defaultPrevented, true);
  assert.equal(linkEligible(anchor, event, location.href), false, 'navigation must leave the claimed drawer link alone');
});
