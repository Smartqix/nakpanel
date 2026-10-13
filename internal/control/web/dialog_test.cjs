const test = require('node:test');
const assert = require('node:assert/strict');
const {createDialogController} = require('./static/interaction.js');

function fixture() {
  const events = [];
  const document = {activeElement: null, getElementById: id => dialogs[id]};
  const classes = new Set();
  document.body = {classList: {toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name)}};
  function control(tag, options = {}) {
    return Object.assign({tagName: tag, disabled: false, hidden: false, isConnected: true,
      focus() { document.activeElement = this; }, getClientRects: () => [{}],
      closest: () => null, matches: () => false}, options);
  }
  function dialog(id, controls) {
    const attributes = new Map();
    const listeners = {};
    const heading = {id: ''}, description = {id: ''};
    return {id, open: false, isConnected: true, heading, description,
      getAttribute: name => attributes.get(name) || null,
      setAttribute: (name, value) => attributes.set(name, value),
      querySelector(selector) {
        if (selector === '.np-dialog-head h2, h2') return heading;
        if (selector === '.np-dialog-head p') return description;
        if (selector === '[data-np-confirmation-cancel]') return controls.find(c => c.cancel) || null;
        return null;
      },
      querySelectorAll: () => controls,
      addEventListener: (name, listener) => { listeners[name] = listener; },
      showModal() { this.open = true; document.activeElement = controls[0]; },
      close() { this.open = false; events.push(() => listeners.close()); },
      cancel() { const event = {preventDefault() { this.prevented = true; }}; listeners.cancel(event); assert.ok(event.prevented); },
      focus() { document.activeElement = this; }
    };
  }
  const opener = control('BUTTON');
  const close = control('BUTTON', {matches: selector => selector.includes('data-np-dialog-close')});
  const disabled = control('INPUT', {disabled: true});
  const hidden = control('INPUT', {getClientRects: () => []});
  const input = control('INPUT');
  const textarea = control('TEXTAREA');
  const submit = control('BUTTON');
  const cancel = control('BUTTON', {cancel: true});
  const dialogs = {edit: dialog('edit', [close, disabled, hidden, input, textarea, submit]),
    confirm: dialog('confirm', [close, cancel, submit])};
  const closed = [];
  const controller = createDialogController({document, onClose: d => closed.push(d.id)});
  return {controller, document, classes, dialogs, opener, input, textarea, cancel, closed,
    drain: () => { while (events.length) events.shift()(); }};
}

test('creation dialogs focus the first visible enabled field, not the close button', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  assert.equal(f.document.activeElement, f.input);
});

test('dialogs derive an accessible title and description without replacing explicit names', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  assert.equal(f.dialogs.edit.getAttribute('aria-labelledby'), 'edit-title');
  assert.equal(f.dialogs.edit.getAttribute('aria-describedby'), 'edit-description');
  f.dialogs.confirm.setAttribute('aria-label', 'Explicit name');
  f.controller.open(f.dialogs.confirm, f.input);
  assert.equal(f.dialogs.confirm.getAttribute('aria-labelledby'), null);
});

test('nested confirmations prefer Cancel and restore the parent field without unlocking the page', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  f.textarea.focus();
  f.controller.open(f.dialogs.confirm, f.textarea);
  assert.equal(f.document.activeElement, f.cancel);
  f.controller.close(f.dialogs.confirm);
  f.drain();
  assert.equal(f.controller.top(), f.dialogs.edit);
  assert.equal(f.document.activeElement, f.textarea);
  assert.ok(f.classes.has('np-modal-open'));
  f.controller.close(f.dialogs.edit);
  f.drain();
  assert.equal(f.document.activeElement, f.opener);
  assert.ok(!f.classes.has('np-modal-open'));
  assert.deepEqual(f.closed, ['confirm', 'edit']);
});

test('native Escape cancellation follows the same focus restoration path', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  f.dialogs.edit.cancel();
  f.drain();
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.controller.top(), null);
});

test('a delayed close event cannot remove a reopened dialog', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  f.controller.close(f.dialogs.edit);
  f.controller.open(f.dialogs.edit, f.opener);
  f.drain();
  assert.equal(f.controller.top(), f.dialogs.edit);
  assert.ok(f.classes.has('np-modal-open'));
});

test('closing a lower dialog never steals focus from a nested confirmation', () => {
  const f = fixture();
  f.controller.open(f.dialogs.edit, f.opener);
  f.controller.open(f.dialogs.confirm, f.input);
  f.controller.close(f.dialogs.edit);
  f.drain();
  assert.equal(f.controller.top(), f.dialogs.confirm);
  assert.equal(f.document.activeElement, f.cancel);
  assert.ok(f.classes.has('np-modal-open'));
});
test('opening without an explicit trigger restores the previously focused control', () => {
  const f=fixture();f.opener.focus();
  f.controller.open(f.dialogs.edit);
  f.controller.close(f.dialogs.edit);f.drain();
  assert.equal(f.document.activeElement,f.opener);
});
