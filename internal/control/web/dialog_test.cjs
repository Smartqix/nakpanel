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
      removeEventListener: name => { delete listeners[name]; },
      showModal() { this.open = true; document.activeElement = controls[0]; },
      close() { this.open = false; const listener = listeners.close; events.push(() => listener?.()); },
      cancel() { const event = {preventDefault() { this.prevented = true; }}; listeners.cancel(event); assert.ok(event.prevented); },
      focus() { document.activeElement = this; }
    };
  }
  const opener = control('BUTTON');
  const close = control('BUTTON', {matches: selector => selector === '[data-np-dialog-close], .np-dialog-close button'});
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

test('unmount closes nested dialogs, unlocks the page and allows preparation again', () => {
  const f = fixture(), root = {contains: dialog => Object.values(f.dialogs).includes(dialog), querySelectorAll: () => Object.values(f.dialogs)};
  f.controller.open(f.dialogs.edit, f.opener);
  f.controller.open(f.dialogs.confirm, f.input);
  f.controller.unmount(root);
  f.drain();
  assert.equal(f.controller.top(), null);
  assert.equal(f.dialogs.edit.open, false);
  assert.equal(f.dialogs.confirm.open, false);
  assert.equal(f.classes.has('np-modal-open'), false);
  f.controller.open(f.dialogs.edit, f.opener);
  f.dialogs.edit.cancel(); f.drain();
  assert.equal(f.controller.top(), null);
  assert.equal(f.document.activeElement, f.opener);
});

test('unmount also dismisses a shell confirmation opened from the removed drawer', () => {
  const f = fixture(), root = {contains: element => element === f.dialogs.edit || element === f.input, querySelectorAll: () => [f.dialogs.edit]};
  f.controller.open(f.dialogs.edit, f.opener);
  f.controller.open(f.dialogs.confirm, f.input);
  f.controller.unmount(root); f.drain();
  assert.equal(f.controller.top(), null);
  assert.equal(f.classes.has('np-modal-open'), false);
  assert.equal(f.dialogs.confirm.open, false);
});

test('prefill sets named fields and signals dependent controls, ignoring malformed data', () => {
  const f = fixture(), changes = [];
  const fields = [{name:'subscription_id', type:'select-one', value:'1'}, {name:'domain', type:'text', value:''}, {name:'enabled', type:'checkbox', value:'true', checked:false}];
  fields.forEach(field => { field.dispatchEvent = event => changes.push([field.name, event.type]); });
  const dialog = {querySelectorAll: () => fields};
  f.controller.prefill(dialog, {getAttribute: () => '{"subscription_id":"42","domain":"example.test","enabled":true}'});
  assert.equal(fields[0].value, '42'); assert.equal(fields[1].value, 'example.test'); assert.equal(fields[2].checked, true);
  assert.deepEqual(changes, [['subscription_id','change'],['domain','change'],['enabled','change']]);
  assert.doesNotThrow(() => f.controller.prefill(dialog, {getAttribute: () => '{bad'}));
});

for (const variant of ['np-drawer', 'np-mail-dialog']) test(variant + ' error recovery restores safe fields with fresh CSRF', () => {
  const f = fixture(), dialog = f.dialogs.edit;
  dialog.matches = selector => selector.split(',').some(part => part.trim() === 'dialog.' + variant);
  const fields = [
    {name:'name',type:'text',value:'entered'}, {name:'password',type:'password',value:'secret'},
    {name:'upload',type:'file',value:'private'}, {name:'csrf_token',type:'hidden',value:'old-csrf'},
    {name:'resource_id',type:'hidden',value:'12'}, {name:'enabled',type:'checkbox',value:'true',checked:false},
    {name:'destinations',type:'select-multiple',multiple:true,options:[{value:'a',selected:true},{value:'b',selected:false}]},
    {name:'environment',type:'textarea',value:'{"MODE":"production"}'},
    {name:'secrets',type:'textarea',value:'private-container-value'},
    {name:'relay_password',type:'text',value:'revealed-private-password'}
  ];
  const changed = [];
  fields.forEach(field => { field.dispatchEvent = event => {
    assert.equal(event.type, 'change'); assert.equal(fields[0].value, 'entered'); assert.equal(fields[5].checked, false);
    changed.push(field.name);
  }; });
  const form = {elements:fields, closest: selector => dialog.matches(selector) ? dialog : null};
  const snapshot = f.controller.capture(form);
  assert.ok(!JSON.stringify(snapshot).includes('secret')); assert.ok(!JSON.stringify(snapshot).includes('old-csrf'));
  assert.ok(!JSON.stringify(snapshot).includes('private-container-value'));
  assert.ok(!JSON.stringify(snapshot).includes('revealed-private-password'));
  // Shell drawers survive swaps, including their original sensitive controls.
  fields[0].value = ''; fields[3].value = 'fresh-csrf'; fields[4].value = ''; fields[5].checked = true;
  fields[6].options.forEach(option => { option.selected = !option.selected; }); fields[7].value='';
  const error = {setAttribute(){}, focus(){this.focused=true;}, cloneNode(){return {...this};}};
  const body = {prepend(node){this.error=node;}};
  const query = dialog.querySelector;
  dialog.querySelector = selector => selector === 'form[method="post"]' ? form : selector === '.np-drawer-body' ? body : query(selector);
  f.document.querySelectorAll = () => [];
  const main = {querySelector: () => error};
  assert.equal(f.controller.restore(snapshot, main), true);
  assert.equal(dialog.open, true); assert.equal(fields[0].value, 'entered'); assert.equal(fields[1].value, '');
  assert.equal(fields[2].value, ''); assert.equal(fields[3].value, 'fresh-csrf'); assert.equal(fields[4].value, '12'); assert.equal(fields[5].checked, false);
  assert.deepEqual(fields[6].options.map(option=>option.selected), [true,false]); assert.equal(body.error.focused, true);
  assert.equal(fields[7].value,'{"MODE":"production"}');assert.equal(fields[8].value,'');assert.equal(fields[9].value,'');
  assert.deepEqual(changed, ['name','enabled','destinations','environment']);
  f.controller.close(dialog);
  assert.equal(f.controller.restore(snapshot, {querySelector:()=>null}), false);
  delete f.dialogs.edit;
  assert.equal(f.controller.restore(snapshot, main), false);
});

test('collapsed impact details never receive invisible initial focus',()=>{
  const f=fixture();const summary={contains:()=>false};const closedDetails={querySelector:()=>summary};
  f.input.closest=selector=>selector==='details:not([open])'?closedDetails:null;
  f.controller.open(f.dialogs.edit,f.opener);
  assert.equal(f.document.activeElement,f.textarea);
});

test('review dialogs without fields prefer their Cancel action over committing a change', () => {
  const f = fixture();
  f.cancel.cancel = false;
  f.cancel.matches = selector => selector === '.np-dialog-actions [data-np-dialog-close]' || selector === '[data-np-dialog-close], .np-dialog-close button';
  f.controller.open(f.dialogs.confirm, f.opener);
  assert.equal(f.document.activeElement, f.cancel);
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
