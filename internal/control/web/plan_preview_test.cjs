const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const installLifecycle = require('./lifecycle_harness.cjs');
const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function harness() {
  const forms = [], requests = [], previews = [], opened = [], submitted = [];
  const warning = {textContent:'', classList:{add(){}}}, confirm = {disabled:true};
  const root = {contains:element => forms.includes(element)};
  const document = {querySelectorAll:()=>[], getElementById:()=>({}), querySelector:selector => {
    if (selector === '[data-np-preview-warning]') return warning;
    if (selector === '[data-np-plan-confirm-submit]') return confirm;
    if (selector === '#main-content') return root;
    return null;
  }};
  const context = vm.createContext({document, AbortController, FormData:class {},
    each:()=>{}, csrfToken:()=> 'csrf', populatePlanPreview:preview=>previews.push(preview),
    openDialog:id=>opened.push(id), closeDialog:()=>{}, dialogs:{unmount(){}},
    fetch:(url, init)=>{ const response = deferred(); requests.push({url, init, response}); return response.promise; }});
  installLifecycle(context);
  const stateStart = source.indexOf('  var planSubmitBypass');
  const stateEnd = source.indexOf('  var confirmationResolver', stateStart);
  const previewStart = source.indexOf('  function clearPlanPreview(');
  const previewEnd = source.indexOf('  function selectedFilePaths(', previewStart);
  const unmountStart = source.indexOf('  if (lifecycle.onUnmount)');
  const unmountEnd = source.indexOf('  mount(document);', unmountStart);
  const confirmStart = source.indexOf('    if (event.target.closest("[data-np-plan-confirm-submit]")');
  const confirmEnd = source.indexOf('\n  });', confirmStart);
  const submitStart = source.indexOf('\tvar planEditorForm = event.target.closest');
  const submitEnd = source.indexOf('\tif (planEditorForm) planEditorForm.dataset', submitStart);
  assert.ok([stateStart, previewStart, unmountStart, confirmStart, submitStart].every(index=>index >= 0));
  vm.runInContext(source.slice(stateStart, stateEnd) + source.slice(previewStart, previewEnd) +
    source.slice(unmountStart, unmountEnd) +
    '\nfunction clickConfirm(event) {\n' + source.slice(confirmStart, confirmEnd) + '\n}\n' +
    '\nfunction submitPlan(event) {\n' + source.slice(submitStart, submitEnd) + '\n}', context);
  function form() {
    const button = {disabled:false};
    const element = {dataset:{npDirty:'true'}, isConnected:true, closest:()=>null,
      querySelector:()=>button, requestSubmit:()=>submitted.push(element)};
    forms.push(element);
    return {element, button};
  }
  async function settle(index, preview) {
    requests[index].response.resolve({ok:true, json:async()=>({ok:true, preview})});
    await new Promise(setImmediate);
  }
  return {context, form, requests, previews, opened, warning, submitted, settle,
    review:form=>context.reviewPlan(form.element),
    unmount:()=>context.testLifecycle.unmount(root),
    confirm:()=>context.clickConfirm({target:{closest:()=>({})}}),
    submit(form) {
      const event = {target:{closest:()=>form.element}, prevented:false, preventDefault(){this.prevented=true;}};
      context.submitPlan(event); return event;
    }};
}

test('plan preview requests share the form lifetime and cannot open after unmount', async () => {
  const h = harness(), form = h.form();
  h.review(form);
  assert.equal(h.requests[0].init.signal, h.context.testLifecycle.signal(form.element));
  h.unmount();
  assert.equal(h.requests[0].init.signal.aborted, true);
  await h.settle(0, {name:'removed plan'});
  assert.deepEqual(h.previews, []);
  assert.deepEqual(h.opened, []);
  assert.equal(form.button.disabled, true);
});

test('an unmounted preview failure cannot reopen the shell dialog or replace its warning', async () => {
  const h = harness(), form = h.form();
  h.review(form); h.unmount();
  h.requests[0].response.reject(new Error('late failure'));
  await new Promise(setImmediate);
  assert.deepEqual(h.opened, []);
  assert.equal(h.warning.textContent, '');
});

test('a superseded preview cannot display results or unlock the newer request', async () => {
  const h = harness(), form = h.form();
  h.review(form); h.review(form);
  await h.settle(0, {name:'old'});
  assert.deepEqual(h.previews, []);
  assert.deepEqual(h.opened, []);
  assert.equal(form.button.disabled, true);
  await h.settle(1, {name:'new'});
  assert.deepEqual(h.previews, [{name:'new'}]);
  assert.equal(h.opened.length, 1);
  assert.equal(form.button.disabled, false);
});

test('an older preview failure cannot overwrite a newer successful review', async () => {
  const h = harness(), form = h.form();
  h.review(form); h.review(form);
  await h.settle(1, {name:'new'});
  h.requests[0].response.reject(new Error('old failure'));
  await new Promise(setImmediate);
  assert.deepEqual(h.previews, [{name:'new'}]);
  assert.equal(h.opened.length, 1);
  assert.equal(h.warning.textContent, '');
});

test('an aborted preview does not show an error dialog', async () => {
  const h = harness(), form = h.form();
  h.review(form);
  h.requests[0].response.reject(Object.assign(new Error('aborted'), {name:'AbortError'}));
  await new Promise(setImmediate);
  assert.deepEqual(h.opened, []);
  assert.equal(h.warning.textContent, '');
});

test('unmount clears plan confirmation and its bypass before another page submits', async () => {
  const h = harness(), first = h.form();
  h.review(first); await h.settle(0, {allowed:true}); h.confirm();
  assert.equal(h.submitted.length, 1);
  h.unmount(); h.confirm();
  assert.equal(h.submitted.length, 1, 'the removed plan cannot be submitted again');
  const next = h.form();
  assert.equal(h.submit(next).prevented, true, 'the next plan still requires review');
  assert.equal(h.requests.length, 2);
});
