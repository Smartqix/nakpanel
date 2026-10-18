const test = require('node:test');
const assert = require('node:assert/strict');
const {getEventListeners} = require('node:events');
const fs = require('node:fs');
const vm = require('node:vm');
const {createLifecycle} = require('./static/navigation.js');

function harness(asset) {
  const lifecycle = createLifecycle(), window = new EventTarget(), timers = new Map();
  let timer = 0;
  const request = ()=>new Promise(()=>{});
  Object.assign(window, {NakpanelUI:{lifecycle, fetch:request},
    setTimeout:callback=>{timers.set(++timer, callback); return timer;},
    clearTimeout:id=>timers.delete(id)});
  const document = {readyState:'complete', querySelector:()=>null, querySelectorAll:()=>[]};
  const context = vm.createContext({window, document, AbortController, fetch:request});
  vm.runInContext(fs.readFileSync(__dirname + '/static/' + asset, 'utf8'), context);
  function scope() {
    const nodes = new Map();
    const panel = {dataset:{state:'pending', npDnsProgressUrl:'/dns/status'},
      getAttribute:name=>({'data-state':'queued', 'data-plan-id':'7', 'data-status-url':'/mail/status'})[name],
      querySelector:selector=>{ if (!nodes.has(selector)) nodes.set(selector, {addEventListener(){}, classList:{toggle(){}}, replaceChildren(){}}); return nodes.get(selector); }};
    const workspace = {querySelectorAll:selector=>selector==='[data-np-dns-progress-url]'?[panel]:[]};
    return {contains:element=>element===panel || element===workspace,
      querySelector:selector=>selector==='[data-np-dns-settings-workspace]'?workspace:null,
      querySelectorAll:selector=>['[data-np-mail-import-progress]', '[data-np-plan-sync]'].includes(selector)?[panel]:[]};
  }
  return {window, lifecycle, scope, timers};
}

for (const asset of ['mail-import.js', 'plan-sync.js', 'dns-template.js']) {
  test(asset + ' releases each pagehide handler when its page unmounts', () => {
    const h = harness(asset), baseline = getEventListeners(h.window, 'pagehide').length;
    for (let visit = 0; visit < 20; visit++) {
      const root = h.scope();
      h.lifecycle.mount(root);
      assert.equal(getEventListeners(h.window, 'pagehide').length, baseline + 1);
      h.lifecycle.unmount(root);
      assert.equal(getEventListeners(h.window, 'pagehide').length, baseline, 'visit ' + visit + ' retained a removed panel');
      assert.equal(h.timers.size, 0);
    }
  });
}
