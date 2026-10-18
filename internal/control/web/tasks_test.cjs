const test = require('node:test');
const assert = require('node:assert/strict');
const {createTaskPoller} = require('./static/tasks.js');
const flush = () => new Promise(resolve => setImmediate(resolve));
function harness(seed = {active:0, items:[]}) {
  const timers = new Map(), toasts = [], renders = [], responses = [];
  let id = 0, hidden = false, calls = 0;
  const controller = createTaskPoller({
    setTimeout:(fn, delay) => { timers.set(++id, {fn, delay}); return id; },
    clearTimeout:id => timers.delete(id), hidden:() => hidden,
    render:(data, open) => renders.push({data, open}), toast:item => toasts.push(item),
    fetch:async signal => { calls++; const next = responses.shift() || seed; if (next instanceof Error) throw next; if (typeof next === 'function') return next(signal); return next; }
  });
  async function tick() { assert.equal(timers.size, 1); const [id, timer] = [...timers][0]; timers.delete(id); await timer.fn(); }
  return {controller, timers, toasts, renders, responses, tick, start:async()=>{controller.start(seed); await flush();}, hide:()=>{hidden=true;controller.visibility();}, show:()=>{hidden=false;controller.visibility();}, get calls(){return calls;}, get delay(){return [...timers.values()][0]?.delay;}};
}
test('task cadence is idle 30s, open/active 4s, and paused while hidden', async()=>{
  const h=harness();await h.start();assert.equal(h.delay,30000);
  h.controller.setOpen(true);await flush();assert.equal(h.delay,4000);
  h.controller.setOpen(false);assert.equal(h.delay,30000);
  h.responses.push({active:1,items:[{id:1,state:'scheduled',label:'Create site'}]});await h.tick();assert.equal(h.delay,4000);
  const calls=h.calls;h.hide();assert.equal(h.timers.size,0);assert.equal(h.calls,calls);
  h.show();await flush();assert.equal(h.calls,calls+1);assert.equal(h.delay,30000);
});
test('errors back off exponentially to 60s and success resets cadence',async()=>{
  const h=harness();for(let i=0;i<7;i++)h.responses.push(new Error('offline'));
  await h.start();assert.equal(h.delay,8000);
  for(const delay of [16000,32000,60000,60000,60000,60000]){await h.tick();assert.equal(h.delay,delay);}
  await h.tick();assert.equal(h.delay,30000);
});
test('active to terminal transitions toast once; initial and unseen terminals do not',async()=>{
  const h=harness({active:2,items:[{id:1,state:'running',label:'Create site'},{id:2,state:'retryable',label:'Issue cert'}]});
  await h.start();assert.equal(h.toasts.length,0);
  const final={active:0,items:[{id:1,state:'completed',label:'Create site'},{id:2,state:'discarded',label:'Issue cert'},{id:3,state:'failed',label:'Old failure'}]};
  h.responses.push(final,final);await h.tick();assert.deepEqual(h.toasts,final.items.slice(0,2));assert.equal(h.delay,30000);
  await h.tick();assert.equal(h.toasts.length,2);
});
test('topbar remounts retain state and a single timer/request',async()=>{
  const h=harness({active:1,items:[{id:1,state:'running',label:'Create site'}]});await h.start();
  h.controller.setOpen(true);await flush();const calls=h.calls;
  for(let i=0;i<20;i++){h.controller.mount();h.controller.start({active:0,items:[]});}
  assert.equal(h.calls,calls);assert.equal(h.timers.size,1);assert.equal(h.renders.at(-1).open,true);assert.equal(h.renders.at(-1).data.active,1);
  h.responses.push({active:0,items:[{id:1,state:'completed',label:'Create site'}]});await h.tick();assert.equal(h.toasts.length,1);
});
test('hiding aborts in-flight polling and ignores its late result',async()=>{
  const h=harness();let complete,signal;
  h.responses.push(s=>{signal=s;return new Promise(resolve=>{complete=resolve;});});
  h.controller.start();assert.equal(h.calls,1);h.hide();assert.equal(signal.aborted,true);
  complete({active:1,items:[]});await flush();assert.equal(h.timers.size,0);assert.equal(h.toasts.length,0);
  h.show();await flush();assert.equal(h.calls,2);assert.equal(h.delay,30000);
});
test('hidden initial document never polls until visible',async()=>{
 const h=harness();h.hide();await h.start();assert.equal(h.calls,0);assert.equal(h.timers.size,0);h.show();await flush();assert.equal(h.calls,1);
});

test('DOM tray rebinds after swaps, Escape restores focus, and completion offers explicit Refresh',async()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const {createLifecycle}=require('./static/navigation.js');
 const listeners={},timers=new Map(),lifecycle=createLifecycle();let seq=0,calls=0,refreshes=0,reloads=0;
 class Element {
  constructor(tag){this.tagName=tag;this.children=[];this.dataset={};this.attrs={};this.handlers={};this.className='';this.textContent='';}
  setAttribute(k,v){this.attrs[k]=v;}getAttribute(k){return this.attrs[k]??null;}
  append(...nodes){nodes.forEach(n=>this.appendChild(n));}appendChild(n){this.children.push(n);n.parent=this;return n;}
  replaceChildren(...nodes){this.children=[];this.append(...nodes);}remove(){this.parent.children=this.parent.children.filter(n=>n!==this);}
  addEventListener(type,fn){this.handlers[type]=fn;}focus(){this.focused=true;}
  contains(target){return this===target||this.children.some(n=>n.contains(target));}
  get firstElementChild(){return this.children[0];}
 }
 function newTray(){const root=new Element('div');root.parts={};for(const selector of ['[data-np-tasks-toggle]','[data-np-tasks-count]','#np-tasks-panel','[data-np-tasks-items]','[data-np-tasks-error]'])root.parts[selector]=root.appendChild(new Element('div'));root.parts['[data-np-tasks-count]'].textContent='0';root.querySelector=s=>root.parts[s];root.querySelectorAll=()=>[];return root;}
 let root=newTray(),payload={active:1,items:[{id:1,state:'running',tone:'run',label:'Create site',target:'owned.test',created_at:'2026-10-18T10:00:00Z',error:''}]};
 const body=new Element('body');
 const document={body,hidden:false,createElement:tag=>new Element(tag),querySelector:s=>s==='[data-np-tasks]'?root:body.children.find(n=>Object.hasOwn(n.dataset,'npTaskToasts')),addEventListener:(type,fn)=>{listeners[type]=fn;}};
 const ui={lifecycle,refresh:()=>{refreshes++;},fetch:async()=>{calls++;return {ok:true,json:async()=>payload};}};
 const window={document,NakpanelUI:ui,setTimeout:(fn,delay)=>{timers.set(++seq,{fn,delay});return seq;},clearTimeout:id=>timers.delete(id),location:{reload:()=>{reloads++;}}};
 vm.runInNewContext(fs.readFileSync(require.resolve('./static/tasks.js'),'utf8'),{window,AbortController,Date,Map,Number});await flush();
 listeners.click({target:root.parts['[data-np-tasks-toggle]']});await flush();assert.equal(root.parts['#np-tasks-panel'].focused,true);
 const before=calls;root=newTray();for(let i=0;i<10;i++)lifecycle.mount(root);assert.equal(calls,before);assert.equal(timers.size,1);assert.equal(root.parts['[data-np-tasks-toggle]'].getAttribute('aria-expanded'),'true');
 listeners.keydown({key:'Escape',preventDefault(){}});assert.equal(root.parts['[data-np-tasks-toggle]'].focused,true);assert.equal(root.parts['[data-np-tasks-toggle]'].getAttribute('aria-expanded'),'false');
 payload={active:0,items:[{...payload.items[0],state:'completed',tone:'ok'}]};const [id,timer]=[...timers][0];timers.delete(id);await timer.fn();
 const toast=body.children[0].children[0];assert.equal(toast.getAttribute('role'),'status');assert.equal(toast.children[0].textContent,'Finished: Create site');assert.equal(refreshes,0);assert.equal(reloads,0);
 toast.children[1].handlers.click();assert.equal(refreshes,1);assert.equal(reloads,0);
});

test('tray wording matches the server relative labels', () => {
  const { relative } = require('./static/tasks.js');
  const now = Date.parse('2026-10-12T12:00:00Z');
  const ago = (ms) => new Date(now - ms).toISOString();
  assert.equal(relative(ago(30e3), now), 'just now');
  assert.equal(relative(ago(70e3), now), 'a minute ago');
  assert.equal(relative(ago(5 * 60e3), now), '5 minutes ago');
  assert.equal(relative(ago(60 * 60e3), now), 'an hour ago');
  assert.equal(relative(ago(5 * 3600e3), now), '5 hours ago');
  assert.equal(relative(ago(30 * 3600e3), now), 'yesterday');
  assert.equal(relative(ago(3 * 86400e3), now), '3 days ago');
});
