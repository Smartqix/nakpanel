const test = require('node:test');
const assert = require('node:assert/strict');
const nav = require('./navigation.js');
const current = 'https://panel.test/sites/7?tab=dns';
function anchor(href, attrs = {}, full = false) {
 return {getAttribute: name => name === 'href' ? href : attrs[name] ?? null,
 hasAttribute: name => Object.hasOwn(attrs, name), closest: () => full ? {} : null};
}
test('eligible links include relative, query, and same-origin routed links', () => {
 for (const href of ['/dashboard', '?tab=mail', '/subscriptions/20', '7?tab=php'])
  assert.equal(nav.linkEligible(anchor(href), {button:0}, current), true, href);
});
test('all browser-owned gestures, destinations and explicit opt-outs stay native', () => {
 for (const event of [{defaultPrevented:true}, {button:1}, {ctrlKey:true}, {metaKey:true}, {altKey:true}, {shiftKey:true}])
  assert.equal(nav.linkEligible(anchor('/dashboard'), event, current), false);
 for (const href of ['#zone', '/sites/7?tab=dns#zone', 'https://other.test/dashboard', 'mailto:admin@test', '/logout', '/login', '/login/2fa', '/assets/app.js', '/sites/7/files/download', '/logs/export', '/support/customers/88/dashboard', '/database-manager/grant/', '/webmail', '/terminal', '/tools-settings/terminal', '/databases/7/manager'])
  assert.equal(nav.linkEligible(anchor(href), {button:0}, current), false, href);
 for (const attrs of [{target:'_blank'}, {target:'frame'}, {target:''}, {download:''}, {'data-np-full-nav':''}])
  assert.equal(nav.linkEligible(anchor('/dashboard', attrs), {}, current), false);
 assert.equal(nav.linkEligible(anchor('/dashboard', {}, true), {}, current), false);
 assert.equal(nav.linkEligible(anchor('/dashboard', {target:'_self'}), {}, current), true);
});
test('late responses from aborted or superseded navigations are ignored', () => {
 const controller = new AbortController();
 assert.equal(nav.isCurrent(1, 1, controller.signal), true);
 assert.equal(nav.isCurrent(1, 2, controller.signal), false);
 controller.abort(); assert.equal(nav.isCurrent(1, 1, controller.signal), false);
});
test('fragment metadata and full-document requirements are parsed without a DOM', () => {
 const html = '<template data-np-shell="meta" data-title="Mail &amp; DNS" data-body-class="np-domain" data-route="site-detail"></template><template data-np-shell="sidebar"><aside>Side</aside></template><template data-np-shell="topbar"><header>Top</header></template><template data-np-shell="support"></template><div data-np-fragment="main"><h1>Mail</h1><div>Nested</div></div>';
 assert.deepEqual(nav.parseFragment(html), {title:'Mail & DNS', bodyClass:'np-domain', route:'site-detail', fullDocument:false, keepShell:false});
 for(const dialog of ['', '<dialog id="site-dialog"></dialog>'])assert.deepEqual(nav.parseFragment(html+'<template data-np-shell="site-dialog">'+dialog+'</template>'),nav.parseFragment(html));
 assert.equal(nav.parseFragment('<template data-np-shell="meta" data-full-document="true" data-title="Editor"></template>').fullDocument, true);
 assert.throws(() => nav.parseFragment('<html><title>Login</title></html>'), /fragment/i);
 assert.throws(() => nav.parseFragment('<template data-np-shell="meta"></template>'), /fragment/i);
});
test('lifecycle aborts element and nested region work, and permits a fresh mount', () => {
 const lifecycle=nav.createLifecycle(), child={contains:()=>false}, root={contains:el=>el===child};
 let mounts=0,unmounts=0;lifecycle.onMount(()=>mounts++);lifecycle.onUnmount(()=>unmounts++);
 lifecycle.mount(root);lifecycle.mount(child);const signal=lifecycle.signal(child);
 lifecycle.unmount(root);assert.equal(signal.aborted,true);assert.equal(lifecycle.signal(child),signal);assert.equal(unmounts,1);
 lifecycle.mount(child);assert.equal(lifecycle.signal(child).aborted,false);assert.equal(mounts,3);
});
const {createClient}=require('./interaction.js');
test('relative requests resolve against the current page after pushState', async () => {
 let base='https://panel.test/sites/7'; const urls=[];
 const client=createClient({baseURL:()=>base,fetch:async url=>{urls.push(url);return new Response('{}',{headers:{'Content-Type':'application/json'}});}});
 await client.fetch('?tab=dns');base='https://panel.test/subscriptions/20';await client.fetch('?tab=mail');
 assert.deepEqual(urls,['https://panel.test/sites/7?tab=dns','https://panel.test/subscriptions/20?tab=mail']);
});
const vm = require('node:vm');
const fs = require('node:fs');
function appHarness(withLifecycle = true) {
 const lifecycle = withLifecycle ? nav.createLifecycle() : undefined;
 const bindings = new Map(), intervals = new Map(), documentEvents={}, dialogs=new Map(), opened=[];let nextTimer=0;
 const form = {dataset:{}, hasAttribute:()=>false, querySelector:()=>null,
  addEventListener(type, listener) {if(!bindings.has(type))bindings.set(type,[]);bindings.get(type).push(listener);}};
 const progress = {};
 function scope() {return {querySelector:()=>null,querySelectorAll(selector) {
  if(selector==='[data-np-dirty-guard]')return [form];
  if(selector==='[data-np-wordpress-progress]')return [progress];
  return [];
 },contains:el=>el===form||el===progress};}
 const document = Object.assign(scope(),{getElementById:id=>dialogs.get(id),documentElement:{classList:{add(){}}},addEventListener(type,listener){(documentEvents[type] ||= []).push(listener);},hidden:false});
 const ui={lifecycle,createDialogController:()=>({prepare(){},unmount(){},prefill(dialog,trigger){opened.push(['prefill',dialog,trigger]);},open(dialog,trigger){opened.push(['open',dialog,trigger]);},top:()=>null}),fetch:async()=>{},setBusy(){}};
 const window={document,NakpanelUI:ui,fetch:async()=>{},addEventListener(){},location:{href:current,search:''},
  setTimeout:()=>++nextTimer,clearTimeout(){},setInterval:fn=>{const id=++nextTimer;intervals.set(id,fn);return id;},clearInterval:id=>intervals.delete(id)};
 vm.runInNewContext(fs.readFileSync(require.resolve('./app.js'),'utf8'), {window,document,URL,URLSearchParams,AbortController,WeakMap,Set});
 return {lifecycle,bindings,form,progress,root:scope(),intervals,documentEvents,dialogs,opened};
}
test('app mounts are idempotent and retain dirty state on repeated mounts', () => {
 const app=appHarness();assert.equal(app.bindings.get('input').length,1);
 app.bindings.get('input')[0]();assert.equal(app.form.dataset.npDirty,'true');
 app.lifecycle.mount(app.root);app.lifecycle.mount(app.root);
 assert.equal(app.bindings.get('input').length,1);
 assert.equal(app.form.dataset.npDirty,'true');
 assert.equal(app.intervals.size,1);
 app.lifecycle.unmount(app.root);assert.equal(app.intervals.size,0);
});
test('legacy documents without navigation still initialise once', () => {
 const app=appHarness(false);assert.equal(app.bindings.get('input').length,1);assert.equal(app.intervals.size,1);
});

test('dialog triggers prefill and open without instant navigation, preserving missing-dialog fallback and modified clicks',()=>{
 const h=appHarness(false), dialog={showModal(){},querySelector:()=>null,querySelectorAll:()=>[]};
 const trigger={dataset:{},disabled:false,getAttribute:()=> 'site-dialog',hasAttribute:()=>false,closest:selector=>selector==='[data-np-dialog-open]'?trigger:null,matches:()=>false};
 let prevented=false;
 const click=extra=>{h.documentEvents.click.forEach(listener=>listener({target:trigger,preventDefault(){prevented=true;},...extra}));};
 click({});assert.equal(prevented,false);assert.equal(h.opened.length,0);
 h.dialogs.set('site-dialog',dialog);
 click({ctrlKey:true});assert.equal(prevented,false);assert.equal(h.opened.length,0);
 click({});assert.equal(prevented,true);assert.deepEqual(h.opened.map(entry=>entry[0]),['prefill','open']);
 assert.equal(h.opened[0][1],dialog);assert.equal(h.opened[0][2],trigger);
});
test('shell dialog timers share the lifetime of the current main content', () => {
 const installLifecycle=require('../lifecycle_harness.cjs');
 const timers=new Map();let id=0;
 const main={contains:()=>false},dialog={closest:()=>null},element={closest:()=>dialog};
 const context=vm.createContext({document:{querySelector:()=>main},window:{setTimeout:fn=>{timers.set(++id,fn);return id;},clearTimeout:id=>timers.delete(id)},element});
 const lifecycle=installLifecycle(context);
 vm.runInContext('later(element, function () {}, 1000);',context);
 assert.equal(timers.size,1);lifecycle.unmount(main);assert.equal(timers.size,0);
});

test('HTML POST requests keep redirect semantics, CSRF and standalone error text',async()=>{
 const requests=[];
 const client=createClient({baseURL:current,csrf:()=> 'token',fetch:async(url,options)=>{requests.push(options);return new Response('<html><body>Invalid value</body></html>',{status:422,headers:{'Content-Type':'text/html'}});}});
 const response=await client.fetch('/save',{method:'POST',headers:{Accept:'text/html','X-Nakpanel-Fragment':'main'},allowPageResponse:true});
 assert.equal(response.status,422);assert.match(await response.text(),/Invalid value/);
 assert.equal(requests[0].headers.get('X-Nakpanel-CSRF'),'token');assert.equal(requests[0].headers.has('X-Nakpanel-SPA'),false);
 await assert.rejects(client.fetch('/page',{headers:{Accept:'text/html'},allowPageResponse:true}),/HTTP 422/);
});

const tick = () => new Promise(resolve => setImmediate(resolve));
function cacheHarness(connection) {
 let now = 0, count = 0, active = 0, peak = 0;
 const releases = [];
 const cache = nav.createPrefetchCache({now:()=>now, connection:()=>connection, fetch:async url=>{
  count++; active++; peak=Math.max(peak,active);
  await new Promise(resolve=>releases.push(resolve)); active--;
  return {url,clone(){return {...this};}};
 }});
 return {cache, releases, advance:ms=>{now+=ms;}, get count(){return count;},get peak(){return peak;}};
}
test('prefetch cache expires at 30 seconds and evicts the oldest of eight entries', async()=>{
 const h=cacheHarness();
 for(let i=0;i<9;i++){const work=h.cache.prefetch('https://panel.test/'+i);h.releases.shift()();await work;}
 assert.equal(h.cache.get('https://panel.test/0'),null);
 assert.equal(h.cache.get('https://panel.test/1').url,'https://panel.test/1');
 h.advance(29999);assert.ok(h.cache.get('https://panel.test/8'));
 h.advance(1);assert.equal(h.cache.get('https://panel.test/8'),null);
});
test('prefetch queues with at most two active requests and clear discards queued and late results', async()=>{
 const h=cacheHarness();const work=[0,1,2,3].map(i=>h.cache.prefetch('https://panel.test/'+i));
 assert.equal(h.count,2);h.releases.shift()();await tick();assert.equal(h.count,3);assert.equal(h.peak,2);
 h.cache.clear();while(h.releases.length)h.releases.shift()();await Promise.all(work);
 assert.equal(h.count,3);assert.equal(h.cache.get('https://panel.test/0'),null);
 assert.equal(h.cache.get('https://panel.test/2'),null);
});
test('prefetch skips saveData and notice query parameters', async()=>{
 const h=cacheHarness({saveData:true});await h.cache.prefetch('https://panel.test/dashboard');assert.equal(h.count,0);
 const normal=cacheHarness();await normal.cache.prefetch('https://panel.test/dashboard?notice=saved');assert.equal(normal.count,0);
});
test('optimistic active state restores exact prior states on failure or abort',()=>{
 function link(active,current){return {classList:{contains:()=>active,toggle:(_,value)=>{active=value;}},getAttribute:()=>current,setAttribute:(_,value)=>{current=value;},removeAttribute:()=>{current=null;},state:()=>[active,current]};}
 const old=link(true,'page'),next=link(false,null),other=link(false,'false');
 const restore=nav.optimisticActive([old,next,other],next);
 assert.deepEqual(old.state(),[false,null]);assert.deepEqual(next.state(),[true,'page']);
 restore();assert.deepEqual(old.state(),[true,'page']);assert.deepEqual(next.state(),[false,null]);assert.deepEqual(other.state(),[false,'false']);
});
test('GET form URL includes repeated values and the successful submitter',()=>{
 const entries=new FormData();entries.append('q','mail & DNS');entries.append('tag','a');entries.append('tag','b');entries.append('action','search');
 assert.equal(nav.formURL('/sites?old=1#list',entries,'https://panel.test/dashboard'),'https://panel.test/sites?q=mail+%26+DNS&tag=a&tag=b&action=search#list');
});
function form(attrs={}, region=true, files=[]) {
 return {method:'post',action:'https://panel.test/save',getAttribute:name=>attrs[name]??null,hasAttribute:name=>Object.hasOwn(attrs,name),closest:()=>region?{}:null,querySelectorAll:()=>files};
}
test('submit eligibility honours claimed events, region, method, targets, overrides and uploads',()=>{
 const current='https://panel.test/dashboard';assert.equal(nav.formEligible(form(),{},current),true);
 for(const f of [form({},false),form({method:'dialog'}),form({target:''}),form({'data-np-full-nav':''}),form({},true,[{files:[{}]}]),form({action:'https://elsewhere.test/save'}),form({action:'/logout'})])assert.equal(nav.formEligible(f,{},current),false);
 assert.equal(nav.formEligible(form(),{defaultPrevented:true},current),false);
 assert.equal(nav.formEligible(form(),{submitter:{hasAttribute:()=>true,getAttribute:()=>''}},current),false);
 assert.equal(nav.formEligible(form(),{submitter:{hasAttribute:()=>false,getAttribute:()=>null,dataset:{npConfirmBypass:'true'}}},current),true);
 assert.equal(nav.formEligible(form({},true,[{files:[]}]),{},current),true);
});
test('one-time fragments accept keep-shell without shell templates',()=>{
 const meta=nav.parseFragment('<template data-np-shell="meta" data-keep-shell="true" data-title="Secret"></template><div data-np-fragment="main"><pre>secret</pre></div>');
 assert.equal(meta.keepShell,true);assert.equal(meta.title,'Secret');
 assert.throws(()=>nav.parseFragment('<template data-np-shell="meta" data-keep-shell="true"></template>'),/fragment/i);
});

test('form bodies are encoded like a native submission', () => {
  const nav = require('./navigation.js');
  const file = { name: 'report.txt' };
  const params = nav.urlencoded([['plan_id', '4'], ['note', 'a & b'], ['upload', file]]);
  assert.equal(params.toString(), 'plan_id=4&note=a+%26+b&upload=report.txt');
  const form = (enctype) => ({ getAttribute: (name) => (name === 'enctype' ? enctype : null) });
  const button = (enctype) => ({ getAttribute: (name) => (name === 'formenctype' ? enctype : null) });
  assert.equal(nav.formEnctype(form(null), null), 'application/x-www-form-urlencoded');
  assert.equal(nav.formEnctype(form('multipart/form-data'), null), 'multipart/form-data');
  assert.equal(nav.formEnctype(form('multipart/form-data'), button('application/x-www-form-urlencoded')), 'application/x-www-form-urlencoded');
  assert.equal(nav.formEnctype(form('TEXT/PLAIN'), null), 'text/plain');
});
