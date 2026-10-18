const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require.resolve('./navigation.js'), 'utf8');
const initialURL = 'https://panel.test/dashboard';
const envelope = title => `<template data-np-shell="meta" data-title="${title}" data-body-class="np-app" data-route="sites"></template><template data-np-shell="sidebar"></template><template data-np-shell="topbar"></template><template data-np-shell="support"></template><div data-np-fragment="main"><h1>${title}</h1></div>`;
function response(title, url = 'https://panel.test/sites', headers = {}) {
 return {ok:true,status:200,url, clone(){return {...this};}, headers:{get:name=>headers[name] ?? (name==='Content-Type'?'text/html':null)},text:async()=>envelope(title)};
}
function deferred() {let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
function harness(enabled = true) {
 const windowEvents = {}, windowCapture = {}, documentEvents = {}, assignments = [], pushes = [], events = [], requests = [];
 let dirty = false, fullSource = false, time = 0, timerID = 0; const timers = new Map(), busy = [];
 class Node {
  constructor(name, children = []) {this.name=name;this.childNodes=children;this.dataset={};this.attributes=[];this.scrollTop=45;this.isConnected=true;this.classes=new Set();this.classList={add:(...names)=>names.forEach(name=>this.classes.add(name)),remove:(...names)=>names.forEach(name=>this.classes.delete(name)),contains:name=>this.classes.has(name),toggle:(name,value)=>value?this.classes.add(name):this.classes.delete(name)};}
  remove() {this.removed=true;if(this.parentElement)this.parentElement.childNodes=this.parentElement.childNodes.filter(child=>child!==this);}
  replaceWith(next) {const parent=this.parentElement;parent.childNodes[parent.childNodes.indexOf(this)]=next;next.parentElement=parent;this.removed=true;}
  before(node) {this.beforeNode=node;}
  contains(node) {return this.childNodes.some(child=>child===node||child.contains(node));}
  setAttribute(name,value) {this.removeAttribute(name);this.attributes.push({name,value});}
  removeAttribute(name) {this.attributes=this.attributes.filter(attr=>attr.name!==name);}
  hasAttribute(name) {return this.attributes.some(attr=>attr.name===name);}
  replaceChildren(...children) {this.childNodes=children;}
  append(...children) {this.childNodes.push(...children);children.forEach(child=>{child.parentElement=this;});}
  appendChild(child) {this.append(child);}
  prepend(child) {this.childNodes.unshift(child);}
  querySelector(selector) {
   if(selector==='.np-notice, [role="alert"], [role="status"]')return this.childNodes.find(child=>child.name==='notice');
   if(selector==='h1')return this.childNodes.find(child=>child.name==='h1');
   if(selector.includes('data-np-dirty-guard'))return dirty?{}:null;
   if(selector.includes('data-np-navigation-error'))return this.childNodes.find(child=>Object.hasOwn(child.dataset,'npNavigationError'));
   return null;
  }
  querySelectorAll() {return [];}
  addEventListener() {}
  reset() {}
  focus() {this.focused=true;}
 }
 const progress = new Node('progress');
 const main = new Node('main', [new Node('old')]), side = new Node('side'), top = new Node('top'), scrim={hidden:false}, dialog=new Node('dialog');
 const closed=[];
 const document = {title:'Old',body:Object.assign(new Node('body'),{dataset:{npNav:enabled?'on':undefined},className:'old'}),
  createElement:name=>new Node(name),createTextNode:text=>({text}),
  querySelector:selector=>selector==='#site-dialog'?document.body.childNodes.find(child=>child.name==='site-dialog')||null:({'#main-content':main,'.np-nav-progress':progress,'.np-routed-side':side,'.np-routed-top':top,'.np-v2-create':fullSource?{}:null,'[data-np-menu-close]':scrim}[selector]||null),
  querySelectorAll:selector=>selector==='dialog[open]'?[dialog]:[],addEventListener:(type,fn)=>{documentEvents[type]=fn;},dispatchEvent:event=>events.push(event)};
 const location = {href:initialURL,origin:'https://panel.test',assign:url=>assignments.push(url)};
 const history = {state:null,replaceState(state,_,url){this.state=state;location.href=new URL(url,location.href).href;},pushState(state,_,url){this.state=state;location.href=new URL(url,location.href).href;pushes.push(url);}};
 const ui = {setBusy:(form,value)=>busy.push(value),dialogs:{close:dialog=>closed.push(dialog)},fetch:async(url,options)=>{requests.push({url,options});return response('Sites');},confirm:async()=>true};
 const window = {navigator:{},setTimeout:(fn,delay)=>{timers.set(++timerID,{fn,at:time+delay});return timerID;},clearTimeout:id=>timers.delete(id),document,NakpanelUI:ui,location,history,scrollY:120,scrollTo:(_,y)=>{window.scrollY=y;},addEventListener:(type,fn,options)=>{(options===true?windowCapture:windowEvents)[type]=fn;}};
 class DOMParser {
  parseFromString(html) {
   const heading=new Node('h1');heading.textContent=html.match(/<h1>(.*?)<\/h1>/)?.[1];
   const fragment=new Node('fragment',[heading]);
   if(html.includes('notice-test'))fragment.childNodes.unshift(new Node('notice'));
   const templates={sidebar:{content:{firstElementChild:new Node('side',[new Node('updated-side')])}},topbar:{content:{firstElementChild:new Node('top',[new Node('updated-top')])}},support:{content:{firstElementChild:null}}};
   const shell=html.match(/<template data-np-shell="site-dialog">(.*?)<\/template>/s);
   if(shell)templates['site-dialog']={content:{firstElementChild:shell[1]?new Node('site-dialog',[new Node('fresh-form')]):null}};
   Object.entries(templates).forEach(([part,template])=>{template.getAttribute=()=>part;template.content.querySelectorAll=()=>[];});
   const messages=Array.from(html.matchAll(/<(h1|h2|p)\b[^>]*>(.*?)<\/\1>/gs),match=>({textContent:match[2].replace(/<[^>]+>/g,'')}));
   return {body:{textContent:'Fallback text',querySelectorAll:selector=>selector==='script, style'?[]:messages},querySelectorAll:selector=>selector==='noscript'?[]:Object.values(templates),querySelector:selector=>selector==='[data-np-fragment="main"]'?fragment:templates[selector.match(/"(.*?)"/)?.[1]]||null};
  }
 }
 class Fields extends FormData {constructor(form,submitter){super();for(const entry of form.entries||[])this.append(...entry);if(submitter&&submitter.name)this.append(submitter.name,submitter.value);}}
 vm.runInNewContext(source,{window,URL,URLSearchParams,FormData:Fields,AbortController,DOMParser,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}}});
 windowEvents.DOMContentLoaded?.();
 return {ui,main,progress,windowEvents,windowCapture,documentEvents,busy,timers,Node,advance(ms){time+=ms;for(const [id,timer] of [...timers])if(timer.at<=time){timers.delete(id);timer.fn();}},side,top,scrim,dialog,closed,document,window,history,location,assignments,pushes,events,requests,setDirty:value=>{dirty=value;},setFullSource:value=>{fullSource=value;},
  async pop(url,scrollY) {location.href=url;history.state={npNav:true,scrollY};windowEvents.popstate({state:history.state});await new Promise(resolve=>setImmediate(resolve));}};
}
test('navigation swaps content while retaining region roots and sidebar scroll', async () => {
 const h=harness();const old=h.main.childNodes[0];const signal=h.ui.lifecycle.signal(old);
 await h.ui.navigate('/sites');
 assert.equal(signal.aborted,true);assert.equal(h.main.childNodes[0].textContent,'Sites');
 assert.equal(h.side.scrollTop,45);assert.equal(h.document.title,'Sites');assert.equal(h.window.scrollY,0);
 assert.equal(h.location.href,'https://panel.test/sites');assert.equal(h.pushes.length,1);
 assert.equal(h.main.hasAttribute('aria-busy'),false);assert.equal(h.main.childNodes[0].focused,true);
 assert.equal(h.events[0].type,'nakpanel:navigated');assert.equal(h.events[0].detail.url,'https://panel.test/sites');
});
test('actual superseded fetch and body completions cannot overwrite the current page', async () => {
 const h=harness(), late=deferred();let calls=0;
 h.ui.fetch=async()=>++calls===1?late.promise:response('Latest','https://panel.test/subscriptions');
 const before=h.ui.navigate('/sites');await h.ui.navigate('/subscriptions');late.resolve(response('Late'));await before;
 assert.equal(h.document.title,'Latest');assert.equal(h.pushes.length,1);
 const text=deferred();h.ui.fetch=async()=>({...response('Late'),text:()=>text.promise});const body=h.ui.navigate('/sites');
 await new Promise(resolve=>setImmediate(resolve));h.ui.fetch=async()=>response('Newest');await h.ui.navigate('/sites');
 text.resolve(envelope('Late'));await body;assert.equal(h.document.title,'Newest');
});
test('dirty cancellation keeps the mounted page and restores a cancelled popstate URL', async () => {
 const h=harness();h.setDirty(true);const questions=[];h.ui.confirm=async message=>{questions.push(message);return false;};
 await h.ui.navigate('/sites');assert.equal(h.location.href,initialURL);assert.equal(h.main.childNodes[0].name,'old');
 await h.pop('https://panel.test/subscriptions',35);
 assert.equal(h.location.href,initialURL);assert.equal(h.main.childNodes[0].name,'old');
 assert.equal(questions.length,2);assert.match(questions[0],/Your changes will be lost/);
});
test('successful popstate restores saved scroll without adding a history entry', async () => {
 const h=harness();await h.ui.navigate('/sites');h.ui.fetch=async()=>response('Dashboard',initialURL);
 await h.pop(initialURL,185);assert.equal(h.window.scrollY,185);assert.equal(h.pushes.length,1);
});
test('superseding pending Back with a failed navigation restores the rendered URL and state',async()=>{
 const h=harness();await h.ui.navigate('/sites');const renderedState=h.history.state,back=deferred();let calls=0;
 h.ui.fetch=async()=>{if(++calls===1)return back.promise;throw new Error('offline');};
 await h.pop(initialURL,185);
 const next=h.ui.navigate('/subscriptions');await next;
 assert.equal(h.location.href,'https://panel.test/sites');assert.equal(h.history.state.npKey,renderedState.npKey);
 assert.equal(h.main.childNodes.at(-1).textContent,'Sites');
 back.resolve(response('Dashboard',initialURL));await new Promise(resolve=>setImmediate(resolve));
 assert.equal(h.location.href,'https://panel.test/sites');assert.equal(h.history.state.npKey,renderedState.npKey);
});
test('refresh replaces history and retains scroll', async () => {
 const h=harness();h.ui.fetch=async()=>response('Refreshed',initialURL);await h.ui.refresh();
 assert.equal(h.pushes.length,0);assert.equal(h.window.scrollY,120);assert.equal(h.document.title,'Refreshed');
});
test('failures retain existing content and offer recovery', async () => {
 const h=harness();h.ui.fetch=async()=>{throw new Error('offline');};await h.ui.navigate('/sites');
 assert.equal(h.main.childNodes[1].name,'old');const error=h.main.childNodes[0];
 assert.equal(error.childNodes[0].textContent,"Couldn't load this page.");
 assert.equal(error.childNodes[1].textContent,'Retry');assert.equal(error.childNodes[3].textContent,'Open normally');
 assert.equal(h.location.href,initialURL);assert.equal(h.main.hasAttribute('aria-busy'),false);
});
test('authentication, non-HTML and full-document responses navigate normally', async () => {
 for(const result of [Object.assign(new Error('login'),{status:401}),response('Sites',undefined,{'X-Nakpanel-Location':'/login'}),response('Sites',undefined,{'Content-Type':'application/pdf'}),{...response('Editor'),text:async()=>'<template data-np-shell="meta" data-full-document="true"></template>'}]) {
  const h=harness();h.ui.fetch=async()=>{if(result instanceof Error)throw result;return result;};await h.ui.navigate('/sites');
  assert.equal(h.assignments.length,1);assert.equal(h.main.childNodes[0].name,'old');
 }
});
test('disabled navigation leaves links, history and requests alone', () => {
 const h=harness(false);assert.equal(h.ui.navigate,undefined);assert.equal(h.ui.refresh,undefined);assert.equal(h.history.state,null);assert.equal(h.requests.length,0);
});

test('programmatic navigation respects standalone routes and restores the shell after Add Website', async () => {
 for (const path of ['/db', '/support/customers/88/dashboard', '/webmail', '/terminal']) {
  const h=harness();await h.ui.navigate(path);assert.equal(h.assignments.length,1);assert.equal(h.requests.length,0);
 }
 const h=harness();h.setFullSource(true);await h.ui.navigate('/dashboard');
 assert.equal(h.assignments.length,1);assert.equal(h.requests.length,0);
});
test('document navigation supersedes a pending fragment before it can commit',async()=>{
 const h=harness(),pending=deferred();h.ui.fetch=()=>pending.promise;
 const fragment=h.ui.navigate('/sites');await h.ui.navigate('/logout');
 pending.resolve(response('Stale sites'));await fragment;
 assert.deepEqual(h.assignments,['https://panel.test/logout']);assert.equal(h.document.title,'Old');
 assert.equal(h.location.href,initialURL);assert.equal(h.pushes.length,0);
});
test('full-document and non-HTML fallbacks honour dirty cancellation during popstate', async () => {
 for(const result of [{...response('Editor'),text:async()=>'<template data-np-shell="meta" data-full-document="true"></template>'},response('Export',undefined,{'Content-Type':'application/pdf'})]) {
  const h=harness();h.setDirty(true);h.ui.confirm=async()=>false;h.ui.fetch=async()=>result;
  await h.pop('https://panel.test/sites/7/files/edit',55);
  assert.equal(h.assignments.length,0);assert.equal(h.location.href,initialURL);assert.equal(h.main.childNodes[0].name,'old');
 }
});
test('a successful document handoff during Back keeps its destination in the address bar',async()=>{
 const h=harness();await h.ui.navigate('/sites');
 h.ui.fetch=async()=>({...response('Editor',initialURL),text:async()=>'<template data-np-shell="meta" data-full-document="true"></template>'});
 await h.pop(initialURL,25);
 assert.deepEqual(h.assignments,[initialURL]);assert.equal(h.location.href,initialURL);
});
test('requested fragment identifiers survive fragment fetches that omit the hash', async () => {
 const h=harness();h.ui.fetch=async()=>response('DNS','https://panel.test/tools-settings/dns?run=4');
 await h.ui.navigate('/tools-settings/dns?run=4#dns-sync');
 assert.equal(h.location.href,'https://panel.test/tools-settings/dns?run=4#dns-sync');
});

test('successful navigation dismisses the persistent mobile scrim and shell dialogs', async () => {
 const h=harness();assert.equal(h.scrim.hidden,false);await h.ui.navigate('/sites');
 assert.equal(h.scrim.hidden,true);assert.deepEqual(h.closed,[h.dialog]);
});
test('fragment commit replaces a stale Add Domain dialog and mounts a fresh form',async()=>{
 const h=harness(),stale=new h.Node('site-dialog'),form=new h.Node('form');form.hidden=true;form.dataset.npSubmitting='true';stale.appendChild(form);stale.open=true;h.document.body.appendChild(stale);
 const signal=h.ui.lifecycle.signal(stale),mounted=[];h.ui.lifecycle.onMount(root=>mounted.push(root));
 h.ui.lifecycle.onUnmount(root=>{if(root===stale)assert.ok(h.closed.includes(stale),'close before replacing');});
 h.ui.fetch=async()=>({...response('Sites'),text:async()=>envelope('Sites')+'<template data-np-shell="site-dialog"><dialog id="site-dialog"><form></form></dialog></template>'});
 await h.ui.navigate('/sites');const fresh=h.document.querySelector('#site-dialog');
 assert.notEqual(fresh,stale);assert.ok(fresh);assert.equal(signal.aborted,true);assert.ok(mounted.includes(fresh));
 assert.notEqual(fresh.childNodes[0].dataset.npSubmitting,'true');assert.notEqual(fresh.childNodes[0].hidden,true);
});
test('site-dialog shell template inserts, removes and preserves keep-shell dialogs',async()=>{
 const h=harness();
 const navigate=async(template,keep=false)=>{h.ui.fetch=async()=>({...response('Sites'),text:async()=>envelope('Sites').replace('data-np-shell="meta"','data-np-shell="meta"'+(keep?' data-keep-shell="true"':''))+template});await h.ui.navigate('/sites');};
 await navigate('<template data-np-shell="site-dialog"><dialog></dialog></template>');const dialog=h.document.querySelector('#site-dialog');assert.ok(dialog);
 await navigate('<template data-np-shell="site-dialog"></template>',true);assert.equal(h.document.querySelector('#site-dialog'),dialog);
 await navigate('<template data-np-shell="site-dialog"></template>');assert.equal(h.document.querySelector('#site-dialog'),null);
});


test('delayed feedback starts at 120 and 300 ms and is cleaned on failure', async()=>{
 const h=harness(),pending=deferred();h.ui.fetch=()=>pending.promise;
 const work=h.ui.navigate('/sites');h.advance(119);assert.equal(h.progress.classList.contains('is-pending'),false);
 h.advance(1);assert.equal(h.progress.classList.contains('is-pending'),true);
 h.advance(179);assert.equal(h.main.classList.contains('np-nav-loading'),false);
 h.advance(1);assert.equal(h.main.classList.contains('np-nav-loading'),true);
 pending.resolve(response('Sites'));await work;
 assert.equal(h.main.classList.contains('np-nav-loading'),false);assert.equal(h.progress.classList.contains('is-complete'),true);
 h.advance(200);assert.equal(h.progress.classList.contains('is-complete'),false);
 h.ui.fetch=async()=>{throw new Error('offline');};await h.ui.navigate('/sites');h.advance(1000);
 assert.equal(h.main.classList.contains('np-nav-loading'),false);assert.equal(h.progress.classList.contains('is-pending'),false);
});
test('fast navigation never shows skeleton and view transitions wrap only the swap', async()=>{
 const h=harness(),pending=deferred();let transitions=0;
 h.document.startViewTransition=fn=>{transitions++;return {updateCallbackDone:Promise.resolve().then(fn)};};
 h.ui.fetch=()=>pending.promise;const work=h.ui.navigate('/sites');assert.equal(transitions,0);
 pending.resolve(response('Sites'));await work;h.advance(500);assert.equal(transitions,1);assert.equal(h.main.classList.contains('np-nav-loading'),false);
 h.window.matchMedia=()=>({matches:true});await h.ui.navigate('/sites');assert.equal(transitions,1);
});
test('POST keep-shell swaps main with no history entry and restores busy state',async()=>{
 const h=harness(),oldSide=h.side.childNodes,oldTop=h.top.childNodes;
 const form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/rotate'}[name]??null);form.closest=()=>h.main;form.entries=[['name','value']];
 h.ui.fetch=async(url,options)=>{assert.equal(options.method,'POST');assert.equal(options.body.get('intent'),'rotate');assert.equal(options.headers.Accept,'text/html');return {...response('Secret',url),text:async()=>'<template data-np-shell="meta" data-keep-shell="true" data-title="Secret"></template><div data-np-fragment="main"><h1>Secret</h1></div>'};};
 let prevented=false;await h.windowEvents.submit({target:form,submitter:{name:'intent',value:'rotate',hasAttribute:()=>false,getAttribute:()=>null},preventDefault(){prevented=true;}});
 assert.equal(prevented,true);assert.equal(h.main.childNodes[0].textContent,'Secret');assert.equal(h.side.childNodes,oldSide);assert.equal(h.top.childNodes,oldTop);assert.equal(h.pushes.length,0);assert.equal(h.location.href,initialURL);assert.deepEqual(h.busy,[true,false]);
});

for (const fragment of [true, false]) test('drawer is closed before a '+(fragment?'fragment':'standalone')+' POST swap', async()=>{
 const h=harness(), form=new h.Node('form');
 form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
 h.ui.lifecycle.onUnmount(root=>{if(root===h.main)assert.deepEqual(h.closed,[h.dialog]);});
 h.ui.fetch=async()=>fragment?response('Saved'):({ok:true,status:200,url:initialURL,headers:{get:name=>name==='Content-Type'?'text/html':null},text:async()=>'<html>Saved</html>'});
 await h.windowEvents.submit({target:form,preventDefault(){}});
 assert.deepEqual(h.closed,[h.dialog]);
});

test('a drawer submission captures values before disabling and recovers only after mounting the response',async()=>{
 const h=harness(), form=new h.Node('form'), snapshot={id:'edit',fields:[]};let mounted=false, restored=false;
 form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
 h.ui.dialogs.capture=source=>{assert.equal(source,form);assert.equal(h.busy.length,0);return snapshot;};
 h.ui.dialogs.restore=(values,main)=>{assert.equal(values,snapshot);assert.equal(main,h.main);assert.equal(mounted,true);restored=true;return true;};
 h.ui.lifecycle.onMount(root=>{if(root===h.main)mounted=true;});
 await h.windowEvents.submit({target:form,preventDefault(){}});
 assert.equal(restored,true);assert.equal(h.main.childNodes[0].focused,undefined);
});
test('POST failures preserve values and never offer an automatic POST retry',async()=>{
 const h=harness();const form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;form.entries=[['name','kept']];
 let calls=0;h.ui.fetch=async()=>{calls++;throw new Error('offline');};
 await h.windowEvents.submit({target:form,preventDefault(){}});
 assert.equal(calls,1);assert.equal(form.entries[0][1],'kept');assert.match(form.beforeNode.childNodes[0].textContent,/could not finish/i);assert.equal(form.beforeNode.childNodes.some(node=>node.name==='button'),false);assert.deepEqual(h.busy,[true,false]);
});
test('failed HTML POST preserves the mounted form, values, dirty guard and history',async()=>{
 for(const html of ['<main><h1> File changed </h1><p> Reload before saving. </p></main>',envelope('File changed')]) {
  const h=harness(),form=new h.Node('form');
  form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
  form.setAttribute('data-np-dirty-guard','');form.dataset.npDirty='false';form.entries=[['contents','unsaved edits']];
  h.main.appendChild(form);const old=h.main.childNodes.slice(),signal=h.ui.lifecycle.signal(h.main);
  h.ui.fetch=async()=>({...response('Conflict'),ok:false,status:409,redirected:true,text:async()=>html});
  await h.windowEvents.submit({target:form,preventDefault(){}});
  assert.deepEqual(h.main.childNodes,old);assert.equal(signal.aborted,false);assert.equal(form.entries[0][1],'unsaved edits');
  assert.equal(form.dataset.npDirty,'true');assert.match(form.beforeNode.childNodes[0].textContent,/File changed/);
  assert.equal(h.pushes.length,0);assert.equal(h.location.href,initialURL);assert.deepEqual(h.busy,[true,false]);
 }
});
test('failed POST messages are readable, bounded and have an HTTP fallback',async()=>{
 for(const [html,expected] of [['<h1> Failed </h1><p>  Try\n again. </p><script>secret()</script>','Failed Try again.'],['<p>'+ 'x'.repeat(500)+'</p>','x'.repeat(300)],['<html></html>','The action failed (HTTP 422)']]) {
  const h=harness(),form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
  h.ui.fetch=async()=>({...response('Invalid'),ok:false,status:422,text:async()=>html});
  await h.windowEvents.submit({target:form,preventDefault(){}});
  assert.equal(form.beforeNode?.childNodes[0].textContent,expected);
 }
});
test('plain-text POST failure keeps its HTTP fallback through the shared client',async()=>{
 const h=harness(),form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
 h.ui.fetch=require('./interaction.js').createClient({baseURL:initialURL,fetch:async()=>new Response('Forbidden',{status:403,headers:{'Content-Type':'text/plain'}})}).fetch;
 await h.windowEvents.submit({target:form,preventDefault(){}});
 assert.equal(form.beforeNode.childNodes[0].textContent,'The action failed (HTTP 403)');
 assert.equal(h.main.childNodes[0].name,'old');assert.equal(h.pushes.length,0);
});
test('document-only pages submit forms natively',async()=>{
 const h=harness(),form=new h.Node('form');h.document.body.setAttribute('data-np-document-only','');
 form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
 let prevented=false;await h.windowEvents.submit({target:form,preventDefault(){prevented=true;}});
 assert.equal(prevented,false);assert.equal(h.requests.length,0);assert.equal(h.busy.length,0);
});
test('leaving a document-only page restores instant form submission on the destination',async()=>{
 const h=harness();h.document.body.setAttribute('data-np-document-only','');await h.ui.navigate('/sites');
 const form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
 let prevented=false;await h.windowEvents.submit({target:form,preventDefault(){prevented=true;}});
 assert.equal(prevented,true);assert.equal(h.document.body.hasAttribute('data-np-document-only'),false);
 assert.equal(h.requests.at(-1).options.method,'POST');
});
test('prefetch intent uses cached responses and submit, errors and refresh invalidate them',async()=>{
 for(const invalidation of ['submit','error','refresh']) {
  const h=harness();let calls=0;h.ui.fetch=async(url,options)=>{calls++;if(calls===1){assert.equal(options.headers['X-Nakpanel-Fragment'],'main');assert.equal(options.headers['Sec-Purpose'],'prefetch');assert.equal(options.headers.Purpose,'prefetch');}return response('Sites',url);};
  const anchor={href:'https://panel.test/sites',getAttribute:name=>name==='href'?'/sites':null,hasAttribute:()=>false,closest:selector=>selector==='a[href]'?anchor:null};
  h.documentEvents.pointerenter({target:anchor});h.advance(64);assert.equal(calls,0);h.advance(1);await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
  await h.ui.navigate('/sites');assert.equal(calls,1);
  if(invalidation==='submit')await h.windowEvents.submit({target:{closest:()=>null}});
  if(invalidation==='error'){h.ui.fetch=async()=>{calls++;throw new Error('offline');};await h.ui.navigate('/other');}
  if(invalidation==='refresh')await h.ui.refresh();
  h.ui.fetch=async url=>{calls++;return response('Sites',url);};const before=calls;await h.ui.navigate('/sites');assert.equal(calls,before+1,invalidation);
 }
});
test('leaving intent before 65 ms cancels the prefetch',()=>{
 const h=harness();const anchor={href:'https://panel.test/sites',getAttribute:name=>name==='href'?'/sites':null,hasAttribute:()=>false,closest:selector=>selector==='a[href]'?anchor:null};
 h.documentEvents.pointerenter({target:anchor});h.advance(64);h.documentEvents.pointerleave({target:anchor});h.advance(100);assert.equal(h.requests.length,0);
});

test('a late aborted navigation cannot roll back a newer optimistic tab',async()=>{
 const h=harness(),first=deferred(),second=deferred();let calls=0;
 h.ui.fetch=()=>++calls===1?first.promise:second.promise;
 function link(active) {const node=new h.Node('a');if(active)node.classList.add('is-active');node.getAttribute=name=>name==='aria-current'?node.aria??null:null;node.setAttribute=(_,value)=>{node.aria=value;};node.removeAttribute=()=>{node.aria=null;};node.closest=()=>bar;return node;}
 const old=link(true),a=link(false),b=link(false),bar={querySelectorAll:()=>[old,a,b]};
 const one=h.ui.navigate('/sites',{anchor:a});const two=h.ui.navigate('/subscriptions',{anchor:b});
 assert.equal(b.classList.contains('is-active'),true);
 first.resolve(response('Late'));await one;assert.equal(b.classList.contains('is-active'),true);
 second.resolve(response('Latest'));await two;
});
test('POST non-HTML, fallback HTML, and auth never replay the mutation',async()=>{
 for(const mode of ['file','html','auth']) {
  const h=harness();const form=new h.Node('form');form.getAttribute=name=>({method:'post',action:'/save'}[name]??null);form.closest=()=>h.main;
  let calls=0;h.ui.fetch=async()=>{calls++;if(mode==='auth')throw Object.assign(new Error('expired'),{status:401,location:'/login?next=page'});return {...response('Legacy'),redirected:true,text:async()=>'<html><body><p>Fallback text</p><script>bad()</script></body></html>',headers:{get:name=>name==='Content-Type'?(mode==='file'?'application/octet-stream':'text/html'):null}};};
  await h.windowEvents.submit({target:form,preventDefault(){}});assert.equal(calls,1);
  if(mode==='file'){assert.match(form.beforeNode.childNodes[1].textContent,/repeat this action normally/);assert.equal(h.assignments.length,0);}
  if(mode==='html'){assert.equal(h.main.childNodes[0].textContent,'Fallback text');assert.equal(h.assignments.length,0);assert.equal(h.location.href,'https://panel.test/sites');}
  if(mode==='auth')assert.deepEqual(h.assignments,['/login?next=page']);
 }
});

test('same-path tab skeleton leaves tabs visible and abort immediately restores its body',async()=>{
 const h=harness(),pending=deferred(),scope=new h.Node('scope');let calls=0;
 const select=h.main.querySelector.bind(h.main);h.main.querySelector=selector=>selector==='[data-np-nav-scope-body]'?scope:select(selector);
 h.ui.fetch=()=>++calls===1?pending.promise:Promise.resolve(response('Sites'));
 const first=h.ui.navigate('/dashboard?tab=mail');h.advance(300);
 assert.equal(scope.classList.contains('np-nav-loading'),true);assert.equal(h.main.classList.contains('np-nav-loading'),false);assert.equal(scope.inert,true);
 const next=h.ui.navigate('/sites');assert.equal(scope.classList.contains('np-nav-loading'),false);assert.equal(scope.inert,undefined);await next;
 pending.resolve(response('Late'));await first;assert.equal(h.document.title,'Sites');
});
test('GET and confirmed POST submissions include submitter and POST blocks double submission',async()=>{
 const h=harness();const form=new h.Node('form');let method='get',calls=0;
 form.entries=[['q','find me']];form.getAttribute=name=>name==='method'?method:name==='action'?'/search-results':null;form.closest=()=>h.main;
 const submitter={name:'action',value:'find',hasAttribute:()=>false,getAttribute:()=>null,dataset:{npConfirmBypass:'true'}};
 h.ui.fetch=async url=>{calls++;assert.equal(url,'https://panel.test/search-results?q=find+me&action=find');return response('Found',url);};
 await h.windowEvents.submit({target:form,submitter,preventDefault(){}});assert.equal(calls,1);
 method='post';const pending=deferred();h.ui.fetch=async()=>{calls++;return pending.promise;};
 const one=h.windowEvents.submit({target:form,submitter,preventDefault(){}});await h.windowEvents.submit({target:form,submitter,preventDefault(){}});assert.equal(calls,2);
 pending.resolve({...response('Saved','https://panel.test/sites?notice=saved'),redirected:true,text:async()=>envelope('notice-test')});await one;
 assert.equal(h.location.href,'https://panel.test/sites?notice=saved');assert.equal(h.main.childNodes[0].name,'notice');assert.equal(h.main.childNodes[0].focused,true);
});
test('capture invalidates prefetch even if a feature stops propagation at its form',async()=>{
 const h=harness();let calls=0;h.ui.fetch=async url=>{calls++;return response('Sites',url);};
 const anchor={href:'https://panel.test/sites',getAttribute:name=>name==='href'?'/sites':null,hasAttribute:()=>false,closest:selector=>selector==='a[href]'?anchor:null};
 h.documentEvents.pointerenter({target:anchor});h.advance(65);await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
 h.windowCapture.submit({target:{}});await h.ui.navigate('/sites');assert.equal(calls,2);
});

test('refresh invalidates cached intent immediately while its request is pending',async()=>{
 const h=harness(),pending=deferred();let calls=0;
 h.ui.fetch=async url=>{calls++;return response('Sites',url);};
 const anchor={href:'https://panel.test/sites',getAttribute:name=>name==='href'?'/sites':null,hasAttribute:()=>false,closest:selector=>selector==='a[href]'?anchor:null};
 h.documentEvents.pointerenter({target:anchor});h.advance(65);await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
 h.ui.fetch=async url=>{calls++;return calls===2?pending.promise:response('Fresh',url);};
 const refresh=h.ui.refresh();await h.ui.navigate('/sites');assert.equal(calls,3);
 pending.resolve(response('Old refresh'));await refresh;
});
test('optimistic tab selection also clears and restores an active More summary',async()=>{
 const h=harness(),pending=deferred();h.ui.fetch=()=>pending.promise;
 const summary=new h.Node('summary'),clicked=new h.Node('a');summary.classList.add('is-active');
 summary.getAttribute=()=>null;clicked.getAttribute=()=>null;
 const bar={querySelectorAll:selector=>selector.includes('summary')?[summary,clicked]:[clicked]};clicked.closest=()=>bar;
 const work=h.ui.navigate('/sites',{anchor:clicked});assert.equal(clicked.classList.contains('is-active'),true);assert.equal(summary.classList.contains('is-active'),false);
 pending.resolve({...response('Invalid'),text:async()=>''});await work;
 assert.equal(summary.classList.contains('is-active'),true);assert.equal(clicked.classList.contains('is-active'),false);
});
