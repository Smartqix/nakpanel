const installLifecycle = require('./lifecycle_harness.cjs');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');

function harness(responses, options = {}) {
  const start = source.indexOf('  function renderSiteSetupProgress(');
  const end = source.indexOf('\n  function submitSite(', start);
  assert(start >= 0 && end > start, 'shared setup tracker exists');
  const nodes = {};
  const node = selector => nodes[selector] ||= {dataset:{},hidden:false,textContent:'',setAttribute(){},focus(){}};
  let closed = false, now = 0, sequence = 0;
  const timers = new Map(), requests = [], navigations = [];
  const dialog = {closest:()=>null,open:true,addEventListener(name,fn){if(name === 'close') this.close = fn;},removeEventListener(name,fn){if(this.close===fn)this.close=null;},querySelector:node,querySelectorAll:()=>[panel]};
  const panel = {dataset:{},isConnected:true,closest:()=>options.page ? null : dialog,querySelector:node,setAttribute(){},hasAttribute:()=>false};
  const context = vm.createContext({URL,AbortController,Date:{now:()=>now},document:{hidden:false,querySelector:()=>options.dirty ? {} : null},window:{location:{href:'https://panel.test/sites/1',origin:'https://panel.test',assign:url=>navigations.push(url)},setTimeout:(fn,delay)=>{timers.set(++sequence,{fn,delay});return sequence;},clearTimeout:id=>timers.delete(id),fetch:async (url,init)=>{requests.push({url,init});const response=responses.shift();if(response instanceof Error) throw response;return {ok:true,status:200,redirected:false,json:async()=>response,...response};}}});
  installLifecycle(context);
  context.window.NakpanelUI={lifecycle:context.testLifecycle};
  if(options.instantNav!==false)context.window.NakpanelUI.navigate=url=>navigations.push(url);
  vm.runInContext(source.slice(start,end),context);
  const data={site_id:7,status_url:'/sites/7/setup/status',redirect:'/sites/7?tab=overview',setup_url:'/sites/7/setup'};
  const begin=()=>context.trackSiteSetup(panel,data);
  async function tick(){const entry=[...timers].find(([,timer])=>timer.delay<10000);assert(entry,'status timer scheduled');timers.delete(entry[0]);await entry[1].fn();}
  return {unmount:()=>context.testLifecycle.unmount(panel),init:()=>context.initSiteSetupProgress(dialog),begin,tick,panel,requests,navigations,nodes,timers,dialog,data,setTime:value=>{now=value;},close:()=>{closed=true;dialog.open=false;dialog.close?.();},get closed(){return closed;}};
}

test('queued setup waits and redirects only to the ready child',async()=>{
  const h=harness([{ok:true,site_id:7,state:'pending',message:'Applying DNS',steps:[]},{ok:true,site_id:7,state:'ready',message:'Created',steps:[],redirect:'/sites/7?tab=overview'}]);
  h.begin();assert.equal(h.navigations.length,0);await h.tick();assert.equal(h.navigations.length,0);await h.tick();assert.equal(new URL(h.navigations[0]).pathname,'/sites/7');assert(h.requests.every(r=>r.init.method==='GET'));
});
test('starting recovery immediately hides the previous retry action',()=>{
 const h=harness([]);h.nodes['[data-np-setup-retry]']={hidden:false};h.begin();assert.equal(h.nodes['[data-np-setup-retry]'].hidden,true);
});
for(const state of ['failed','attention']) test(`${state} setup stops without redirect or resubmission`,async()=>{
  const h=harness([{ok:true,site_id:7,state,message:'Review this step',steps:[]}]);h.begin();await h.tick();assert.equal(h.panel.dataset.npSetupState,state);assert.equal(h.navigations.length,0);assert.equal(h.requests.length,1);assert.equal(h.timers.size,0);
});
test('temporary status failure retries GET without replaying creation',async()=>{
  const h=harness([new Error('offline'),{ok:true,site_id:7,state:'ready',steps:[],redirect:'/sites/7?tab=overview'}]);h.begin();await h.tick();assert.equal(h.navigations.length,0);await h.tick();assert.equal(h.navigations.length,1);assert(h.requests.every(r=>r.init.method==='GET'));
});
test('five minute timeout stops polling and keeps background completion available',async()=>{
  const h=harness([]);h.begin();h.setTime(300001);await h.tick();assert.equal(h.requests.length,0);assert.equal(h.navigations.length,0);assert.match(h.nodes['[data-np-setup-message]'].textContent,/background/i);assert.equal(h.timers.size,0);
});
test('closing the dialog cancels automatic navigation',async()=>{
  const h=harness([]);h.begin();const pending=[...h.timers.values()][0].fn;h.close();assert.equal(h.timers.size,0);await pending();assert.equal(h.requests.length,0);assert.equal(h.navigations.length,0);
});
test('superseded setup timers cannot fetch or navigate',async()=>{
  const h=harness([]);h.begin();h.panel.isConnected=false;await h.tick();assert.equal(h.requests.length,0);
});
test('ready setup does not discard unsaved settings',async()=>{
  const h=harness([{ok:true,site_id:7,state:'ready',steps:[],redirect:'/sites/7?tab=overview'}],{dirty:true});h.begin();await h.tick();assert.equal(h.navigations.length,0);assert.equal(h.panel.dataset.npSetupState,'ready');
});
test('website SSL tracker waits through HTTPS activation',async()=>{
 const h=harness([{ok:true,site_id:7,kind:'website',state:'pending',steps:[{code:'tls',state:'active'},{code:'https',state:'pending'}]},{ok:true,site_id:7,kind:'website',state:'ready',steps:[{code:'https',state:'active'}],redirect:'/sites/7?notice=website-secured'}]);h.data.kind='website';h.begin();await h.tick();assert.equal(h.navigations.length,0);assert.equal(h.nodes['[data-np-setup-step="https"]'].textContent,'Waiting');assert.match(h.nodes['[data-np-setup-title]'].textContent,/website/i);await h.tick();assert.equal(h.navigations.length,1);
});
test('generated WordPress credentials prevent automatic navigation until acknowledged',async()=>{
 const h=harness([{ok:true,site_id:7,state:'ready',steps:[],redirect:'/sites/7'}]);h.panel.dataset.npSetupHold='true';h.begin();await h.tick();assert.equal(h.navigations.length,0);assert.equal(h.panel.dataset.npSetupState,'ready');
});
for(const status of [401,403,404]) test(`access change ${status} stops polling`,async()=>{
  const h=harness([{ok:false,status}]);h.begin();await h.tick();assert.equal(h.navigations.length,0);assert.equal(h.timers.size,0);
});
test('cross-origin status URL is rejected',()=>{
  const h=harness([]);h.data.status_url='https://elsewhere.test/sites/7/setup/status';h.begin();assert.equal(h.requests.length,0);assert.equal(h.timers.size,0);
});
test('wrong site result cannot redirect',async()=>{
  const h=harness([{ok:true,site_id:9,state:'ready',steps:[],redirect:'/sites/9?tab=overview'}]);h.begin();await h.tick();assert.equal(h.navigations.length,0);assert.equal(h.timers.size,0);
});

function submissionHarness(payload, status=202) {
  const start=source.indexOf('  function submitSite('), end=source.indexOf('\n  function updateV2CreateGate(',start);
  let posts=0;const navigations=[],tracks=[];
  const submit={disabled:false},gate={textContent:'',classList:{add(){}}},panel={hidden:true,querySelector:()=>({focus(){}})};
  const dialog={querySelector:selector=>selector==='[data-np-setup-tracker]'?panel:{textContent:''}};
  const form={dataset:{},hidden:false,action:'/sites/1/subdomains',matches:()=>true,closest:()=>dialog,querySelector:selector=>selector==='[data-np-create-submit]'?submit:gate};
  const context=vm.createContext({FormData:class extends Array{constructor(){super();this.push(['label','blog']);}},URLSearchParams,setFormBusy(){},trackSiteSetup:(...args)=>tracks.push(args),window:{location:{assign:url=>navigations.push(url)},NakpanelUI:{fetch:async()=>{posts++;if(payload instanceof Error)throw payload;return {ok:status<400,status,text:async()=>typeof payload==='string'?payload:JSON.stringify(payload)};}}}});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end),context);
  return {submit:()=>context.submitSite(form),form,posts:()=>posts,navigations,tracks,gate};
}
test('accepted creation stays in its dialog and cannot POST twice',async()=>{
  const h=submissionHarness({ok:true,site_id:7,status_url:'/sites/7/setup/status',redirect:'/sites/7'});
  await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.tracks.length,1);assert.equal(h.navigations.length,0);assert.equal(h.form.hidden,true);
});
test('accepted creation without a status URL cannot silently redirect or submit again',async()=>{
  const h=submissionHarness({ok:true,site_id:7,redirect:'/sites/7'});
  await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.navigations.length,0);assert.match(h.gate.textContent,/check Websites/i);
});
for(const response of [new Error('connection lost'),'<html>Unexpected response</html>']) test('uncertain creation result cannot replay POST',async()=>{
  const h=submissionHarness(response);await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.navigations.length,0);assert.match(h.gate.textContent,/check Websites/i);
});
test('confirmed validation rejection preserves the ability to correct and submit',async()=>{
  const h=submissionHarness({ok:false,error:'Invalid label'},400);await h.submit();await h.submit();assert.equal(h.posts(),2);assert.match(h.gate.textContent,/Invalid label/);
});
test('shared fetch HTTP validation errors allow correction while keeping network uncertainty locked',async()=>{
  const error=new Error('Invalid label');error.status=400;error.payload={error:'Invalid label'};
  const h=submissionHarness(error);await h.submit();await h.submit();assert.equal(h.posts(),2);assert.match(h.gate.textContent,/Invalid label/);
});
test('editing an uncertain request cannot erase its warning or re-enable Create',()=>{
  const start=source.indexOf('  function updateSubdomainGate('),end=source.indexOf('\n  function updateCreateGate(',start);
  const form={dataset:{npSubmitting:'true'},querySelector(){throw new Error('must preserve the in-flight request state');}};
  const context=vm.createContext({each:(_selector,_scope,fn)=>fn(form),document:{}});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end),context);context.updateSubdomainGate();
});

function websiteSubmissionHarness(response, sharedClient=false) {
 const start=source.indexOf('  function submitWebsiteV2('),end=source.indexOf('\n  function updateCreationSSLChoice(',start);
 const submit={disabled:false,focus(){}},gate={textContent:'',setAttribute(){},removeAttribute(){}};
 const form={dataset:{},action:'/websites',querySelector:selector=>selector==='[data-np-v2-create-submit]'?submit:gate};
 let posts=0;
 const transport=async()=>{posts++;if(response instanceof Error)throw response;return response;};
 const request=sharedClient?require('./static/interaction.js').createClient({baseURL:'https://panel.test',csrf:()=> 'token',fetch:transport}).fetch:transport;
 const context=vm.createContext({URL,window:{location:{origin:'https://panel.test'}},FormData:class{},csrfToken:()=> 'token',updateV2CreateGate:f=>{if(f.dataset.npSubmitting!=='true')submit.disabled=false;},fetch:request});
 installLifecycle(context);
  vm.runInContext(source.slice(start,end),context);
 return {submit:()=>context.submitWebsiteV2(form),form,gate,button:submit,posts:()=>posts};
}
test('website login redirects preserve input and offer sign-in recovery',async()=>{
 const h=websiteSubmissionHarness({status:200,ok:true,redirected:true,url:'https://panel.test/login',json:async()=>{throw new SyntaxError('HTML');}});
 // Match the real page origin without borrowing a browser session.
 h.form.action='https://panel.test/websites';
 await h.submit();assert.equal(h.form.dataset.npSubmitting,'false');assert.equal(h.button.disabled,false);assert.match(h.gate.textContent,/sign in/i);assert.equal(h.posts(),1);
});
test('website 401 HTML responses have sign-in recovery instead of a parse error',async()=>{
 const h=websiteSubmissionHarness({status:401,ok:false,redirected:false,json:async()=>{throw new SyntaxError('HTML');}});
 await h.submit();assert.equal(h.form.dataset.npSubmitting,'false');assert.match(h.gate.textContent,/sign in/i);
});
test('website network uncertainty keeps creation locked without replay',async()=>{
 const h=websiteSubmissionHarness(new Error('offline'));await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.button.disabled,true);assert.match(h.gate.textContent,/Check Websites/);
});
test('website outside login redirect remains uncertain and cannot replay',async()=>{
 const h=websiteSubmissionHarness({status:200,ok:true,redirected:true,url:'https://outside.test/login',json:async()=>{throw new SyntaxError('HTML');}});
 await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.form.dataset.npSubmitting,'true');assert.match(h.gate.textContent,/Check Websites/);
});
test('website shared-client session rejection offers sign-in and preserves input',async()=>{
 const response=new Response('<html>login</html>');Object.defineProperties(response,{redirected:{value:true},url:{value:'https://panel.test/login'}});
 const h=websiteSubmissionHarness(response,true);await h.submit();assert.equal(h.form.dataset.npSubmitting,'false');assert.equal(h.button.disabled,false);assert.match(h.gate.textContent,/sign in/i);assert.equal(h.posts(),1);
});
test('website shared-client validation errors remain correctable',async()=>{
 const h=websiteSubmissionHarness(new Response('{"ok":false,"error":"Invalid domain"}',{status:400,headers:{'Content-Type':'application/json'}}),true);
 await h.submit();assert.equal(h.form.dataset.npSubmitting,'false');assert.match(h.gate.textContent,/Invalid domain/);
});
test('website shared-client server failures cannot replay creation',async()=>{
 const h=websiteSubmissionHarness(new Response('{"ok":false,"error":"Server unavailable"}',{status:503,headers:{'Content-Type':'application/json'}}),true);
 await h.submit();await h.submit();assert.equal(h.posts(),1);assert.equal(h.form.dataset.npSubmitting,'true');assert.match(h.gate.textContent,/Check Websites/);
});

test('page setup polling cancels its timer on unmount',()=>{
 const h=harness([],{page:true});h.begin();assert.equal(h.timers.size,1);
 h.unmount();assert.equal(h.timers.size,0);assert.equal(h.requests.length,0);
});
for(const instantNav of [true,false])test('pending setup resumes on reopen with instant navigation '+(instantNav?'on':'off'),async()=>{
 const h=harness([{ok:true,site_id:7,state:'pending',steps:[]},{ok:true,site_id:7,state:'ready',steps:[],redirect:'/sites/7'}],{instantNav});
 h.dialog.open=false;h.init(); // Initial mount finds a dormant tracker before creation.
 h.dialog.open=true;h.begin();await h.tick();assert.equal(h.requests.length,1);
 h.close();assert.equal(h.timers.size,0);assert.equal(h.requests.length,1);
 h.dialog.open=true;h.init();h.init(); // Repeated mounts must only start one run.
 await h.tick();assert.equal(h.requests.length,2);assert.equal(h.navigations.length,1);assert.equal(h.panel.dataset.npSetupState,'ready');
});
