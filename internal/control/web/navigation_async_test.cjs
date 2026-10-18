const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const installLifecycle = require('./lifecycle_harness.cjs');
const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

function backupHarness() {
  let resolve;
  const pending = new Promise(done => { resolve = done; });
  function page() {
    const error = {textContent:'', hidden:true, closest:()=>null};
    const output = {textContent:'', hidden:true};
    const root = {contains:node=>node===error || node===output};
    return {root, error, output};
  }
  const first = page(), next = page();
  let current = first, refreshes = 0, options;
  const document = {querySelector:selector=>selector==='#main-content'?current.root:selector==='[data-np-backup-error]'?current.error:selector==='[data-np-backup-key-output]'?current.output:null};
  const context = vm.createContext({document, AbortController, JSON,
    window:{setTimeout, clearTimeout}, csrfToken:()=> 'csrf',
    fetch:async(_url, config)=>{options=config;return pending;},
    loadServerBackups:()=>{refreshes++;}});
  const lifecycle = installLifecycle(context);
  const start = source.indexOf('  function backupAction(');
  vm.runInContext(source.slice(start, source.indexOf('\n  function ', start+1)), context);
  return {first, next, get options(){return options;}, get refreshes(){return refreshes;},
    start:()=>context.backupAction('/tools-settings/backups/key/init',{},'Key ready'),
    leave:()=>{lifecycle.unmount(first.root);current=next;},
    finish:async()=>{resolve({ok:true,status:200,json:async()=>({ok:true,key:'one-time-backup-key',notice:'Save privately'})});await tick();await tick();}};
}

test('backup key is shown once on its originating page', async()=>{
  const h=backupHarness();h.start();await h.finish();
  assert.match(h.first.output.textContent,/one-time-backup-key/);
  assert.equal(h.first.output.hidden,false);
  assert.equal(h.refreshes,1);
});
test('a delayed backup key cannot enter a later page after navigation', async()=>{
  const h=backupHarness();h.start();h.leave();await h.finish();
  assert.equal(h.next.output.textContent,'');
  assert.equal(h.next.output.hidden,true);
  assert.equal(h.refreshes,0);
});

for (const failure of [false,true]) test('old Mail server status cannot replace fresh status after navigation: '+failure, async()=>{
  let resolve, reject;
  const pending=new Promise((done,fail)=>{resolve=done;reject=fail;});
  function page(){const status={closest:()=>null},state={textContent:'fresh',className:''};return{status,state,root:{contains:node=>node===status}};}
  const first=page(),next=page();let current=first;
  const document={querySelector:selector=>selector==='[data-np-mail-status]'?current.status:selector==='[data-np-mail-state]'?current.state:null};
  const context=vm.createContext({document,AbortController,window:{fetch(){},setTimeout,clearTimeout},fetch:async()=>pending});
  const lifecycle=installLifecycle(context);
  const start=source.indexOf('  function loadMailStatus(');
  vm.runInContext(source.slice(start,source.indexOf('\n  function ',start+1)),context);
  context.loadMailStatus();lifecycle.unmount(first.root);current=next;
  if(failure)reject(new Error('late failure'));else resolve({ok:true,json:async()=>({ok:true,status:{state:'old'}})});
  await tick();await tick();
  assert.equal(next.state.textContent,'fresh');
});

for (const [name,payload] of [
  ['loadServerInventory',{ok:true,inventory:{}}], ['loadServerJournal',{ok:true,result:{}}],
  ['loadServerUpdates',{ok:true,updates:{}}], ['loadServerSecurity',{ok:true,policy:{}}],
  ['loadSecurityBans',{ok:true,bans:{}}], ['loadServerBackups',{ok:true}],
  ['loadMailQueue',{ok:true,queue:{}}], ['loadMailLogs',{ok:true,logs:{}}],
  ['loadDatabaseAdmin',{ok:true,database_admin:{}}], ['loadApplicationCatalog',{ok:true,catalog:[]}]
]) test(name+' cancels and ignores its old page response', async()=>{
  let finish,options,left=false,lateWrites=0;
  const pending=new Promise(resolve=>{finish=resolve;});
  const node=new Proxy({closest:()=>null,dataset:{},children:[],querySelector:()=>null,
    replaceChildren(){if(left)lateWrites++;},appendChild(){if(left)lateWrites++;}},
    {set(target,key,value){if(left)lateWrites++;target[key]=value;return true;}});
  const root={contains:element=>element===node};
  const document={querySelector:()=>{if(left)lateWrites++;return node;},querySelectorAll:()=>[],createElement:()=>node};
  class Fields extends FormData {constructor(){super();}}
  const context=vm.createContext({document,AbortController,FormData:Fields,URLSearchParams,JSON,
    window:{fetch(){},setTimeout,clearTimeout},csrfToken:()=> 'csrf',fetch:async(_url,config)=>{options=config;return pending;}});
  const lifecycle=installLifecycle(context);
  for(const helper of ['each','replaceTableWithMessage']) {
    const start=source.indexOf('  function '+helper+'(');
    vm.runInContext(source.slice(start,source.indexOf('\n  }',start)+4),context);
  }
  const start=source.indexOf('  function '+name+'(');
  vm.runInContext(source.slice(start,source.indexOf('\n  function ',start+1)),context);
  context[name]();lifecycle.unmount(root);left=true;
  finish({ok:true,status:200,json:async()=>payload});await tick();await tick();
  assert.equal(lateWrites,0,'old request reached DOM after leaving');
  assert.equal(options.signal?.aborted,true,'outgoing network request was not cancelled');
});

test('security actions cannot start polling a later page after navigation',async()=>{
  let finish,options,polling=0;
  const pending=new Promise(resolve=>{finish=resolve;});
  const root={contains:()=>false},status={closest:()=>null};
  const context=vm.createContext({AbortController,JSON,document:{querySelector:selector=>selector==='#main-content'?root:status},
    window:{setTimeout,clearTimeout},csrfToken:()=> 'csrf',trackSecurityOperation:()=>polling++,loadSecurityBans:()=>polling++,
    fetch:async(_url,config)=>{options=config;return pending;}});
  const lifecycle=installLifecycle(context);
  const start=source.indexOf('  async function securityAction(');
  vm.runInContext(source.slice(start,source.indexOf('\n  function ',start+1)),context);
  await context.securityAction('/security/action',{});
  lifecycle.unmount(root);
  finish({ok:true,status:200,json:async()=>({ok:true,operation_id:'old-operation'})});await tick();await tick();
  assert.equal(polling,0);assert.equal(options.signal?.aborted,true);
});

test('a completed database action cannot refresh or notify a different domain',async()=>{
  let finish,refreshes=0;
  const pending=new Promise(resolve=>{finish=resolve;});
  const root={contains:()=>false},feedback={hidden:true,textContent:''};
  const form={dataset:{},action:'https://panel.test/databases',querySelector:()=>null,closest:()=>null,appendChild(){}};
  class Fields extends FormData {constructor(){super();}}
  const context=vm.createContext({AbortController,URL,URLSearchParams,FormData:Fields,form,
    document:{querySelector:selector=>selector==='#main-content'?root:feedback,createElement:()=>({})},
    window:{crypto:{randomUUID:()=> 'request-id'},setTimeout,clearTimeout},csrfToken:()=> 'csrf',setFormBusy(){},clearSensitiveInputs(){},
    reloadDatabasePanel:async()=>{refreshes++;},fetch:async()=>pending});
  const lifecycle=installLifecycle(context);
  const start=source.indexOf('  async function submitDomainDatabase(');
  vm.runInContext(source.slice(start,source.indexOf('\n  function ',start+1)),context);
  const submission=context.submitDomainDatabase(form);lifecycle.unmount(root);
  finish({ok:true,json:async()=>({ok:true,notice:'Prior domain database queued'})});await submission;
  assert.equal(refreshes,0);assert.equal(feedback.hidden,true);assert.equal(feedback.textContent,'');
});
