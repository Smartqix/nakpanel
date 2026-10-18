const installLifecycle = require('./lifecycle_harness.cjs');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
test('database refresh uses scoped page and stops after terminal state', async () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initDatabaseRefresh(root)');
  assert(start >= 0, 'database refresh initializer exists');
  const end = source.indexOf('\n  async function reloadDatabasePanel', start + 1);
  const callbacks = [];
  let replaced = false;
  const panel = {dataset:{npDbStatusUrl:'/sites/58/databases/status'},querySelector:()=>null};
  const context = vm.createContext({document:{querySelector:()=>panel,hidden:false},window:{setTimeout:fn=>callbacks.push(fn)},fetch:async url=>{assert.equal(url,'/sites/58/databases/status');return {ok:true,redirected:false,json:async()=>({databases:[{id:1,status:'active'}]})};},reloadDatabasePanel:async()=>{replaced=true;}});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\ninitDatabaseRefresh();',context);
  assert.equal(callbacks.length,1);
  await callbacks.shift()();
  assert.equal(replaced,true);
  assert.equal(callbacks.length,0);
});

test('database status retries a temporary HTTP failure', async () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initDatabaseRefresh(root)');
  const end = source.indexOf('\n  async function reloadDatabasePanel', start);
  const callbacks = [];
  const panel = {dataset:{npDbStatusUrl:'/sites/58/databases/status'},querySelector:()=>null};
  const context = vm.createContext({document:{querySelector:()=>panel,hidden:false},window:{setTimeout:fn=>callbacks.push(fn)},fetch:async()=>({ok:false,status:503,redirected:false})});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\ninitDatabaseRefresh();',context);
  await callbacks.shift()();
  assert.equal(callbacks.length,1,'transient failure must schedule another status check');
});

test('obsolete database panel timers stop without fetching', async () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initDatabaseRefresh(root)');
  const end = source.indexOf('\n  async function reloadDatabasePanel', start);
  const callbacks=[];
  let panel={dataset:{npDbStatusUrl:'/status'},querySelector:()=>null};
  let calls=0;
  const context=vm.createContext({document:{querySelector:()=>panel,hidden:false},window:{setTimeout:fn=>callbacks.push(fn)},fetch:async()=>{calls++;return {ok:true,json:async()=>({databases:[]})};}});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\ninitDatabaseRefresh();',context);
  panel={};
  await callbacks.shift()();
  assert.equal(calls,0);
});

test('successful submission reports refresh failure outside closed dialog', async () => {
  const source=fs.readFileSync(__dirname+'/static/app.js','utf8');
  const start=source.indexOf('  async function submitDomainDatabase(form)');
  const end=source.indexOf('\n  function generateDatabasePassword',start);
  const feedback={hidden:true,textContent:''};
  const error={hidden:true,textContent:''};
  let closed=false;
  const form={action:'https://panel.test/databases/30/password',dataset:{},querySelector:()=>error,closest:()=>({})};
  const context=vm.createContext({URL,URLSearchParams,FormData:class{*[Symbol.iterator](){}},document:{querySelector:()=>feedback},setFormBusy:()=>{},csrfToken:()=>'',fetch:async()=>({ok:true,json:async()=>({ok:true,notice:'Password change queued.'})}),closeDialog:()=>{closed=true;},clearSensitiveInputs:()=>{},reloadDatabasePanel:async()=>{throw new Error('offline');}});
  installLifecycle(context);
  vm.runInContext(source.slice(start,end),context);
  await context.submitDomainDatabase(form);
  assert(closed);
  assert.equal(feedback.hidden,false);
  assert.match(feedback.textContent,/queued/i);
  assert.match(feedback.textContent,/refresh/i);
  assert.equal(error.hidden,true,'successful queue must not be presented as failed');
});

test('unmount cancels database polling before its next request', () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initDatabaseRefresh(root)');
  const end = source.indexOf('\n  async function reloadDatabasePanel', start);
  const timers = new Map();let id = 0, calls = 0;
  const panel = {dataset:{npDbStatusUrl:'/status'},querySelector:()=>null};
  const root = {querySelector:()=>panel,contains:element=>element===panel};
  const context = vm.createContext({document:{querySelector:()=>panel,hidden:false},root,
    window:{setTimeout:fn=>{timers.set(++id,fn);return id;},clearTimeout:id=>timers.delete(id)},fetch:async()=>{calls++;}});
  const lifecycle = installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\ninitDatabaseRefresh(root);',context);
  assert.equal(timers.size,1);lifecycle.unmount(root);
  assert.equal(timers.size,0);assert.equal(calls,0);
});
