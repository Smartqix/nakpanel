const installLifecycle = require('./lifecycle_harness.cjs');
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(__dirname+'/static/app.js','utf8');
test('server administration ignores a second pending submission',()=>{
 const start=source.indexOf('  function submitServerAdminForm(');
 const end=source.indexOf('\n  function ',start+5);
 let busy=false,calls=0;
 const form={matches:()=>false,getAttribute:()=>busy?'true':'false'};
 const context=vm.createContext({form,FormData:class{},formStatus:()=>null,csrfToken:()=>'',setFormBusy:(_,value)=>{busy=value;},fetch:()=>{calls++;return new Promise(()=>{});}});
 installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\nsubmitServerAdminForm(form);submitServerAdminForm(form);',context);
 assert.equal(calls,1);
});
test('operation polling stops when its view is removed',()=>{
 const start=source.indexOf('  function pollServerOperation(');
 const end=source.indexOf('\n  function ',start+5);
 const callbacks=[]; let calls=0;
 const context=vm.createContext({window:{fetch:true,setTimeout:fn=>callbacks.push(fn)},fetch:()=>{calls++;return new Promise(()=>{});},status:{isConnected:false}});
 installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\npollServerOperation("123",status);',context);
 assert.equal(callbacks.length,0);
 assert.equal(calls,0);
});
test('a long-running operation explains when automatic checking pauses',async()=>{
 const start=source.indexOf('  function pollServerOperation(');
 const end=source.indexOf('\n  function ',start+5);
 const callbacks=[]; let calls=0;
 const status={isConnected:true,setAttribute:()=>{},textContent:''};
 const context=vm.createContext({window:{fetch:true,setTimeout:fn=>callbacks.push(fn)},fetch:async()=>{calls++;return {ok:true,json:async()=>({ok:true,operation:{status:'running'}})};},status});
 installLifecycle(context);
  vm.runInContext(source.slice(start,end)+'\npollServerOperation("123",status);',context);
 while(callbacks.length){ callbacks.shift()(); await new Promise(resolve=>setImmediate(resolve)); }
 assert.equal(calls,40);
 assert.match(status.textContent,/checking paused/);
 assert.match(status.textContent,/do not submit/);
});
