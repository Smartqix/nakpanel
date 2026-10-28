const installLifecycle = require('./lifecycle_harness.cjs');
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(__dirname+'/static/app.js','utf8');
test('server forms serialize browser fields and preserve the selected action',async()=>{
 const start=source.indexOf('  function submitServerAdminForm('),end=source.indexOf('\n  function ',start+5);
 let body,url;
 class Fields extends Map {constructor(){super([['service_id','web']])}}
 const form={matches:()=>false,getAttribute:name=>name==='action'?'/tools-settings/services/action':false,action:{namedActionButtons:true}};
 const context=vm.createContext({form,FormData:Fields,URLSearchParams,formStatus:()=>null,csrfToken:()=> 'csrf',setFormBusy(){},clearSensitiveInputs(){},fetch:async(target,opts)=>{url=target;body=opts.body;return {ok:true,json:async()=>({ok:true})}}});
 installLifecycle(context);
 vm.runInContext(source.slice(start,end)+'\nsubmitServerAdminForm(form,{name:"action",value:"reload"});',context);
 await new Promise(r=>setImmediate(r));
 assert.ok(body instanceof URLSearchParams,'request must use the native URL-encoded form contract');
 assert.equal(body.toString(),'service_id=web&action=reload');
 assert.equal(url,'/tools-settings/services/action','a control named action must not replace the form endpoint');
});
test('service progress uses its visible notice rather than the collapsed authorization form',()=>{
 const start=source.indexOf('  function formStatus('),end=source.indexOf('\n  function ',start+5);
 const service={},reauth={},scope={querySelector:selector=>selector==='[data-np-reauth-status]'?reauth:service};
 const form={matches:()=>false,closest:()=>scope};
 const context=vm.createContext({form,document:{querySelector:()=>service}});
 vm.runInContext(source.slice(start,end)+'\nresult=formStatus(form,"[data-np-service-operation]");',context);
 assert.equal(context.result,service);
});
test('closing service menus keeps only the selected menu and restores its opener on Escape',()=>{
 const start=source.indexOf('  function closeServiceMenus('),end=source.indexOf('\n  function ',start+5);
 let focused=0;
 const opener={setAttribute(){},focus(){focused++}},first={open:true,querySelector:()=>opener},second={open:true,querySelector:()=>opener};
 const context=vm.createContext({first,each:(_selector,_root,fn)=>[first,second].filter(m=>m.open).forEach(fn),document:{}});
 vm.runInContext(source.slice(start,end)+'\ncloseServiceMenus(first,false);',context);
 assert.equal(first.open,true);assert.equal(second.open,false);assert.equal(focused,0);
 vm.runInContext('closeServiceMenus(null,true);',context);
 assert.equal(first.open,false);assert.equal(focused,1);
});
test('server administration ignores a second pending submission',()=>{
 const start=source.indexOf('  function submitServerAdminForm(');
 const end=source.indexOf('\n  function ',start+5);
 let busy=false,calls=0;
 const form={matches:()=>false,getAttribute:()=>busy?'true':'false'};
 const context=vm.createContext({form,FormData:class{},URLSearchParams,formStatus:()=>null,csrfToken:()=>'',setFormBusy:(_,value)=>{busy=value;},fetch:()=>{calls++;return new Promise(()=>{});}});
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

test('successful reauthentication clears the stale service warning without replaying an action',async()=>{
 const start=source.indexOf('  function submitServerAdminForm('),end=source.indexOf('\n  function ',start+5);
 const feedback={hidden:false,textContent:'Recent authentication is required',setAttribute(name,value){this[name]=value}},status={setAttribute(){},getAttribute:()=> 'status'};
 const form={matches:selector=>selector==='[data-np-reauth-form]',getAttribute:name=>name==='action'?'/tools-settings/reauthenticate':null};
 let requests=0;
 const context=vm.createContext({form,FormData:class extends Map{constructor(){super()}},URLSearchParams,formStatus:()=>status,csrfToken:()=> 'csrf',setFormBusy(){},clearSensitiveInputs(){},document:{querySelector:()=>feedback},fetch:async()=>{requests++;return {ok:true,json:async()=>({ok:true})}}});
 installLifecycle(context);
 vm.runInContext(source.slice(start,end)+'\nsubmitServerAdminForm(form);',context);
 await new Promise(r=>setImmediate(r));
 assert.equal(requests,1);assert.match(feedback.textContent,/Authentication refreshed/);assert.equal(feedback.role,'status');
});

test('a server failure retains uncertainty until a successful status check',async()=>{
 const {createServiceTracker}=require('./static/service-controls.js');
 let rendered;
 const tracker=createServiceTracker({load:async()=>{throw Error('status unavailable')},render:items=>rendered=items,isCurrent:()=>true});
 const start=source.indexOf('  function submitServerAdminForm('),end=source.indexOf('\n  function ',start+5);
 const form={matches:s=>s==='[data-np-service-form]',getAttribute:()=>null};
 class Fields extends Map{constructor(){super([['service_id','web'],['action','restart']])}}
 const context=vm.createContext({form,FormData:Fields,URLSearchParams,formStatus:()=>null,getServiceTracker:()=>tracker,csrfToken:()=> '',setFormBusy(){},clearSensitiveInputs(){},fetch:async()=>{const error=Error('upstream unavailable');error.status=502;throw error}});
 installLifecycle(context);
 vm.runInContext(source.slice(start,end)+'\nsubmitServerAdminForm(form);',context);
 await new Promise(r=>setImmediate(r));
 assert.equal(rendered.get('web')?.status,'unknown');
 assert.equal(rendered.get('web')?.action,'restart');
});
test('inventory refresh preserves the form behind an open confirmation, including late responses',async()=>{
 const start=source.indexOf('  function loadServerInventory('),end=source.indexOf('\n  function ',start+5);
 let dialogOpen=true,calls=0,resolve;
 const target={isConnected:true},signal=new AbortController().signal;
 const context=vm.createContext({window:{fetch:true},document:{querySelector:selector=>selector==='[data-np-settings-inventory]'?target:dialogOpen?{}:null},lifetime:()=>signal,each(){},fetch:()=>{calls++;return new Promise(r=>resolve=r)}});
 vm.runInContext(source.slice(start,end)+'\nresult=loadServerInventory();',context);
 assert.equal(calls,0,'an open confirmation must defer inventory requests');assert.equal(await context.result,false);
 dialogOpen=false;vm.runInContext('result=loadServerInventory();',context);assert.equal(calls,1);
 dialogOpen=true;resolve({ok:true,json:async()=>({ok:true,inventory:{services:[]}})});
 assert.equal(await context.result,false,'a late inventory response must not rebuild action forms inside confirmation');
});
