const test=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const {createLifecycle}=require('./navigation.js');
function source(name){return fs.readFileSync(require.resolve('./'+name+'.js'),'utf8');}
test('the deferred DNS script waits for interaction/navigation on an interactive document',()=>{
 const callbacks=[];
 const document={readyState:'interactive',querySelector:()=>null};
 const window={addEventListener:(type,fn)=>{assert.equal(type,'DOMContentLoaded');callbacks.push(fn);}};
 vm.runInNewContext(source('dns-template'),{document,window});
 assert.equal(callbacks.length,1);
 window.NakpanelUI={lifecycle:createLifecycle()};callbacks[0]();
});
for(const name of ['dns-template','mail-import'])test(name+' ignores a late form response after leaving its page',async()=>{
 const lifecycle=createLifecycle(),assigned=[],listeners={};let finish;
 const pending=new Promise(resolve=>{finish=resolve;});
 const error={hidden:true,setAttribute(){},focus(){}},button={};
 const form={action:'https://panel.test/save',dataset:{},isConnected:true,matches:()=>false,
  addEventListener:(type,fn)=>{listeners[type]=fn;},
  querySelector:selector=>selector==='[name=source_kind]'?{value:'imap',addEventListener(){}}:selector==='button[type=submit]'?button:selector==='[name=csrf_token]'?{value:'csrf'}:error,
  querySelectorAll:selector=>selector==='[type=submit]'?[button]:[]};
 const workspace={contains:element=>element===form,querySelectorAll:selector=>selector==='form[method="post"]'?[form]:[]};
 const document={readyState:'complete',querySelector:()=>workspace,querySelectorAll:selector=>selector==='[data-mail-import-source]'?[form]:[]};
 const window={NakpanelUI:{lifecycle,fetch:async()=>pending},location:{href:'https://panel.test/page',origin:'https://panel.test',assign:url=>assigned.push(url)},addEventListener(){}};
 class Fields extends FormData {constructor(){super();}}
 vm.runInNewContext(source(name),{window,document,URL,URLSearchParams,FormData:Fields,AbortController});
 const submission=listeners.submit({preventDefault(){},stopPropagation(){}});
 lifecycle.unmount(workspace);form.isConnected=false;
 finish({ok:true,url:'https://panel.test/new',headers:{get:()=> 'application/json'},json:async()=>({ok:true,redirect:'/new'})});
 await submission;await new Promise(resolve=>setImmediate(resolve));
 assert.equal(assigned.length,0);assert.equal(error.hidden,true);
});
test('shared removal-dialog work belongs to the main content lifetime',async()=>{
 const lifecycle=createLifecycle(),assigned=[],listeners={},timers=new Map();let id=0,finish,requestSignal;
 const pending=new Promise(resolve=>{finish=resolve;});
 const main={contains:()=>false};
 const dialog={closest:()=>null,querySelector:()=>null,addEventListener(){}};
 const form={closest:selector=>selector.includes('.np-site-removal-dialog')?dialog:form,hasAttribute:()=>false,dataset:{npRemovalLookup:'/lookup'},action:'/remove'};
 const document={querySelector:()=>main,getElementById:()=>dialog,querySelectorAll:()=>[],addEventListener:(type,fn)=>{listeners[type]=fn;}};
 const window={document,location:{href:'https://panel.test/sites/7',pathname:'/sites/7',assign:url=>assigned.push(url)},NakpanelUI:{lifecycle,setBusy(){},fetch:async(url,options)=>{requestSignal=options.signal;return pending;}}};
 class Fields extends FormData {constructor(){super();}}
 vm.runInNewContext(source('site-removal'),{window,URL,URLSearchParams,AbortController,FormData:Fields,Date,setTimeout:(fn,delay)=>{timers.set(++id,fn);return id;},clearTimeout:id=>timers.delete(id)});
 const submit=listeners.submit({target:form,preventDefault(){}});
 lifecycle.unmount(main);assert.equal(requestSignal.aborted,true);
 finish({json:async()=>({state:'completed',redirect:'/sites/7',status_url:'/status'})});await submit;
 assert.equal(assigned.length,0);assert.equal(timers.size,0);
});
