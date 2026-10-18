const test=require('node:test');
const assert=require('node:assert/strict');
const {createSiteRemovalController}=require('./static/site-removal.js');
const fs=require('node:fs');
const vm=require('node:vm');
const {createLifecycle}=require('./static/navigation.js');

function environment(request){let clock=0;const updates=[],redirects=[];return {request,updates,redirects,now:()=>clock,sleep:async ms=>{clock+=ms},update:value=>updates.push(value),redirect:path=>redirects.push(path),baseURL:'https://panel.test'};}
test('TestSiteRemovalLostResponseDoesNotReplay',async()=>{
	const calls=[];const env=environment(async(url,opts={})=>{calls.push([url,opts.method||'GET']);if(opts.method==='POST')throw new Error('lost response');if(url==='/lookup')return {state:'queued',status_url:'/site-removals/1/status',progress_url:'/site-removals/1'};return {state:'completed',redirect:'/subscriptions/20?tab=websites'};});
	const controller=createSiteRemovalController(env);await controller.submit('/remove','body','/lookup');await controller.submit('/remove','body','/lookup');
	assert.equal(calls.filter(call=>call[1]==='POST').length,1);assert.equal(calls[1][0],'/lookup');assert.deepEqual(env.redirects,['/subscriptions/20?tab=websites']);
});
test('TestSiteRemovalSessionExpiryPreservesProgress',async()=>{
	let calls=0;const env=environment(async()=>{calls++;throw Object.assign(new Error('session expired'),{status:401});});
	await createSiteRemovalController(env).watch('/site-removals/1/status','/site-removals/1');
	assert.equal(calls,1);assert.equal(env.redirects.length,0);assert.equal(env.updates.at(-1).state,'signin');assert.equal(env.updates.at(-1).progress_url,'/site-removals/1');
});
test('removal waits for completion, stops on failure and respects foreground deadline',async()=>{
	const env=environment(async()=>({state:'running',stage:'remove_hosting'}));await createSiteRemovalController(env).watch('/status','/progress');assert.equal(env.updates.at(-1).state,'background');assert.equal(env.redirects.length,0);
	const failed=environment(async()=>({state:'failed',message:'Could not finish',html:'failure'}));await createSiteRemovalController(failed).watch('/status','/progress');assert.equal(failed.redirects.length,0);assert.equal(failed.updates.at(-1).state,'failed');
});
test('removal refuses off-panel or deleted-object destinations',async()=>{
	for(const redirect of ['https://other.test/subscriptions/20','/sites/7/remove','javascript:alert(1)']){const env=environment(async()=>({state:'completed',redirect}));await createSiteRemovalController(env).watch('/status','/progress');assert.equal(env.redirects.length,0);}
});

test('closing during acceptance never restarts foreground polling or steals navigation',async()=>{
 let resolve;const accepted=new Promise(done=>{resolve=done});let calls=0;
 const env=environment(async(_url,options={})=>{calls++;return options.method==='POST'?accepted:{state:'completed',redirect:'/subscriptions/20?tab=websites'};});
 const controller=createSiteRemovalController(env);const pending=controller.submit('/remove','body','/lookup');controller.stop();resolve({state:'queued',status_url:'/status',progress_url:'/progress'});await pending;
 assert.equal(calls,1);assert.equal(env.redirects.length,0);
});

test('mounted failed progress enables Retry instead of leaving the form busy',async()=>{
 const button={disabled:false};const form={dataset:{},querySelector:()=>null};
 const root={closest:()=>null,dataset:{npRemovalStatus:'/status'},querySelector:selector=>selector.includes('form')?form:null};
 const document={querySelector:()=>null,getElementById:()=>null,addEventListener:()=>{},querySelectorAll:()=>[root]};
 const window={document,location:{href:'https://panel.test/site-removals/1',pathname:'/site-removals/1',assign:()=>{}},NakpanelUI:{fetch:async()=>({json:async()=>({state:'failed',stage:'remove_hosting',html:'failed retry form'})}),setBusy:(_form,busy)=>{button.disabled=busy}}};
 vm.runInNewContext(fs.readFileSync(require.resolve('./static/site-removal.js'),'utf8'),{window,URL,AbortController,setTimeout,clearTimeout,Date,WeakMap});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(button.disabled,false,'authoritative failure must offer a usable Retry');
});

function previewHarness() {
 const events={},pending=new Map(),lifecycle=createLifecycle(),body={textContent:''};
 let root={contains:()=>false};
 const dialog={open:false,innerHTML:'',dataset:{},closest:()=>null,querySelector:selector=>selector==='.np-removal-body'?body:null,addEventListener:(name,fn)=>{events['dialog:'+name]=fn;}};
 const document={getElementById:()=>dialog,querySelector:()=>root,querySelectorAll:()=>[],addEventListener:(name,fn)=>{events[name]=fn;}};
 const ui={lifecycle,dialogs:{open:()=>{dialog.open=true;}},fetch:(url,options)=>new Promise((resolve,reject)=>pending.set(url,{options,resolve:html=>resolve({json:async()=>({html})}),reject}))};
 const window={document,location:{href:'https://panel.test/sites/1'},NakpanelUI:ui};
 vm.runInNewContext(fs.readFileSync(require.resolve('./static/site-removal.js'),'utf8'),{window,URL,AbortController,setTimeout,clearTimeout});
 return {dialog,body,pending,click(domain){const owner=root,link={href:'/sites/'+domain+'/remove',closest:selector=>selector==='[data-np-removal-open]'?link:selector==='#main-content'?owner:null};return events.click({target:link,preventDefault(){}});},navigate(){lifecycle.unmount(root);root={contains:()=>false};dialog.open=false;},close(){dialog.open=false;events['dialog:close']();}};
}
for(const mode of ['success','error'])test('removal preview ignores a superseded '+mode+' after navigation',async()=>{
 const h=previewHarness(),a=h.click(1);h.navigate();const b=h.click(2);
 h.pending.get('/sites/2/remove/preview').resolve('Domain B removal form');await b;
 if(mode==='success')h.pending.get('/sites/1/remove/preview').resolve('Domain A removal form');
 else h.pending.get('/sites/1/remove/preview').reject(new Error('Domain A failed'));
 await a;assert.equal(h.dialog.innerHTML,'Domain B removal form');assert.equal(h.body.textContent,'');
});
test('removal preview generations protect reopening on the same page',async()=>{
 const h=previewHarness(),a=h.click(1);h.close();const b=h.click(2);
 h.pending.get('/sites/2/remove/preview').resolve('Domain B removal form');await b;
 h.pending.get('/sites/1/remove/preview').resolve('Domain A removal form');await a;
 assert.equal(h.dialog.innerHTML,'Domain B removal form');
});
test('unmount aborts a pending removal preview before any replacement opens',async()=>{
 const h=previewHarness(),a=h.click(1);h.navigate();h.dialog.open=true;
 h.pending.get('/sites/1/remove/preview').resolve('Stale domain removal form');await a;
 assert.equal(h.pending.get('/sites/1/remove/preview').options.signal.aborted,true);
 assert.notEqual(h.dialog.innerHTML,'Stale domain removal form');
});
