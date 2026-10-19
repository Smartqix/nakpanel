const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {createLifecycle}=require('./static/navigation.js');
const {mailAddressMatches,createMailConnectionLoader}=require('./static/mail.js');
test('mail search matches complete addresses case-insensitively',()=>{
 assert.equal(mailAddressMatches('Admin@example.test',' ADMIN '),true);
 assert.equal(mailAddressMatches('Admin@example.test','missing'),false);
 assert.equal(mailAddressMatches('Admin@example.test',''),true);
});
test('late connection responses cannot overwrite another mailbox or a closed dialog',async()=>{
 const pending=[],seen=[];
 const loader=createMailConnectionLoader({request:()=>new Promise(resolve=>pending.push(resolve)),show:v=>seen.push(v),error:e=>seen.push(e)});
 const first=loader.load('first'),second=loader.load('second');
 pending[1]('second mailbox');await second;
 pending[0]('first mailbox');await first;
 assert.deepEqual(seen,['second mailbox']);
 const third=loader.load('third');loader.stop();pending[2]('closed');await third;
 assert.deepEqual(seen,['second mailbox']);
});
test('mail connection views are enhanced on each fragment mount',()=>{
 const lifecycle=createLifecycle(),view={classList:{add(name){this.added=name;}}},panel={hidden:false};
 const document={getElementById:()=>null,querySelectorAll:()=>[],addEventListener(){}};
 const window={document,NakpanelUI:{lifecycle}};
 vm.runInNewContext(fs.readFileSync(__dirname+'/static/mail.js','utf8'),{window,AbortController});
 lifecycle.mount({querySelectorAll:selector=>selector==='[data-np-mail-client-view]'?[view]:selector==='[data-np-mail-protocol-panel="pop"]'?[panel]:[]});
 assert.equal(view.classList.added,'is-enhanced');assert.equal(panel.hidden,true);
});
test('leaving a Mail connection loader aborts its active request',async()=>{
 let signal,finish;const seen=[];
 const loader=createMailConnectionLoader({request:(_url,requestSignal)=>{signal=requestSignal;return new Promise(resolve=>{finish=resolve;});},show:value=>seen.push(value),error:value=>seen.push(value)});
 const pending=loader.load('connection');loader.stop();
 assert.equal(signal.aborted,true);finish('late mailbox');await pending;
 assert.deepEqual(seen,[]);
});
