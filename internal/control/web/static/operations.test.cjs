const {test}=require('node:test');const assert=require('node:assert/strict');const {createOperationsPoller}=require('./operations.js');
function setup(){let resolve,rendered=[],events=[],timers=[],failed=[];const env={hidden:()=>false,setTimeout:f=>(timers.push(f),timers.length),clearTimeout:()=>{},load:(_s,cursor)=>new Promise(r=>resolve=r),render:x=>rendered.push(x),events:x=>events.push(...x),error:x=>failed.push(x)};const poller=createOperationsPoller(env);return {poller,env,rendered,events,timers,failed,resolve:x=>resolve(x)}}
test('old response cannot replace a new navigation scope',async()=>{const x=setup();x.poller.mount('one',0);x.poller.mount('two',0);x.resolve({cursor:2,events:[],page:{scope:'two'}});await new Promise(r=>setImmediate(r));assert.deepEqual(x.rendered,[{scope:'two'}]);x.poller.stop()});
test('reconnect replays durable events and preserves data on failure',async()=>{const x=setup();let n=0;x.env.load=async(_s,c)=>{if(n++===0)return {cursor:3,events:[{id:10,kind:'task.failed'}],page:{count:1}};throw Error('offline')};x.poller.mount('one',0);await new Promise(r=>setImmediate(r));x.timers.shift()();await new Promise(r=>setImmediate(r));assert.equal(x.events.length,1);assert.deepEqual(x.rendered,[{count:1}]);assert.equal(x.failed.at(-1),true);x.poller.stop()});
test('stopping aborts in-flight fetch and ignores its result',async()=>{const x=setup();x.poller.mount('one',0);x.poller.stop();x.resolve({cursor:99,events:[],page:{bad:true}});await new Promise(r=>setImmediate(r));assert.equal(x.rendered.length,0)});
test('late response from prior scope is discarded even if abort is ignored',async()=>{const x=setup(),pending=[];x.env.load=(_s,c,scope)=>new Promise(resolve=>pending.push({resolve,scope,c}));x.poller.mount('old',10);x.poller.mount('new',50);pending[1].resolve({cursor:51,page:{scope:'new'},events:[]});await new Promise(r=>setImmediate(r));pending[0].resolve({cursor:11,page:{scope:'old'},events:[]});await new Promise(r=>setImmediate(r));assert.deepEqual(x.rendered,[{scope:'new'}]);assert.equal(pending[1].c,50);x.poller.stop()});
test('hidden tabs cancel polling; reconnect retains the committed feed cursor',async()=>{const x=setup();let hidden=false,received=[];x.env.hidden=()=>hidden;x.env.load=async(_s,c)=>{received.push(c);return {cursor:40,events:c===30?Array.from({length:20},(_,id)=>({id})):[],page:{}}};x.poller.mount('scope',30);await new Promise(r=>setImmediate(r));hidden=true;x.poller.visibility();const before=received.length;hidden=false;x.poller.visibility();await new Promise(r=>setImmediate(r));assert.equal(received.length,before+1);assert.equal(received.at(-1),40);assert.equal(x.events.length,20);x.poller.stop()});

test('navigation preserves consumed cursor within authenticated scope, including cached fragments',async()=>{
 const x=setup(),received=[];x.env.load=async(_s,c)=>{received.push(c);return {cursor:c===10?11:c===11?12:c,events:[],page:{}}};
 x.poller.mount('/activity',10,'user:1|all');await new Promise(r=>setImmediate(r));
 x.poller.stop();x.poller.mount('/sites/51',99,'user:1|all');await new Promise(r=>setImmediate(r));
 x.poller.stop();x.poller.mount('/activity?tab=tasks',2,'user:1|all');await new Promise(r=>setImmediate(r));
 x.poller.mount('/activity',70,'user:2|all');await new Promise(r=>setImmediate(r));
 assert.deepEqual(received,[10,11,12,70]);x.poller.stop();
});

test('all relevant terminal results beyond eight rows are presented once',async()=>{
 const {terminalResults}=require('./operations.js');
 const events=Array.from({length:12},(_,id)=>({id:id+1,cursor:id+1,kind:['task.succeeded','task.cancelled','task.failed'][id%3],trigger:'manual',operation_kind:'create_backup'}));
 const x=setup();x.env.load=async()=>({cursor:12,events,page:{}});x.env.events=e=>x.events.push(...terminalResults(e));
 x.poller.mount('all',0);await new Promise(r=>setImmediate(r));x.poller.refresh();await new Promise(r=>setImmediate(r));
 assert.equal(x.events.length,12);assert.equal(terminalResults([{kind:'task.succeeded',trigger:'scheduled',operation_kind:'reconcile_system'}]).length,0);x.poller.stop();
});

test('preferences remain unavailable until loaded and stale loads cannot overwrite newer settings',async()=>{
 const {loadPreferenceForm}=require('./operations.js'),controls=[{},{}],pending=[];
 const form={dataset:{},isConnected:true,querySelectorAll:()=>controls};let value;
 const first=loadPreferenceForm(form,()=>new Promise(r=>pending.push(r)),p=>value=p.mode,()=>{});
 assert.ok(controls.every(c=>c.disabled));assert.notEqual(form.dataset.npOpLoaded,'true');
 const second=loadPreferenceForm(form,()=>new Promise(r=>pending.push(r)),p=>value=p.mode,()=>{});
 pending[1]({mode:'immediate'});await second;pending[0]({mode:'off'});await first;
 assert.equal(value,'immediate');assert.equal(form.dataset.npOpLoaded,'true');assert.ok(controls.every(c=>!c.disabled));
 await loadPreferenceForm(form,async()=>{throw Error('offline')},()=>{},()=>{});
 assert.ok(controls.every(c=>c.disabled));assert.notEqual(form.dataset.npOpLoaded,'true');
});

test('settings destinations preserve support context and reject external URLs',()=>{
 const {settingsDestination}=require('./operations.js');
 assert.equal(settingsDestination('/sites/51?tab=ssl','/support/customers/10/activity'),'/support/customers/10/sites/51?tab=ssl');
 assert.equal(settingsDestination('/subscriptions/42?tab=backups','/support/customers/10/activity'),'/support/customers/10/subscriptions/42?tab=backups');
 assert.equal(settingsDestination('/tools-settings/mail','/support/customers/10/activity'),'/tools-settings/mail');
 assert.equal(settingsDestination('/sites/51?tab=mail','/activity'),'/sites/51?tab=mail');
 for(const value of ['https://evil.example/','//evil.example/','/\\evil.example/','javascript:alert(1)','//',''])assert.equal(settingsDestination(value,'/activity'),'');
});

test('poller preserves authentication failure identity for visible sign-in guidance',async()=>{
 const x=setup();let status;x.env.load=async()=>{throw Object.assign(Error('Session expired'),{status:401})};x.env.error=(failed,cause)=>{if(failed)status=cause?.status};
 x.poller.mount('all',0);await new Promise(r=>setImmediate(r));assert.equal(status,401);assert.equal(x.rendered.length,0);x.poller.stop();
});
