const {test}=require('node:test');const assert=require('node:assert/strict');const {createClient}=require('./interaction.js');
test('bodyless acknowledgements and accepted checks still use CSRF',async()=>{for(const status of [204,202]){let options;const client=createClient({baseURL:'https://panel.example',csrf:()=> 'token',fetch:async(_u,o)=>{options=o;return new Response(null,{status})}});const result=await client.fetch('/api/workspace/operations/issues/1/verify',{method:'POST'});assert.equal(result.status,status);assert.equal(options.headers.get('X-Nakpanel-CSRF'),'token')}});

test('repeated fragment mounts keep one timer and abort previous requests',async()=>{
 const {createOperationsPoller}=require('./operations.js'),timers=new Map(),signals=[];let id=0,hidden=false;
 const poller=createOperationsPoller({hidden:()=>hidden,setTimeout:fn=>{timers.set(++id,fn);return id},clearTimeout:key=>timers.delete(key),load:async signal=>{signals.push(signal);return {cursor:1,page:{},events:[]}},render(){},error(){}});
 for(let i=0;i<5;i++){poller.mount('page'+i,0,'actor:1|scope');await new Promise(r=>setImmediate(r));assert.equal(timers.size,1)}
 assert.ok(signals.slice(0,-1).every(s=>s.aborted));hidden=true;poller.visibility();assert.equal(timers.size,0);poller.stop();
});

test('receipt orchestration deduplicates clicks and never invents an unread count',async()=>{
 const {createNotificationActions}=require('./notifications.js');let release,calls=0,count=3,cleared=0,identity='actor:1|all';const pending=[],success=[];
 const actions=createNotificationActions({identity:()=>identity,mutate:async()=>{calls++;await new Promise(r=>release=r)},pending:(...args)=>pending.push(args),clearError:()=>cleared++,success:(...args)=>success.push(args),refresh:async()=>{count=1},error(){}});
 const first=actions.run('all','read-all'),second=actions.run('all','read-all');assert.equal(calls,1);assert.equal(count,3);release();await Promise.all([first,second]);assert.equal(count,1);assert.equal(success.length,1);assert.equal(cleared,1);assert.deepEqual(pending,[["all",true],["all",false]]);
});

test('failed receipts retain state and retry locally; old scope results are ignored',async()=>{
 const {createNotificationActions}=require('./notifications.js');let identity='one',release,success=0,error,retry;
 const actions=createNotificationActions({identity:()=>identity,mutate:async()=>{throw Error('offline')},pending(){},success(){success++},refresh(){},error:(e,r)=>{error=e.message;retry=r}});
 assert.equal(await actions.run(1,'archive'),false);assert.equal(success,0);assert.equal(error,'offline');assert.equal(typeof retry,'function');
 const slow=createNotificationActions({identity:()=>identity,mutate:()=>new Promise(r=>release=r),pending(){},success(){success++},refresh(){},error(){throw Error('stale error')}});
 const waiting=slow.run(1,'read');identity='two';release();await waiting;assert.equal(success,0);
});

test('notification detail marks read only after a current successful load',async()=>{
 const {loadNotificationDetail}=require('./notifications.js');let current=true,release,reads=0,renders=0,errors=0;
 const options={load:async()=>({id:1}),isCurrent:()=>current,render:()=>renders++,read:()=>reads++,error:()=>errors++};
 await loadNotificationDetail(options);assert.equal(reads,1);assert.equal(renders,1);
 await loadNotificationDetail({...options,load:async()=>{throw Object.assign(Error('Not found'),{status:404})}});assert.equal(reads,1);assert.equal(errors,1);
 const delayed=loadNotificationDetail({...options,load:()=>new Promise(r=>release=r)});current=false;release({id:2});await delayed;assert.equal(reads,1);assert.equal(renders,1);
});
