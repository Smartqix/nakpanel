const {test}=require('node:test');const assert=require('node:assert/strict');const {createClient}=require('./interaction.js');
test('bodyless acknowledgements and accepted checks still use CSRF',async()=>{for(const status of [204,202]){let options;const client=createClient({baseURL:'https://panel.example',csrf:()=> 'token',fetch:async(_u,o)=>{options=o;return new Response(null,{status})}});const result=await client.fetch('/api/workspace/operations/issues/1/verify',{method:'POST'});assert.equal(result.status,status);assert.equal(options.headers.get('X-Nakpanel-CSRF'),'token')}});

test('repeated fragment mounts keep one timer and abort previous requests',async()=>{
 const {createOperationsPoller}=require('./operations.js'),timers=new Map(),signals=[];let id=0,hidden=false;
 const poller=createOperationsPoller({hidden:()=>hidden,setTimeout:fn=>{timers.set(++id,fn);return id},clearTimeout:key=>timers.delete(key),load:async signal=>{signals.push(signal);return {cursor:1,page:{},events:[]}},render(){},error(){}});
 for(let i=0;i<5;i++){poller.mount('page'+i,0,'actor:1|scope');await new Promise(r=>setImmediate(r));assert.equal(timers.size,1)}
 assert.ok(signals.slice(0,-1).every(s=>s.aborted));hidden=true;poller.visibility();assert.equal(timers.size,0);poller.stop();
});
