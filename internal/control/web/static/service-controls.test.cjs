const test=require('node:test');
const assert=require('node:assert/strict');
const {serviceActions,serviceProgress,createServiceTracker}=require('./service-controls.js');
test('service controls follow state and use only supported commands',()=>{
 const running={id:'web',available:true,active_state:'active',allowed_actions:['reload','restart','start','stop','reboot']};
 assert.deepEqual(serviceActions(running),['reload','restart','stop']);
 assert.deepEqual(serviceActions({...running,active_state:'inactive'}),['start']);
 assert.deepEqual(serviceActions({...running,available:false}),[]);
 assert.deepEqual(serviceActions({...running,id:'php-8.2'}),[]);
});
test('progress names real stages and keeps failed commands distinct from service health',()=>{
 assert.deepEqual(serviceProgress({action:'restart',status:'running',stage:'verifying'}),{busy:true,label:'Verifying',tone:'run'});
 assert.equal(serviceProgress({action:'stop',status:'running'}).label,'Stopping');
 assert.equal(serviceProgress({action:'stop',status:'succeeded'}).label,'Stop completed');
 assert.equal(serviceProgress({status:'failed'}).busy,false);
 assert.equal(serviceProgress({status:'unknown'}).busy,true);
});
test('an accepted action reconciles by operation identity and survives fast completion',async()=>{
 let data=[],rendered;const tracker=createServiceTracker({load:async()=>data,render:items=>rendered=items,isCurrent:()=>true});
 tracker.pending('web','restart');tracker.accept('web',{operation_id:'op_new',task_id:42});
 data=[{service_id:'web',operation_id:'op_old',status:'succeeded',task_id:1}];await tracker.refresh();
 assert.equal(rendered.get('web').operation_id,'op_new');
 data=[{service_id:'web',operation_id:'op_new',status:'succeeded',task_id:42}];await tracker.refresh();
 assert.equal(rendered.get('web').status,'succeeded');assert.equal(rendered.get('web').task_id,42);
 tracker.destroy();
});
test('late responses cannot repaint a newer mount or overwrite a just-accepted action',async()=>{
 const pending=[],renders=[];const tracker=createServiceTracker({load:()=>new Promise(r=>pending.push(r)),render:items=>renders.push(items),isCurrent:()=>true});
 const old=tracker.refresh();tracker.pending('web','restart');tracker.accept('web',{operation_id:'op_new',task_id:42});
 const fresh=tracker.refresh();pending[1]([{service_id:'web',operation_id:'op_new',status:'running'}]);await fresh;
 pending[0]([{service_id:'web',operation_id:'op_old',status:'succeeded'}]);await old;
 assert.equal(renders.at(-1).get('web').operation_id,'op_new');
 const last=tracker.refresh();const count=renders.length;tracker.destroy();pending[2]([]);await last;assert.equal(renders.length,count);
});
test('network uncertainty is retained without replay; confirmed rejection releases only that pending action',async()=>{
 let calls=0,rendered;const tracker=createServiceTracker({load:async()=>{calls++;return []},render:items=>rendered=items,isCurrent:()=>true});
 tracker.pending('web','restart');tracker.reject('web',false);await tracker.refresh();
 assert.equal(rendered.get('web').status,'unknown');assert.equal(calls,1);
 tracker.clearUncertain();assert.equal(rendered.has('web'),false);
 tracker.pending('web','restart');tracker.reject('web',true);assert.equal(rendered.has('web'),false);tracker.destroy();
});
