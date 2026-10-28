(function(root){'use strict';
 const verbs={reload:'Reload',restart:'Restart',start:'Start',stop:'Stop'};
 function serviceActions(service){
  if(!service?.available||!['web','dns','mail','php-8.3','php-8.4','php-8.5'].includes(service.id))return [];
  return (service.allowed_actions||[]).filter(action=>Object.hasOwn(verbs,action)&&(service.active_state==='active'?action!=='start':action==='start'));
 }
 function serviceProgress(operation){
  const status=operation.status;
  if(status==='unknown')return {busy:true,label:'Check outcome',tone:'pend'};
  if(status==='submitting')return {busy:true,label:'Submitting',tone:'pend'};
  if(status==='pending'||status==='awaiting_confirmation')return {busy:true,label:'Queued',tone:'pend'};
  if(status==='running')return {busy:true,label:operation.stage==='verifying'?'Verifying':({reload:'Reloading',restart:'Restarting',start:'Starting',stop:'Stopping'}[operation.action]||'Working'),tone:'run'};
  return {busy:false,label:status==='succeeded'?(verbs[operation.action]||'Action')+' completed':status==='cancelled'?'Cancelled':'Action failed',tone:status==='succeeded'?'ok':'fail'};
 }
 function createServiceTracker(env){
  let version=0,controller,stopped=false,remote=new Map();const pending=new Map();
  function emit(){if(stopped||!env.isCurrent())return;const items=new Map(remote);pending.forEach((item,id)=>items.set(id,item));env.render(items)}
  function invalidate(){version++;controller?.abort()}
  return {
   pending(id,action){invalidate();pending.set(id,{service_id:id,action,status:'submitting'});emit()},
   accept(id,result){invalidate();pending.set(id,{...pending.get(id),...result,service_id:id,status:'pending'});emit()},
   reject(id,confirmed){invalidate();if(confirmed)pending.delete(id);else pending.set(id,{...pending.get(id),service_id:id,status:'unknown'});emit()},
   clearUncertain(){let count=0;pending.forEach((item,id)=>{if(item.status==='unknown'){pending.delete(id);count++}});emit();return count},
   async refresh(){invalidate();if(stopped||!env.isCurrent())return false;const ticket=version;controller=new AbortController();try{
    const items=await env.load(controller.signal);
    if(stopped||ticket!==version||!env.isCurrent())return false;
    remote=new Map();const known=new Set();for(const item of items){if(!remote.has(item.service_id))remote.set(item.service_id,item);known.add(item.operation_id)}
    pending.forEach((item,id)=>{if(item.operation_id&&known.has(item.operation_id))pending.delete(id)});emit();return true;
   }catch(error){if(!stopped&&ticket===version&&env.isCurrent()&&error.name!=='AbortError')env.error?.(error);return false}},
   render:emit,
   destroy(){stopped=true;invalidate();pending.clear();remote.clear()}
  };
 }
 const api={serviceActions,serviceProgress,createServiceTracker};
 if(typeof module==='object'&&module.exports)module.exports=api;else root.NakpanelServices=api;
})(typeof window==='object'?window:globalThis);
