const test=require('node:test');
const assert=require('node:assert/strict');
const {createClient}=require('./static/interaction.js');
test('mutation requests use the server AJAX and CSRF contract',async()=>{
 let calls=0;
 const client=createClient({baseURL:'https://panel.test',csrf:()=> 'token',fetch:async(url,options)=>{
  calls++;assert.equal(options.headers.get('X-Nakpanel-SPA'),'true');
  assert.equal(options.headers.get('X-Nakpanel-CSRF'),'token');
  assert.equal(options.credentials,'same-origin');
  return new Response('{"ok":true}',{headers:{'Content-Type':'application/json'}});
 }});
 await client.fetch('/sites',{method:'POST',body:new URLSearchParams('domain=test')});
 assert.equal(calls,1);
 await assert.rejects(()=>client.fetch('https://outside.test',{method:'POST'}),/same-origin/);
 assert.equal(calls,1);
});
test('session and HTML errors are useful without exposing raw bodies',async()=>{
 for(const [status,expected] of [[401,/sign in/],[403,/403/],[404,/404/],[502,/502/]]){
  const client=createClient({baseURL:'https://panel.test',fetch:async()=>new Response('<html>secret</html>',{status})});
  await assert.rejects(()=>client.fetch('/status'),expected);
 }
});
test('HTML partial refresh is explicitly supported',async()=>{
 const client=createClient({baseURL:'https://panel.test',fetch:async()=>new Response('<main>updated</main>')});
 const result=await client.fetch('/sites',{headers:{Accept:'text/html'}});
 assert.match(await result.text(),/updated/);
});
test('network uncertainty never automatically replays a mutation',async()=>{
 let calls=0;
 const client=createClient({baseURL:'https://panel.test',fetch:async()=>{calls++;throw new TypeError('network');}});
 await assert.rejects(()=>client.fetch('/sites',{method:'POST'}),/Check status/);
 assert.equal(calls,1);
});
test('busy forms preserve controls that were already disabled by policy',()=>{
 const controls=[{disabled:false,matches:()=>true},{disabled:true,matches:()=>true}];
 const form={elements:controls,setAttribute:()=>{}};
 const client=createClient({baseURL:'https://panel.test'});
 client.setBusy(form,true); client.setBusy(form,true);
 assert.deepEqual(controls.map(x=>x.disabled),[true,true]);
 client.setBusy(form,false);
 assert.deepEqual(controls.map(x=>x.disabled),[false,true]);
});
test('structured validation errors retain field information for inline recovery',async()=>{
 const client=createClient({baseURL:'https://panel.test',fetch:async()=>new Response(JSON.stringify({ok:false,error:'Memory exceeds the plan.',field:'site_php_memory'}),{status:400,headers:{'Content-Type':'application/json'}})});
 await assert.rejects(()=>client.fetch('/sites/1/php-settings',{method:'POST'}),error=>{
  assert.equal(error.message,'Memory exceeds the plan.');
  assert.equal(error.payload.field,'site_php_memory');
  assert.equal(error.status,400);
  return true;
 });
});
test('progressive dialog forms can follow same-origin fallback redirects without replay',async()=>{
 let calls=0;
 const response=new Response('<main>Saved</main>',{headers:{'Content-Type':'text/html'}});
 Object.defineProperties(response,{redirected:{value:true},url:{value:'https://panel.test/sites/1?tab=dns'}});
 const client=createClient({baseURL:'https://panel.test',fetch:async(_,options)=>{
  calls++;assert.equal(options.headers.get('X-Nakpanel-SPA'),'false');return response;
 }});
 assert.equal(await client.fetch('/sites/1/dns-records',{method:'POST',headers:{'X-Nakpanel-SPA':'false'},allowPageResponse:true}),response);
 assert.equal(calls,1);
});
test('progressive responses reject cross-origin navigation and login redirects',async()=>{
 for(const url of ['https://outside.test/sites/1','https://panel.test/login']){
  const response=new Response('');Object.defineProperties(response,{redirected:{value:true},url:{value:url}});
  const client=createClient({baseURL:'https://panel.test',fetch:async()=>response});
  await assert.rejects(()=>client.fetch('/operation',{method:'POST',allowPageResponse:true}));
 }
});
test('expired sessions carry a confirmed 401 instead of mutation uncertainty',async()=>{
 for(const redirected of [false,true]){
  const response=new Response('',{status:redirected?200:401});
  Object.defineProperties(response,{redirected:{value:redirected},url:{value:'https://panel.test/login'}});
  const client=createClient({baseURL:'https://panel.test',fetch:async()=>response});
  await assert.rejects(()=>client.fetch('/sites',{method:'POST'}),error=>{
   assert.equal(error.status,401);assert.match(error.message,/sign in/);return true;
  });
 }
});
test('an outside login redirect cannot be classified as a confirmed rejection',async()=>{
 const response=new Response('');Object.defineProperties(response,{redirected:{value:true},url:{value:'https://outside.test/login'}});
 const client=createClient({baseURL:'https://panel.test',fetch:async()=>response});
 await assert.rejects(()=>client.fetch('/sites',{method:'POST'}),error=>{
  assert.equal(error.status,undefined);assert.match(error.message,/outside this panel/);return true;
 });
});

test('busy state follows form ownership for external submit buttons',()=>{
 const external={disabled:false,matches:()=>true},alreadyDisabled={disabled:true,matches:()=>true},foreignChild={disabled:false,matches:()=>true},field={disabled:false,matches:()=>false};
 const form={elements:[external,alreadyDisabled,field],querySelectorAll:()=>[foreignChild],setAttribute(){}};
 const client=createClient({baseURL:'https://panel.test'});
 client.setBusy(form,true);
 assert.equal(external.disabled,true,'an external Delete button must be disabled while its form submits');
 assert.equal(foreignChild.disabled,false,'submitting bulk actions must not change a row button owned by another form');
 assert.equal(field.disabled,false);
 client.setBusy(form,false);
 assert.equal(external.disabled,false);
 assert.equal(alreadyDisabled.disabled,true);
});
