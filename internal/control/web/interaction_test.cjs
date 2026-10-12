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
 const controls=[{disabled:false},{disabled:true}];
 const form={querySelectorAll:()=>controls,setAttribute:()=>{}};
 const client=createClient({baseURL:'https://panel.test'});
 client.setBusy(form,true); client.setBusy(form,true);
 assert.deepEqual(controls.map(x=>x.disabled),[true,true]);
 client.setBusy(form,false);
 assert.deepEqual(controls.map(x=>x.disabled),[false,true]);
});
