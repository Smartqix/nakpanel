const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

function run(enctype='application/x-www-form-urlencoded', failure=null, busy=false) {
 const source=fs.readFileSync(__dirname+'/static/app.js','utf8');
 const start=source.indexOf('  async function submitDialogForm(');
 const end=source.indexOf('\n  function ',start+1);
 const requests=[], errors=[], states=[], navigation=[];
 const form={action:'https://panel.test/sites/1/dns-records',enctype,dataset:{},getAttribute:()=>busy?'true':null};
 class Fields extends FormData {constructor(){super();this.append('host','test');this.append('value','192.0.2.1');}}
 const context=vm.createContext({FormData:Fields,URLSearchParams,clearSitePolicyError:()=>{},
  showSitePolicyError:(form,error)=>errors.push(error),
  window:{NakpanelUI:{setBusy:(form,value)=>states.push(value)},location:{assign:url=>navigation.push(url),reload:()=>navigation.push('reload')}},
  fetch:async(url,options)=>{requests.push(options);if(failure)throw failure;return {redirected:true,url:'https://panel.test/sites/1?tab=dns'};}
 });
 vm.runInContext(source.slice(start,end),context);
 return {requests,errors,states,navigation,result:context.submitDialogForm(form,{name:'confirm',value:'yes'})};
}

test('ordinary dialog mutations preserve URL-encoded ParseForm compatibility',async()=>{
 const f=run();await f.result;
 assert.ok(f.requests[0].body instanceof URLSearchParams);
 assert.equal(f.requests[0].body.get('host'),'test');
 assert.equal(f.requests[0].body.get('confirm'),'yes');
});
test('certificate upload keeps multipart fields and files',async()=>{
 const f=run('multipart/form-data');await f.result;
 assert.ok(f.requests[0].body instanceof FormData);
});
test('validation uses JSON instead of consuming a one-shot error cookie',async()=>{
 const failure=Object.assign(new Error('Invalid record'),{payload:{error:'Invalid record',field:'value'}});
 const f=run(undefined,failure);await f.result;
 assert.equal(f.requests[0].headers['X-Nakpanel-SPA'],'true');
 assert.equal(f.errors[0].field,'value');
 assert.deepEqual(f.navigation,[]);
 assert.deepEqual(f.states,[true,false]);
});
test('an already pending dialog cannot submit twice',async()=>{
 const f=run(undefined,null,true);await f.result;
 assert.equal(f.requests.length,0);
});
