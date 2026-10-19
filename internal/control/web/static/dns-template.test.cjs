const test=require('node:test');
const assert=require('node:assert/strict');
const {pending}=require('./dns-template.js');
test('DNS saves retain their tab and previews open the apply section',()=>{
  const {targetURL}=require('./dns-template.js');
  const current='https://panel.test/tools-settings/dns#dns-policy';
  assert.equal(targetURL('https://panel.test/tools-settings/dns?notice=saved',current).hash,'#dns-policy');
  assert.equal(targetURL('https://panel.test/tools-settings/dns?run=4',current).hash,'#dns-sync');
});
test('DNS form enhancement sends fields in the format accepted by Go ParseForm',()=>{
  const {formBody}=require('./dns-template.js');
  const data=new FormData();data.set('primary_nameserver','ns1.example.com');
  assert.equal(formBody(data).toString(),'primary_nameserver=ns1.example.com');
});
test('DNS progress stops only at authoritative outcomes',()=>{
  assert.equal(pending('pending'),true);assert.equal(pending('running'),true);
  for(const value of ['active','partial','failed','stale','preview'])assert.equal(pending(value),false);
});
test('DNS enhanced forms accept the existing HTML redirect contract',async()=>{
  const vm=require('node:vm');
  const fs=require('node:fs');
  const {createClient}=require('./interaction.js');
  let submit,assigned;
  const error={hidden:true,dataset:{},focus(){}};
  const button={disabled:false};
  const form={action:'https://panel.test/tools-settings/dns/sync/preview',dataset:{},isConnected:true,
    data:new FormData(),matches(){return false;},querySelector(){return error;},
    querySelectorAll(){return [button];},addEventListener(type,callback){if(type==='submit')submit=callback;}};
  form.data.set('scope','all');
  const workspace={querySelectorAll(selector){return selector.startsWith('form')?[form]:[];}};
  const current='https://panel.test/tools-settings/dns#dns-policy';
  const client=createClient({baseURL:current,csrf:()=> 'csrf',fetch:async()=>({ok:true,status:200,redirected:true,url:'https://panel.test/tools-settings/dns?run=4',headers:new Headers({'Content-Type':'text/html'})})});
  client.lifecycle={onMount(){},signal:()=>new AbortController().signal};
  vm.runInNewContext(fs.readFileSync(require.resolve('./dns-template.js'),'utf8'),{
    window:{NakpanelUI:client,location:{href:current,origin:'https://panel.test',assign(value){assigned=value;}},addEventListener(){}},
    document:{readyState:'complete',querySelector(){return workspace;}},
    URL,URLSearchParams,AbortController,FormData:class{constructor(form){return form.data;}}
  });
  await submit({preventDefault(){},stopPropagation(){}});
  assert.equal(assigned,'https://panel.test/tools-settings/dns?run=4#dns-sync',error.textContent);
  assert.equal(error.hidden,true);
  assert.equal(button.disabled,false);
});
