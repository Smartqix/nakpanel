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
