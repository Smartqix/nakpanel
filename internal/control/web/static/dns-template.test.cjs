const test=require('node:test');
const assert=require('node:assert/strict');
const {pending}=require('./dns-template.js');
test('DNS progress stops only at authoritative outcomes',()=>{
  assert.equal(pending('pending'),true);assert.equal(pending('running'),true);
  for(const value of ['active','partial','failed','stale','preview'])assert.equal(pending(value),false);
});
