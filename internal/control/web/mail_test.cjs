const {test}=require('node:test');
const assert=require('node:assert/strict');
const {mailAddressMatches,createMailConnectionLoader}=require('./static/mail.js');
test('mail search matches complete addresses case-insensitively',()=>{
 assert.equal(mailAddressMatches('Admin@example.test',' ADMIN '),true);
 assert.equal(mailAddressMatches('Admin@example.test','missing'),false);
 assert.equal(mailAddressMatches('Admin@example.test',''),true);
});
test('late connection responses cannot overwrite another mailbox or a closed dialog',async()=>{
 const pending=[],seen=[];
 const loader=createMailConnectionLoader({request:()=>new Promise(resolve=>pending.push(resolve)),show:v=>seen.push(v),error:e=>seen.push(e)});
 const first=loader.load('first'),second=loader.load('second');
 pending[1]('second mailbox');await second;
 pending[0]('first mailbox');await first;
 assert.deepEqual(seen,['second mailbox']);
 const third=loader.load('third');loader.stop();pending[2]('closed');await third;
 assert.deepEqual(seen,['second mailbox']);
});
