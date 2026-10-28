// Focused, opt-in UI regressions against TestOperationsBrowserPreview.
const assert=require('node:assert/strict');
const {chromium}=require(process.env.NP_PLAYWRIGHT_MODULE||'playwright');
const base=new URL(process.env.NP_OPERATIONS_PREVIEW_URL);
if(!['localhost','127.0.0.1','[::1]'].includes(base.hostname))throw Error('Loopback preview required');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.NP_CHROME_BINARY,headless:true}),results=[];
 const issue={id:9,operation_id:0,resource:{kind:'site',id:51},resource_available:true,kind:'tls',condition:'certificate',title:'Certificate needs attention',target:'studio.example',summary:'Review certificate settings.',severity:'critical',state:'open',occurrences:1,observed_at:new Date().toISOString(),settings_url:'/sites/51?tab=ssl',settings_label:'Open SSL/TLS settings'};
 async function run(name,check){if(process.env.NP_OPERATIONS_UX_CASE&&!name.includes(process.env.NP_OPERATIONS_UX_CASE))return;const page=await browser.newPage();page.setDefaultTimeout(2000);const errors=[];page.on('pageerror',e=>errors.push(e.message));try{await check(page);assert.deepEqual(errors,[]);results.push({name,passed:true})}catch(e){results.push({name,passed:false,error:e.message})}finally{await page.close()}}
 async function fixture(page,{poll=false,detail=issue,denied=false,readFailure=false}={}){
  const posts=[];
  // Pause polling for SSR checks; otherwise use the real production row renderer.
  if(!poll)await page.route('**/api/workspace/operations?*',r=>r.abort());
  await page.route('**/api/workspace/operations/issues/9',r=>r.fulfill(denied?{status:404,json:{error:'Not found'}}:{json:detail}));
  await page.route('**/api/workspace/operations/notifications/17/read',r=>{posts.push(r.request().url());return r.fulfill({status:readFailure?503:204})});
  page.on('request',r=>{if(r.method()==='POST'&&!r.url().endsWith('/notifications/17/read'))posts.push('UNEXPECTED '+r.url())});
  return posts;
 }
 try {
  await run('SSR notification opening marks only its personal receipt read',async page=>{
   const posts=await fixture(page);await page.goto(new URL('/activity?tab=inbox',base).href);
   await page.locator('[data-np-notification-open="17"]').filter({visible:true}).first().click();await page.getByRole('button',{name:'Acknowledge',exact:true}).waitFor();
   await page.waitForTimeout(300);assert.deepEqual(posts,[new URL('/api/workspace/operations/notifications/17/read',base).href]);
  });
  await run('polled notification and quick inbox opening mark read',async page=>{
   const posts=await fixture(page,{poll:true});await page.goto(new URL('/activity?tab=inbox',base).href);
   await page.locator('[data-np-op-quick-inbox] button').first().waitFor({state:'attached'});
   await page.getByRole('button',{name:'Notifications',exact:false}).click();
   await page.locator('#np-op-inbox').locator('[data-np-notification-open="17"]').click();await page.getByRole('button',{name:'Acknowledge',exact:true}).waitFor();await page.waitForTimeout(100);
   assert.deepEqual(posts,[new URL('/api/workspace/operations/notifications/17/read',base).href]);
  });
  await run('task notification opening records read without issue mutations',async page=>{
   const posts=await fixture(page);await page.goto(new URL('/activity?tab=inbox&notification_task=1',base).href);
   await page.locator('[data-np-notification-open="17"]').filter({visible:true}).first().click();await page.getByRole('heading',{name:'Task attempts',exact:true}).waitFor();await page.waitForTimeout(100);
   assert.deepEqual(posts,[new URL('/api/workspace/operations/notifications/17/read',base).href]);
  });
  await run('closing before details load does not mark a notification read',async page=>{
   const posts=await fixture(page);let release;const gate=new Promise(r=>release=r);
   await page.route('**/api/workspace/operations/issues/9',async r=>{await gate;await r.fulfill({json:issue}).catch(()=>{})});
   await page.goto(new URL('/activity?tab=inbox',base).href);await page.locator('[data-np-notification-open="17"]').filter({visible:true}).first().click();
   await page.getByRole('button',{name:'Close activity details',exact:true}).click();release();await page.waitForTimeout(150);assert.deepEqual(posts,[]);
  });
  await run('issue settings link preserves customer support context',async page=>{
   await fixture(page);await page.goto(new URL('/support/customers/10/activity',base).href);
   await page.getByRole('button',{name:'Scheduled backup failed',exact:true}).click();await page.getByRole('button',{name:'Acknowledge',exact:true}).waitFor();
   const link=page.getByRole('link',{name:'Open SSL/TLS settings',exact:true});assert.equal(await link.count(),1);assert.equal(await link.getAttribute('href'),'/support/customers/10/sites/51?tab=ssl');
  });
  await run('removed and denied issue details expose no stale settings action or read receipt',async page=>{
   const posts=await fixture(page,{denied:true});await page.goto(new URL('/activity?tab=inbox',base).href);await page.locator('[data-np-notification-open="17"]').filter({visible:true}).first().click();await page.locator('[data-np-op-detail-body]').getByText('This resource is no longer available in your scope.',{exact:true}).waitFor();
   assert.equal(await page.locator('#np-operation-detail a').count(),0);assert.deepEqual(posts,[]);
  });
  await run('removed resource has an explicit unavailable settings state',async page=>{
   await fixture(page,{detail:{...issue,resource_available:false,settings_url:'',settings_label:'',settings_unavailable:'This resource has been removed. Its settings are unavailable.'}});await page.goto(new URL('/activity',base).href);await page.getByRole('button',{name:'Scheduled backup failed',exact:true}).click();await page.getByRole('button',{name:'Acknowledge',exact:true}).waitFor();
   assert.equal(await page.locator('#np-operation-detail a').count(),0);assert.equal(await page.getByText('This resource has been removed. Its settings are unavailable.',{exact:true}).count(),1);
  });
  await run('failed read receipt keeps issue open and reports that read was not saved',async page=>{
   const posts=await fixture(page,{readFailure:true});await page.goto(new URL('/activity?tab=inbox',base).href);await page.locator('[data-np-notification-open="17"]').filter({visible:true}).first().click();await page.getByRole('button',{name:'Acknowledge',exact:true}).waitFor();
   await page.waitForTimeout(200);assert.equal(posts.length,1);assert.match(await page.locator('[data-np-op-detail-status]').textContent(),/could not mark.*read/i);
  });
  console.log(JSON.stringify(results,null,2));if(results.some(r=>!r.passed))process.exitCode=1;
 } finally {await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
