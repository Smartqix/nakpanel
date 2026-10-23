// Owned loopback fixture: real navigation swaps the complete topbar fragment.
const assert=require('node:assert/strict');
const {chromium}=require(process.env.NP_PLAYWRIGHT_MODULE||'playwright');
const base=new URL(process.env.NP_OPERATIONS_PREVIEW_URL);
assert(['localhost','127.0.0.1','[::1]'].includes(base.hostname));
(async()=>{
 const browser=await chromium.launch({channel:'chrome',headless:true});
 try{
  const page=await browser.newPage({reducedMotion:'reduce'});let ready=false;const cursors=[],errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const events=Array.from({length:12},(_,n)=>({id:100+n,cursor:11+n,kind:'task.succeeded',trigger:'manual',operation_kind:'run_scheduled_task',operation_id:41,summary:'Fixture result '+n}));
  await page.route('**/operations/events?*',route=>{
   const after=Number(new URL(route.request().url()).searchParams.get('after'));cursors.push(after);
   return route.fulfill({json:{events:ready?events:[],cursor:ready?22:10,more:false}});
  });
  const first=page.waitForResponse(r=>r.url().includes('/operations/events?'));
  await page.goto(new URL('/activity?tab=tasks',base).href);await first;
  await page.waitForTimeout(200);ready=true;
  await page.locator('[data-np-op-result-id]').nth(11).waitFor();
  await page.evaluate(()=>window.__operationsDocument='same-document');
  const swap=page.waitForRequest(r=>r.headers()['x-nakpanel-fragment']==='main'&&new URL(r.url()).searchParams.get('tab')==='issues');
  await page.getByRole('link',{name:'Issues',exact:true}).click();await swap;
  await page.waitForURL(url=>url.searchParams.get('tab')==='issues');
  assert.equal(await page.evaluate(()=>window.__operationsDocument),'same-document');
  await page.waitForTimeout(200);
  assert.equal(await page.locator('[data-np-op-result-id]').count(),12,'actual topbar fragment replacement lost already consumed terminal results');
  assert.equal(cursors.at(-1),22,'fragment rewound the committed cursor');
  await page.locator('[data-np-op-dismiss-results]').click();
  await page.getByRole('link',{name:'Tasks',exact:true}).click();
  await page.waitForURL(url=>url.searchParams.get('tab')==='tasks');await page.waitForTimeout(200);
  assert.equal(await page.locator('[data-np-op-result-id]').count(),0,'dismissed results returned after fragment replacement');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({terminalResults:12,actualFragmentRetained:true,dismissalRetained:true,errors}));
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
