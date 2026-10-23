// Opt-in local fixture only. Start TestOperationsBrowserPreview first.
const assert=require('node:assert/strict');
const {chromium}=require(process.env.NP_PLAYWRIGHT_MODULE||'playwright');
const base=new URL(process.env.NP_OPERATIONS_PREVIEW_URL);
if(!['localhost','127.0.0.1','[::1]'].includes(base.hostname))throw Error('Loopback preview required');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.NP_CHROME_BINARY,headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'}),errors=[],received=[];
  page.on('pageerror',e=>errors.push(e.message));let resultsReady=false;
  const results=Array.from({length:12},(_,n)=>({id:100+n,cursor:11+n,kind:['task.succeeded','task.cancelled','task.failed'][n%3],trigger:'manual',operation_kind:'create_backup',operation_id:41,summary:`Fixture task ${n+1} ${['completed','cancelled','failed'][n%3]}`}));
  await page.route('**/operations/events?*',route=>{const after=Number(new URL(route.request().url()).searchParams.get('after'));received.push(after);return route.fulfill({json:{events:resultsReady?results:[],cursor:resultsReady?22:10,more:false}})});
  const firstFeed=page.waitForResponse(r=>r.url().includes('/operations/events?'));
  await page.goto(new URL('/activity',base).href);
  await firstFeed;
  await page.waitForFunction(()=>document.querySelector('[data-np-op-status]').textContent.includes('Last checked'));

  resultsReady=true;
  await page.evaluate(()=>{document.querySelector('[data-np-op-status]').remove();document.querySelector('[data-np-operations-shell]').dataset.npOperationsCursor='99';history.pushState({},'', '/sites/51?tab=mail');window.NakpanelUI.lifecycle.mount(document)});
  await page.locator('[data-np-op-result-id]').nth(11).waitFor();
  assert.equal(received.at(-1),10,'navigation skipped unconsumed results');
  assert.equal(await page.locator('[data-np-op-result-id]').count(),12);
  await page.evaluate(()=>{document.querySelector('[data-np-operations-shell]').dataset.npOperationsCursor='1';history.pushState({},'', '/activity?tab=tasks');window.NakpanelUI.lifecycle.mount(document)});
  await page.waitForFunction(()=>document.querySelectorAll('[data-np-op-result-id]').length===12);
  await page.waitForTimeout(100);
  assert.equal(received.at(-1),22,'cached fragment rewound the consumed cursor');
  assert.equal(await page.locator('[data-np-op-result-id]').count(),12);
  if(process.env.NP_OPERATIONS_SCREENSHOT_DIR)await page.screenshot({path:process.env.NP_OPERATIONS_SCREENSHOT_DIR+'/desktop-results.png'});
  await page.setViewportSize({width:390,height:844});
  await page.waitForTimeout(400);
  if(process.env.NP_OPERATIONS_SCREENSHOT_DIR)await page.screenshot({path:process.env.NP_OPERATIONS_SCREENSHOT_DIR+'/mobile-results.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);

  await page.evaluate(()=>{const shell=document.querySelector('[data-np-operations-shell]');shell.dataset.npOperationsScope='resource_kind=customer&resource_id=99';shell.dataset.npOperationsCursor='99';history.pushState({},'', '/support/customers/99/activity');window.NakpanelUI.lifecycle.mount(document)});
  assert.equal(await page.locator('[data-np-op-result-id]').count(),0,'results from a previous resource scope remained visible');
  let release;const gate=new Promise(r=>release=r);
  await page.route('**/operations/preferences',async route=>{if(route.request().method()==='GET'){await gate;return route.fulfill({json:{email_mode:'digest'}})}return route.fulfill({status:204})});
  await page.route('**/operations/delivery-policy',async route=>{if(route.request().method()==='GET'){await gate;return route.fulfill({json:{enabled:true,smtp_configured:false}})}return route.fulfill({status:204})});
  await page.goto(new URL('/activity?tab=preferences',base).href);
  const pref=page.locator('[data-np-op-preferences]'),policy=page.locator('[data-np-op-delivery-policy]');
  assert.equal(await pref.locator('select').isDisabled(),true);assert.equal(await pref.locator('button[type=submit]').isDisabled(),true);assert.equal(await policy.locator('input[name=enabled]').isDisabled(),true);
  release();await pref.locator('select:enabled').waitFor();await policy.locator('input[name=enabled]:enabled').waitFor();
  assert.equal(await pref.locator('select').inputValue(),'digest');
  await pref.locator('select').selectOption('off');await policy.locator('button[type=submit]').click();await policy.getByText('Server policy saved.',{exact:true}).waitFor();
  assert.equal(await pref.locator('select').inputValue(),'off','policy reload overwrote personal edits');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({errors,terminalResults:12,cursorPreserved:true,replayDeduplicated:true,preferencesLoadingGuard:true,mobileOverflow:false}));
 } finally {await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
