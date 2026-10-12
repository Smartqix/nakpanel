// Read-only regression checks against an existing active database.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
(async()=>{
  const base=process.env.NAKPANEL_TEST_BASE_URL;
  const site=process.env.NAKPANEL_TEST_SITE_ID;
  const id=process.env.NAKPANEL_TEST_DATABASE_ID;
  assert(base && site && id,'base URL, site ID and database ID are required');
  const browser=await chromium.launch({channel:'chrome',headless:true});
  try {
    async function login(context) {
      const page=await context.newPage();
      await page.goto(base+'/login');
      await page.locator('[name=email]').fill(process.env.NAKPANEL_TEST_EMAIL || 'admin@nakpanel.test');
      await page.locator('[name=password]').fill(process.env.NAKPANEL_TEST_PASSWORD || 'NakpanelAdmin!2026');
      await page.locator('button[type=submit]').click();
      await page.waitForURL('**/dashboard');
      return page;
    }
    const context=await browser.newContext({ignoreHTTPSErrors:true});
    const page=await login(context);
    let checks=0;
    await page.route('**/sites/'+site+'/databases/status',async route=>{
      checks++;
      if (checks===1) await route.fulfill({status:503,body:'Temporarily unavailable'});
      else await route.continue();
    });
    await page.goto(base+'/sites/'+site+'?tab=databases');
    await page.waitForFunction(id=>document.querySelector('[data-np-db-id="'+id+'"] .np-domain-db-state small')?.textContent==='Ready to connect',id);
    assert(checks>=2);
    console.log('PASS status refresh recovered from HTTP 503');
    const details=await (await context.request.get(base+'/databases/'+id+'/connection')).json();
    assert(details.database);
    async function openManager() {
      const manager=await Promise.all([context.waitForEvent('page'),page.locator('[data-np-db-id="'+id+'"]').getByRole('button',{name:'Open phpMyAdmin'}).click()]).then(v=>v[0]);
      await manager.waitForLoadState('networkidle');
      assert((await manager.locator('body').innerText()).includes('Database: '+details.database));
      return manager;
    }
    const first=await openManager();
    const second=await openManager();
    const prefix=manager=>{const u=new URL(manager.url());return u.origin+u.pathname.split('/').slice(0,3).join('/')+'/';};
    const firstURL=prefix(first), secondURL=prefix(second);
    assert.notEqual(firstURL,secondURL);
    const other=await browser.newContext({ignoreHTTPSErrors:true});
    await login(other);
    assert.equal((await other.request.get(firstURL)).status(),404);
    console.log('PASS copied manager URL denied to a different authenticated session');
    await first.goto(firstURL+'logout');
    await first.getByRole('button',{name:'End database session'}).click();
    await first.waitForURL('**/databases');
    assert.equal((await context.request.get(firstURL)).status(),404);
    assert.equal((await context.request.get(secondURL)).status(),200);
    console.log('PASS independent manager tabs and scoped logout');
    await second.goto(secondURL+'logout');
    await second.getByRole('button',{name:'End database session'}).click();
    await second.waitForURL('**/databases');
    await page.setViewportSize({width:390,height:844});
    await page.goto(base+'/sites/'+site+'?tab=databases');
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.screenshot({path:'/tmp/nakpanel-database-recheck-mobile.png',fullPage:true,animations:'disabled'});
    console.log('PASS mobile layout; no database data or passwords changed');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
