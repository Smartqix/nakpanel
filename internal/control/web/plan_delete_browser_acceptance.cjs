// Opt-in loopback fixture only: start TestPlanDeletionBrowserPreview first.
const assert = require('node:assert/strict');
const {chromium} = require(process.env.NP_PLAYWRIGHT_MODULE || 'playwright');
const base = new URL(process.env.NP_PLAN_DELETE_PREVIEW_URL);
if (!['localhost','127.0.0.1','[::1]'].includes(base.hostname)) throw Error('Loopback fixture required');
(async () => {
  const browser = await chromium.launch({executablePath:process.env.NP_CHROME_BINARY,headless:true});
  try {
    for (const scenario of [{width:1440,native:false},{width:390,native:false},{width:1440,native:true}]) {
      const page = await browser.newPage({viewport:{width:scenario.width,height:1000},reducedMotion:'reduce'});
      const errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      await page.request.post(new URL('/__reset',base).href);
      await page.goto(new URL('/service-plans'+(scenario.native?'?native=1':''),base).href);
      const remove=page.getByRole('button',{name:'Delete Unused list plan',exact:true});
      assert.equal(await remove.isEnabled(),true);
      assert.equal(await page.getByRole('button',{name:'Retire',exact:true}).isDisabled(),true);
      assert.equal(await page.getByRole('button',{name:'Delete Used plan',exact:true}).count(),0);
      await remove.click();
      await page.locator('[data-np-confirmation-cancel]').click();
      assert.deepEqual(await (await page.request.get(new URL('/__state',base).href)).json(),{});
      assert.equal(await remove.isEnabled(),true);
      if (!scenario.native) {
        // A failed request must restore the external row button for a retry.
        await page.route('**/plans/42/delete',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({ok:false,error:'The plan has subscriptions.'})}),{times:1});
        await remove.click();await page.locator('[data-np-confirmation-accept]').click();
        await page.locator('[data-np-form-error]').waitFor({state:'visible'});
        assert.equal(await remove.isEnabled(),true);
      }
      let release;
      const gate=new Promise(resolve=>{release=resolve;});
      await page.route('**/plans/42/delete',async route=>{await gate;await route.continue();},{times:1});
      const request=page.waitForRequest(r=>new URL(r.url()).pathname==='/plans/42/delete');
      await remove.click();await page.locator('[data-np-confirmation-accept]').click({noWaitAfter:true});
      await request;
      if (!scenario.native) assert.equal(await remove.isDisabled(),true,'pending deletion must disable its external submit button');
      release();
      await page.getByText('Plan deleted.',{exact:true}).waitFor();
      assert.equal(await page.getByRole('button',{name:'Delete Unused list plan',exact:true}).count(),0);
      await page.goto(new URL('/service-plans/43'+(scenario.native?'?native=1':''),base).href);
      // Deletion must not validate or submit the unrelated plan editor.
      await page.locator('[data-np-plan-editor] input[name="name"]').fill('');
      await page.getByRole('button',{name:'Delete Unused detail plan',exact:true}).click();
      await page.locator('[data-np-confirmation-accept]').click();
      await page.getByText('Plan deleted.',{exact:true}).waitFor();
      assert.deepEqual(await (await page.request.get(new URL('/__state',base).href)).json(),{'42':1,'43':1});
      assert.deepEqual(errors,[]);
      await page.close();
      console.log(`PASS: ${scenario.width}px ${scenario.native?'native navigation':'instant navigation'}; cancel, retry, pending state and exactly one deletion per plan`);
    }
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
