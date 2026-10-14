// Native browser acceptance. Destructive mode is restricted to new QA fixtures.
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const base = process.env.NAKPANEL_QA_URL;
const siteID = process.env.NAKPANEL_QA_SITE_ID;
const domain = process.env.NAKPANEL_QA_DOMAIN;
const perform = process.env.NAKPANEL_QA_REMOVE === '1';
if (!base || !/^\d+$/.test(siteID || '') || !domain || (perform && !/^(removal-[a-z0-9-]+\.nakpanel\.com|addon-\d+-\d+\.test)$/.test(domain))) {
  throw new Error('Exact QA URL, site ID and authorized fixture domain are required');
}
let browser;
(async () => {
  browser = await chromium.launch({channel:'chrome', headless:true});
  const context = await browser.newContext({ignoreHTTPSErrors:true, viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto(`${base}/login`);
  await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL || 'admin@nakpanel.test');
  await page.locator('[name=password]').fill(process.env.NAKPANEL_QA_PASSWORD || 'NakpanelAdmin!2026');
  await page.getByRole('button', {name:/sign in/i}).click();
  await page.waitForURL(url => !url.pathname.endsWith('/login'));
  for (const size of [{width:1440,height:1000},{width:390,height:844}]) {
    await page.setViewportSize(size);
    await page.goto(`${base}/sites/${siteID}`);
    await page.locator('[data-np-removal-open]').first().evaluate(e => e.closest('details').open = true);
    await page.locator('[data-np-removal-open]').first().click();
    const dialog = page.locator('#np-site-removal-dialog');
    await dialog.locator('[name=confirm_domain]').waitFor();
    assert.equal(await dialog.locator('[name=delete_database_ids]:checked').count(), 0);
    assert.equal(await dialog.locator('.np-removal-dialog-cancel').evaluate(e => e === document.activeElement), true);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.keyboard.press('Escape'); await dialog.waitFor({state:'hidden'});
  }
  if (perform) {
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('[data-np-removal-open]').first().evaluate(e => e.closest('details').open = true);
    await page.locator('[data-np-removal-open]').first().click();
    const dialog = page.locator('#np-site-removal-dialog');
    await dialog.locator('[name=confirm_domain]').fill(domain);
    if (await dialog.locator('[name=include_children]').count()) await dialog.locator('[name=include_children]').check();
    await dialog.locator('[name=acknowledge_permanent]').check();
    const completed = page.waitForURL(url => url.searchParams.get('notice') === 'website-removed', {timeout:300000});
    await dialog.getByRole('button', {name:'Remove website', exact:true}).click();
    await completed;
    assert.ok((await page.locator('body').innerText()).includes(`${domain} was removed.`));
  }
  assert.deepEqual(errors, []);
  await browser.close();
  console.log('Desktop/mobile removal dialog, default retention, keyboard and completion checks passed.');
})().catch(async error => { if (browser) await browser.close(); console.error(error); process.exitCode=1; });
