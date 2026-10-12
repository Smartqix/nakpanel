// Runs only invalid-domain probes; never provisions a website.
const assert = require('node:assert/strict');
const { chromium } = require(process.env.NAKPANEL_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const base = process.env.NAKPANEL_PANEL_URL;
  const subscription = process.env.NAKPANEL_SUBSCRIPTION_ID;
  assert(base && subscription && process.env.NAKPANEL_TEST_PASSWORD, 'Set panel URL, subscription ID and test credentials');
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base + '/login');
    await page.locator('[name=email]').fill(process.env.NAKPANEL_TEST_EMAIL);
    await page.locator('[name=password]').fill(process.env.NAKPANEL_TEST_PASSWORD);
    await page.locator('button[type=submit]').click();
    await page.waitForURL('**/dashboard');
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(base + '/subscriptions/' + subscription);
      await page.getByRole('button', { name: 'Add Domain', exact: true }).click();
      const form = page.locator('form[action="/sites"]');
      await form.locator('[name=subscription_id]').selectOption(subscription);
      await form.locator('[name=domain]').fill('invalid/domain');
      const responsePromise = page.waitForResponse(r => r.url() === base + '/sites' && r.request().method() === 'POST');
      // Bypass native domain validation only for this non-mutating diagnostic probe.
      await form.evaluate(f => f.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
      const response = await responsePromise;
      assert.match(response.request().headers()['content-type'], /^application\/x-www-form-urlencoded/);
      assert.equal(new URLSearchParams(response.request().postData()).get('subscription_id'), subscription);
      assert.equal(response.status(), 400);
      assert.match((await response.json()).error, /domain/i);
      assert.doesNotMatch((await response.json()).error, /no active subscription/i);
      await page.waitForFunction(() => !document.querySelector('[data-np-create-submit]').disabled);
      assert.equal(await form.locator('[name=subscription_id]').inputValue(), subscription);
      assert.equal(await form.locator('[name=domain]').inputValue(), 'invalid/domain');
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({ path: '/tmp/nakpanel-site-form-' + width + '.png', fullPage: true });
      console.log('PASS', width, 'subscription preserved; domain validation reached; inline recovery works');
    }
    assert.deepEqual(errors, []);
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
