// Real installed application only: no network mocks or injected UI state.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const config = require('./qualification-browser-config.cjs');
const input = JSON.parse(fs.readFileSync(process.env.NAKPANEL_OPERATIONS_INPUT, 'utf8'));
const evidence = process.env.NAKPANEL_OPERATIONS_EVIDENCE;
const endpoint = '/api/workspace/operations';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(read, accept, label, seconds = 120) {
 const end = Date.now() + seconds * 1000;
 while (true) {
  const value = await read();
  if (accept(value)) return value;
  assert(Date.now() < end, 'Timed out: ' + label);
  await sleep(1000);
 }
}
(async () => {
 const cfg = config({NAKPANEL_QA_GUEST_IP: input.ip, NAKPANEL_QA_IGNORE_HTTPS_ERRORS: '1'});
 const browser = await chromium.launch(cfg.launch);
 const result = {passed: false, errors: []};
 try {
  const context = await browser.newContext({...cfg.context, viewport: {width: 1440, height: 1000}, reducedMotion: 'reduce'});
  const page = await context.newPage();
  page.on('pageerror', error => result.errors.push(error.message));
  page.setDefaultTimeout(30000);
  await page.goto(input.base + '/login');
  await page.locator('input[name=email]').fill(input.email);
  await page.locator('input[name=password]').fill(input.password);
  await page.locator('button[type=submit]').click();
  await page.waitForURL(url => url.pathname !== '/login');
  const cookie = (await context.cookies()).find(c => c.name === 'nakpanel_session');
  assert(cookie, 'Authenticated session required');
  const csrf = crypto.createHash('sha256').update('nakpanel-csrf-v1:' + cookie.value).digest('hex');
  // APIRequestContext is separate from the browser network being disconnected below.
  async function api(route, body) {
   const response = await context.request.fetch(input.base + route, {
    method: body === undefined ? 'GET' : 'POST', data: body,
    headers: {Accept: 'application/json', 'X-Nakpanel-SPA': 'true', 'X-Nakpanel-CSRF': csrf, Referer: input.base + '/'},
   });
   assert([200,202,204].includes(response.status()), route + ' returned ' + response.status());
   return response.status() === 204 ? null : response.json();
  }
  async function navigate(route) {
   await page.goto(input.base + route);
   await page.waitForFunction(() => document.querySelector('[data-np-op-status]')?.textContent.includes('Last checked'));
  }
  await navigate('/activity?tab=inbox');
  const receipt = page.waitForResponse(r => r.url().endsWith('/notifications/' + input.notification + '/read') && r.request().method() === 'POST');
  await page.locator('[data-np-op-rows] [data-np-op-row-id="' + input.notification + '"]').getByRole('button', {name: 'View issue', exact: true}).click();
  assert.equal((await receipt).status(), 204);
  let issue = await api(endpoint + '/issues/' + input.issue);
  assert(!issue.acknowledged_at && !issue.resolved_at, 'Opening must only create a personal read receipt');
  await page.locator('[data-np-op-close]').click();
  result.read_on_open = true;

  await page.goto(input.base + '/support/customers/' + input.customer + '/activity?tab=issues&issue=' + input.issue);
  const settings = page.getByRole('link', {name: 'Open scheduled task settings', exact: true});
  const href = await settings.getAttribute('href');
  assert.equal(href, '/support/customers/' + input.customer + '/sites/' + input.site + '/scheduled-tasks');
  const destination = page.waitForResponse(r => new URL(r.url()).pathname === href && r.request().method() === 'GET');
  await settings.click();
  assert.equal((await destination).status(), 200);
  await page.waitForURL(url => url.pathname === href);
  result.support_settings = true;

  await navigate('/activity?tab=tasks');
  const baseline = await api(endpoint + '?view=tasks');
  const lastID = Math.max(0, ...baseline.tasks.map(t => t.id));
  await context.setOffline(true);
  try {
   for (let n = 0; n < 12; n++) {
    const response = await context.request.post(input.base + '/subscriptions/' + input.subscription + '/scheduled-tasks/' + input.success_task + '/run', {
     form: {}, maxRedirects: 0, headers: {Accept: 'application/json', 'X-Nakpanel-SPA': 'true', 'X-Nakpanel-CSRF': csrf, Referer: input.base + '/'},
    });
    assert([200,202,303].includes(response.status()), 'Actual Run now failed: ' + response.status());
   }
   await until(() => api(endpoint + '?view=tasks'), data => data.tasks.filter(t => t.id > lastID && t.kind === 'run_scheduled_task' && t.state === 'succeeded').length === 12, 'twelve real task completions');
  } finally { await context.setOffline(false); }
  await page.waitForFunction(() => [...document.querySelectorAll('[data-np-op-result-id]')].filter(n => n.textContent.includes('Run scheduled task completed')).length === 12, null, {timeout: 70000});
  const ids = await page.locator('[data-np-op-result-id]').evaluateAll(nodes => nodes.map(n => n.dataset.npOpResultId));
  assert.equal(new Set(ids).size, ids.length, 'Duplicate results after reconnection');
  // Exercise actual fragment navigation without resetting the shared poller.
  await page.getByRole('link', {name: 'Issues', exact: true}).first().click();
  await page.waitForURL(url => url.searchParams.get('tab') === 'issues' || url.pathname === '/activity' && !url.search);
  await page.waitForTimeout(6000);
  const after = await page.locator('[data-np-op-result-id]').evaluateAll(nodes => nodes.map(n => n.dataset.npOpResultId));
  assert(ids.every(id => after.includes(id)), 'Navigation lost terminal results');
  assert.equal(new Set(after).size, after.length, 'Navigation replayed results');
  result.terminal_results = 12;
  await page.screenshot({path: path.join(evidence, 'desktop-results.png')});
  await page.setViewportSize({width: 390, height: 844});
  await page.waitForTimeout(400);
  result.mobile_overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  assert.equal(result.mobile_overflow, false);
  await page.screenshot({path: path.join(evidence, 'mobile-results.png')});
  await page.setViewportSize({width: 1440, height: 1000});

  issue = await api(endpoint + '/issues/' + input.backup_issue);
  const original = await api(endpoint + '/tasks/' + issue.operation_id);
  const failed = original.attempts.filter(a => a.state === 'failed').map(a => a.id);
  assert(failed.length > 0, 'Original failed backup attempt required');
  await page.goto(input.base + '/activity?tab=issues&issue=' + input.backup_issue);
  await page.getByRole('button', {name: 'Review backup retry', exact: true}).click();
  const confirmation = page.locator('[data-np-op-confirm]');
  const retry = confirmation.getByRole('button', {name: 'Create backup and retry', exact: true});
  await retry.waitFor();
  assert.equal(await retry.isDisabled(), true);
  assert.equal(await confirmation.locator('input[type=checkbox]').isChecked(), false);
  await page.screenshot({path: path.join(evidence, 'recovery-confirmation.png')});
  await confirmation.locator('input[type=checkbox]').check();
  const recovery = page.waitForResponse(r => r.url().endsWith('/issues/' + input.backup_issue + '/recover') && r.request().method() === 'POST');
  await retry.click();
  const response = await recovery;
  assert.equal(response.status(), 202);
  const started = await response.json();
  await until(() => api(endpoint + '/tasks/' + started.operation_id), data => data.operation.state === 'succeeded', 'real backup recovery', 180);
  issue = await api(endpoint + '/issues/' + input.backup_issue);
  if (!issue.resolved_at && issue.last_check_status !== 'checking') await api(endpoint + '/issues/' + input.backup_issue + '/verify', {});
  issue = await until(() => api(endpoint + '/issues/' + input.backup_issue), data => !!data.resolved_at, 'independent archive verification');
  assert.equal(issue.verification.source, 'archive_checksum');
  assert.match(issue.verification.checksum, /^[a-f0-9]{64}$/);
  assert(issue.verification.size_bytes > 0);
  assert(issue.verification.summary.includes('restore has not been tested'));
  const retained = await api(endpoint + '/tasks/' + original.operation.id);
  assert(failed.every(id => retained.attempts.some(a => a.id === id && a.state === 'failed')), 'Original failure was rewritten');
  result.backup_recovered = true;
  result.original_failed_attempts_preserved = true;
  result.verification_source = issue.verification.source;
  assert.deepEqual(result.errors, []);
  result.passed = true;
 } catch (error) {
  result.error = String(error.message).replaceAll(input.password, '[synthetic-secret]').slice(0, 2000);
  throw new Error(result.error);
 } finally {
  fs.writeFileSync(path.join(evidence, 'browser.json'), JSON.stringify(result) + '\n', {mode: 0o600});
  await browser.close();
 }
})().catch(error => {console.error(error.message);process.exitCode = 1;});
