const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.NAKPANEL_QA_URL;
const fixture = process.env.NAKPANEL_QA_FIXTURE === '1';
const rootID = process.env.NAKPANEL_QA_ROOT_ID || '1';
const childID = process.env.NAKPANEL_QA_CHILD_ID || '7';
const addonID = process.env.NAKPANEL_QA_ADDON_ID || '9';
const parent = process.env.NAKPANEL_QA_PARENT || 'example.test';
const addon = process.env.NAKPANEL_QA_ADDON || 'example.net';
const output = process.env.NAKPANEL_QA_SCREENSHOT_DIR || '/tmp/nakpanel-domain-workspace';
if (!base || ![rootID,childID,addonID].every(v=>/^\d+$/.test(v))) throw new Error('Explicit QA URL and numeric object IDs required');
let browser;
async function layout(page,label) {
  await page.evaluate(()=>document.fonts.ready);
  const metrics=await page.evaluate(()=>{
    const visible=e=>!!e.getClientRects().length&&!e.closest('[hidden],details:not([open])>div');
    return {
      overflow:document.documentElement.scrollWidth>innerWidth+1,
      missingImages:Array.from(document.querySelectorAll('img')).filter(visible).filter(e=>!e.complete||!e.naturalWidth).map(e=>e.getAttribute('src')),
      inter:document.fonts.check('14px Inter')
    };
  });
  assert.equal(metrics.overflow,false,label+': horizontal overflow');
  assert.deepEqual(metrics.missingImages,[],label+': missing assets');
  assert.equal(metrics.inter,true,label+': bundled Inter missing');
}
async function screenshot(page,label) {await page.screenshot({path:path.join(output,label+'.png'),fullPage:true});}
(async()=>{
  fs.mkdirSync(output,{recursive:true});
  browser=await chromium.launch({channel:'chrome',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000},ignoreHTTPSErrors:new URL(base).hostname==='127.0.0.1'});
  if(fixture)await context.route('**/sites/'+childID+'/setup/status',route=>route.fulfill({json:{ok:true,site_id:Number(childID),kind:'subdomain',domain:'blog.'+parent,state:'failed',ssl_requested:true,can_retry_ssl:true,message:'HTTP-01 validation returned HTTP 403. Check challenge routing and permissions.',steps:[{code:'hosting',state:'active'},{code:'dns',state:'active'},{code:'tls',state:'failed'},{code:'https',state:'pending'}]}}));
  const page=await context.newPage(),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  if(!fixture){
    const password=fs.readFileSync(process.env.NAKPANEL_QA_PASSWORD_FILE,'utf8').trim();
    await page.goto(base+'/login');
    await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL||'admin@nakpanel.com');
    await page.locator('[name=password]').fill(password);
    await page.locator('button[type=submit]').click();
    await page.waitForURL('**/dashboard');
  }
  await page.goto(base+'/sites');
  await layout(page,'list desktop');await screenshot(page,'01-list-desktop');
  await page.locator('[data-np-dialog-open="site-dialog"]').click();
  await page.waitForTimeout(150);
  assert.equal(new URL(page.url()).pathname,'/sites','add-domain dialog navigated away');
  await page.locator('#site-dialog').waitFor({state:'visible'});
  await page.keyboard.press('Escape');
  await page.locator('[data-np-list-search]').fill(parent);
  assert.ok(await page.locator('[data-np-list-row]:visible').count()>0);
  await page.locator('[data-np-list-search]').fill('does-not-exist-qa');
  assert.equal(await page.locator('[data-np-list-row]:visible').count(),0);
  await page.locator('[data-np-list-search]').fill('');
  await page.goto(base+'/sites/'+rootID);
  await layout(page,'root desktop');await screenshot(page,'02-domain-desktop');
  assert.equal(await page.locator('.np-domain-status-strip').count(),1);
  assert.equal(await page.locator('.np-v2-domain-primary').count(),0);
  const primary=page.locator('.np-domain-header-actions details');
  await primary.locator('summary').click();
  assert.equal(await primary.locator('[data-np-removal-open]').count(),0);
  await page.keyboard.press('Escape');
  assert.equal(await primary.getAttribute('open'),null);
  assert.equal(await primary.locator('summary').evaluate(e=>e===document.activeElement),true);
  await page.setViewportSize({width:1440,height:620});
  await page.locator('.np-domain-more summary').click();
  const more=await page.locator('.np-domain-more-menu').boundingBox();
  assert.ok(more.y>=0&&more.y+more.height<=620,'More menu exceeds short desktop viewport');
  await page.keyboard.press('Escape');
  await page.setViewportSize({width:1440,height:1000});
  const opener=page.locator('.np-domain-header-actions [data-np-dialog-open]').first();
  await opener.click();
  const create=page.locator('dialog.np-subdomain-dialog');
  await create.waitFor({state:'visible'});
  assert.equal(await create.locator('[name=label]').evaluate(e=>e===document.activeElement),true);
  await create.locator('[name=label]').fill('blog_dev');
  await create.locator('[data-np-subdomain-field-error]').waitFor({state:'visible'});
  assert.equal(await create.locator('[data-np-create-submit]').isDisabled(),true);
  assert.equal(await create.locator('[name=label]').inputValue(),'blog_dev');
  await screenshot(page,'03-subdomain-validation-desktop');
  await create.locator('[name=label]').fill('blog.'+parent);
  await create.locator('[name=label]').blur();
  assert.equal(await create.locator('[name=label]').inputValue(),'blog');
  await page.keyboard.press('Escape');await create.waitFor({state:'hidden'});
  assert.equal(await opener.evaluate(e=>e===document.activeElement),true);
  await page.goto(base+'/sites/'+childID);
  await layout(page,'child desktop');await screenshot(page,'04-subdomain-desktop');
  assert.equal(await page.locator('.np-domain-header-actions button:has-text("Add subdomain")').count(),0);
  assert.ok(await page.locator('.np-domain-parent-context a[href$="/sites/'+rootID+'"]').count()>0);
  if(fixture){
    await page.locator('[data-np-domain-ssl-review]').click();
    await page.waitForTimeout(650);
    assert.equal(new URL(page.url()).pathname,'/sites/'+childID,'SSL validation dialog navigated away');
    const ssl=page.locator('#domain-ssl-review-'+childID);
    await ssl.waitFor({state:'visible'});
    await ssl.locator('[data-np-setup-retry]').waitFor({state:'visible'});
    await screenshot(page,'09-ssl-validation');
    await page.keyboard.press('Escape');
  }
  for(const size of [{width:390,height:844},{width:390,height:620}]){
    await page.setViewportSize(size);
    await page.goto(base+'/sites/'+rootID);
    await layout(page,'root mobile '+size.height);
    await page.locator('.np-domain-tools-trigger').click();
    const drawer=page.locator('.np-domain-tools-dialog');
    await drawer.waitFor({state:'visible'});await layout(page,'mobile drawer');
    if(fixture)await drawer.locator('.np-dialog-head p').evaluate(e=>e.textContent='a'.repeat(63)+'.example.test');
    const drawerClose=await drawer.locator('[data-np-dialog-close]').first().boundingBox();
    assert.ok(drawerClose.x>=0&&drawerClose.x+drawerClose.width<=size.width,'long domain clips drawer Close');
    const close=drawer.locator('[data-np-dialog-close]').last();
    await close.focus();await page.keyboard.press('Tab');
    assert.equal(await drawer.locator('[data-np-dialog-close]').first().evaluate(e=>e===document.activeElement),true);
    if(size.height===844)await screenshot(page,'05-mobile-tools');
    await page.keyboard.press('Escape');await drawer.waitFor({state:'hidden'});
    await page.locator('.np-domain-header-actions [data-np-dialog-open]').first().click();
    if(fixture)await create.locator('.np-dialog-head p').evaluate(e=>e.textContent='a'.repeat(63)+'.example.test / Main hosting');
    const createClose=await create.locator('[data-np-dialog-close]').first().boundingBox();
    assert.ok(createClose.x>=0&&createClose.x+createClose.width<=size.width,'long domain clips creation Close');
    await create.locator('[name=label]').fill('blog_dev');
    await layout(page,'mobile validation');
    const footer=await create.locator('form[data-np-create-subdomain-form] .np-dialog-actions').boundingBox();
    assert.ok(footer.y>=0&&footer.y+footer.height<=size.height+1,'creation footer clipped');
    if(size.height===844)await screenshot(page,'06-mobile-validation');
    await page.keyboard.press('Escape');
  }
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(base+'/sites/'+addonID);
  await page.locator('.np-domain-header-actions summary').click();
  await page.locator('.np-domain-header-actions [data-np-removal-open]').click();
  const remove=page.locator('#np-site-removal-dialog');
  await remove.locator('[name=confirm_domain]').waitFor();
  assert.equal(await remove.locator('.np-removal-dialog-cancel:visible').count(),1);
  assert.equal(await remove.locator('.np-removal-page-cancel:visible').count(),0);
  assert.equal(await remove.locator('.np-removal-dialog-cancel').evaluate(e=>e===document.activeElement),true);
  assert.equal(await remove.locator('[name=delete_database_ids]:checked').count(),0);
  const submit=remove.locator('button[type=submit]');
  assert.equal(await submit.isDisabled(),true);
  await remove.locator('[name=confirm_domain]').fill(addon);
  if(await remove.locator('[name=include_children]').count()){
    await remove.locator('[name=include_children]').check();
    assert.equal(await submit.isDisabled(),true);
  }
  await remove.locator('[name=acknowledge_permanent]').check();
  assert.equal(await submit.isDisabled(),false);
  await layout(page,'removal desktop');await screenshot(page,'07-removal-desktop');
  await page.setViewportSize({width:390,height:844});
  await layout(page,'removal mobile');
  const footer=await remove.locator('.np-dialog-actions').boundingBox();
  assert.ok(footer.y+footer.height<=844+1,'removal footer clipped');
  await screenshot(page,'08-removal-mobile');
  await page.keyboard.press('Escape');
  assert.deepEqual(errors,[]);
  console.log('PASS: list, root/child, parent context, validation, focus, Escape, mobile drawer, short-view footer, default retention and removal gate.');
  await browser.close();
})().catch(async error=>{if(browser)await browser.close();console.error(error);process.exitCode=1;});
