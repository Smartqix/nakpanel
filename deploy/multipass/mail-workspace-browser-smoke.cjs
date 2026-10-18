const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const base=process.env.NAKPANEL_QA_URL, fixture=process.env.NAKPANEL_QA_FIXTURE==='1';
const siteID=process.env.NAKPANEL_QA_SITE_ID||'1';
const output=process.env.NAKPANEL_QA_SCREENSHOT_DIR||'/tmp/nakpanel-mail-workspace';
if(!base||!/^\d+$/.test(siteID))throw new Error('QA URL and numeric site ID required');
let browser;
async function layout(page,label){
 await page.waitForLoadState('load');await page.locator('.np-domain-mail').waitFor();
 await page.evaluate(()=>document.fonts.ready);
 const metrics=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth+1,missing:Array.from(document.images).filter(e=>e.getClientRects().length&&(!e.complete||!e.naturalWidth)).map(e=>e.src)}));
 assert.equal(metrics.overflow,false,label+': overflow');assert.deepEqual(metrics.missing,[],label+': missing assets');
}
async function snap(page,name){await layout(page,name);await page.screenshot({path:path.join(output,name+'.png'),animations:'disabled',fullPage:page.viewportSize().width>700&&!(await page.locator('dialog[open]').count())});}
async function dialogBounds(dialog,height){const r=await dialog.boundingBox();assert.ok(r.y>=0&&r.y+r.height<=height+1,'dialog exceeds viewport');}
(async()=>{
 fs.mkdirSync(output,{recursive:true});browser=await chromium.launch({channel:'chrome',headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:base});
 const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 if(!fixture){await page.goto(base+'/login');await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL||'admin@nakpanel.com');await page.locator('[name=password]').fill(fs.readFileSync(process.env.NAKPANEL_QA_PASSWORD_FILE,'utf8').trim());await page.locator('button[type=submit]').click();await page.waitForURL('**/dashboard');}
 const target=base+'/sites/'+siteID+'?tab=mail';
 await page.goto(target);await snap(page,'01-mail-desktop');
 assert.equal(await page.locator('.np-domain-mail .np-mail-summary').count(),0);
 assert.ok(await page.locator('[data-np-mail-row]').count()>0);
 const first=page.locator('[data-np-mail-row]').first(),firstAddress=await first.getAttribute('data-np-mail-row');
 const webmail=first.getByRole('link',{name:/Open webmail/});assert.ok((await webmail.getAttribute('href')).startsWith('https://'));
 assert.equal(await webmail.getAttribute('target'),'_blank');
 await page.locator('[data-np-mail-search]').fill('no-such-address');assert.equal(await page.locator('[data-np-mail-row]:visible').count(),0);await page.locator('[data-np-mail-no-results]').waitFor({state:'visible'});
 await page.locator('[data-np-mail-search]').fill(firstAddress.toUpperCase());assert.equal(await page.locator('[data-np-mail-row]:visible').count(),1);await page.locator('[data-np-mail-search]').fill('');
 const connect=first.locator('[data-np-mail-connect]');await connect.click();
 const dialog=page.locator('#np-mail-connect-dialog');await dialog.locator('[data-np-mail-client-view]').waitFor();
 assert.ok((await dialog.locator('.np-mail-client-account').innerText()).includes(firstAddress));
 await dialog.getByRole('button',{name:'Copy all settings'}).click();
 const copied=await page.evaluate(()=>navigator.clipboard.readText());assert.ok(copied.includes(firstAddress)&&copied.includes('993')&&copied.includes('465'));assert.equal(copied.includes('relay'),false);
 await snap(page,'02-connect-desktop');await dialogBounds(dialog,1000);
 await dialog.getByRole('tab',{name:/POP3/}).click();await dialog.locator('[data-np-mail-protocol-panel=pop]').waitFor({state:'visible'});
 await dialog.getByRole('tab',{name:/IMAP/}).focus();await page.keyboard.press('ArrowRight');assert.equal(await dialog.getByRole('tab',{name:/POP3/}).getAttribute('aria-selected'),'true');
 await page.keyboard.press('Escape');await dialog.waitFor({state:'hidden'});assert.equal(await connect.evaluate(e=>e===document.activeElement),true);
 if(await page.locator('[data-np-mail-row]').count()>1){const second=page.locator('[data-np-mail-row]').nth(1),address=await second.getAttribute('data-np-mail-row');await second.locator('[data-np-mail-connect]').click();await dialog.locator('[data-np-mail-client-view]').waitFor();assert.ok((await dialog.locator('.np-mail-client-account').innerText()).includes(address));await page.keyboard.press('Escape');}
 await page.getByRole('link',{name:'Create email address',exact:true}).click();const create=page.locator('dialog[open]');await create.locator('[name=local_part]').waitFor();assert.equal(await create.locator('[name=local_part]').evaluate(e=>e===document.activeElement),true);
 await create.locator('[data-np-generate-password]').click();assert.ok((await create.locator('[name=password]').inputValue()).length>=12);await create.locator('[name=password]').fill('');
 await snap(page,'03-create-desktop');await page.keyboard.press('Escape');
 await first.locator('summary').click();await first.getByRole('link',{name:'Edit email address'}).click();const edit=page.locator('dialog[open]');assert.equal(await edit.locator('[name=password]').inputValue(),'');await page.keyboard.press('Escape');
 await page.locator('[data-np-mail-settings]:visible').click();await snap(page,'04-settings-desktop');await page.keyboard.press('Escape');
 await page.getByRole('link',{name:/Aliases \(/}).click();await page.waitForURL(url=>url.searchParams.get('mail_view')==='aliases');await snap(page,'05-aliases-desktop');
 await page.goto(target);await page.setViewportSize({width:390,height:844});await snap(page,'06-mail-mobile');
 if(await page.locator('body.np-mail-page').count()){const firstCard=await page.locator('[data-np-mail-row]').first().boundingBox();assert.ok(firstCard.y<700,'mailboxes pushed below the mobile working area');}
 // Shared mailbox rows must filter even on the aggregate Customer Mail page.
 await page.evaluate(()=>{document.body.classList.remove('np-domains');document.querySelector('.np-domain-mail').classList.remove('np-domain-mail');});
 await page.locator('[data-np-mail-search]').fill('no-such-address');assert.equal(await page.locator('[data-np-mail-row]:visible').count(),0,'aggregate mobile filtering');
 await page.locator('[data-np-mail-search]').fill('');await page.evaluate(()=>{document.body.classList.add('np-domains');document.querySelector('.np-mail-workspace').classList.add('np-domain-mail');});
 await page.locator('[data-np-mail-row]').first().locator('[data-np-mail-connect]').click();await dialog.locator('[data-np-mail-client-view]').waitFor();await snap(page,'07-connect-mobile-incoming');await dialogBounds(dialog,844);
 await dialog.getByRole('button',{name:'Outgoing',exact:true}).click();assert.equal(await dialog.locator('[data-np-mail-endpoint=outgoing]').isVisible(),true);assert.equal(await dialog.locator('[data-np-mail-endpoint=incoming]').isVisible(),false);await snap(page,'08-connect-mobile-outgoing');
 await page.keyboard.press('Escape');await page.getByRole('link',{name:'Create email address',exact:true}).click();await snap(page,'09-create-mobile');await dialogBounds(page.locator('dialog[open]'),844);await page.keyboard.press('Escape');
 await page.setViewportSize({width:1024,height:620});await page.locator('[data-np-mail-row]').first().locator('[data-np-mail-connect]').click();await dialog.locator('[data-np-mail-client-view]').waitFor();await dialogBounds(dialog,620);await page.keyboard.press('Escape');
 const fallback=await browser.newContext({javaScriptEnabled:false,storageState:await context.storageState(),viewport:{width:390,height:844}}),plain=await fallback.newPage();await plain.goto(target);await plain.locator('[data-np-mail-row]').first().locator('[data-np-mail-connect]').click();await plain.locator('[data-np-mail-client-view]').waitFor();assert.ok(await plain.locator('[data-np-mail-endpoint=incoming]').isVisible());assert.ok(await plain.locator('[data-np-mail-endpoint=outgoing]').isVisible());await layout(plain,'no-JS connection');
 await plain.goto(target);await plain.getByRole('link',{name:'Create email address',exact:true}).click();await plain.locator('.np-mail-form-page [name=local_part]').waitFor({state:'visible'});await layout(plain,'no-JS create form');
 assert.deepEqual(errors,[],'browser errors');console.log(JSON.stringify({ok:true,fixture,checks:['desktop/mobile','mail search','mailbox-specific connection','copy without secrets','POP3 unavailable','keyboard/focus','create/edit/settings dialogs','aliases','short viewport','no-JS connection'],output}));
 await browser.close();
})().catch(async error=>{console.error(error);if(browser)await browser.close();process.exit(1);});
