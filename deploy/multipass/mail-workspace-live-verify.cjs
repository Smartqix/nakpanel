// Explicitly creates/removes only a fresh QA mailbox and alias on the selected site.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const crypto=require('node:crypto');
const base=process.env.NAKPANEL_QA_URL,site=process.env.NAKPANEL_QA_SITE_ID||'1',stateFile=process.env.NAKPANEL_QA_MAIL_STATE,stage=process.env.NAKPANEL_QA_STAGE||'prepare';
if(!base||!/^\d+$/.test(site)||!stateFile)throw new Error('Explicit QA URL, site and private state path required');
let browser;
(async()=>{
 browser=await chromium.launch({channel:'chrome',headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.goto(base+'/login');await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL||'admin@nakpanel.com');await page.locator('[name=password]').fill(fs.readFileSync(process.env.NAKPANEL_QA_PASSWORD_FILE,'utf8').trim());await page.locator('button[type=submit]').click();await page.waitForURL('**/dashboard');
 const target=base+'/sites/'+site+'?tab=mail';await page.goto(target);
 const data=stage==='prepare'?{prefix:'mailux-'+Date.now().toString(36),password:'Np!'+crypto.randomBytes(24).toString('base64url')}:JSON.parse(fs.readFileSync(stateFile,'utf8'));
 async function submit(dialog,endpoint){const result=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith(endpoint));await dialog.locator('button[type=submit]').click();const response=await result;assert.ok(response.status()<400,'mail operation failed: '+response.status());await dialog.waitFor({state:'hidden'});await page.waitForLoadState('domcontentloaded');}
 function row(){return page.locator('[data-np-mail-row]').filter({has:page.getByText(data.address,{exact:true})});}
 async function edit(){await row().locator('summary').click();await row().getByRole('link',{name:'Edit email address'}).click();return page.locator('dialog[open]');}
 async function remove(button){const response=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/delete'));await button.click();await page.locator('[data-np-confirmation-accept]').click();assert.ok((await response).status()<400,'QA removal rejected');}
 if(stage==='prepare'){
  assert.equal(fs.existsSync(stateFile),false,'refuse to replace QA state');
  await page.getByRole('link',{name:'Create email address',exact:true}).click();let dialog=page.locator('dialog[open]');
  data.domain=(await dialog.locator('.np-mail-address-input>span').innerText()).replace(/^@/,'');data.address=data.prefix+'@'+data.domain;data.alias=data.prefix+'-alias@'+data.domain;
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600,flag:'wx'});
  await dialog.locator('[name=local_part]').fill(data.prefix);await dialog.locator('[name=password]').fill(data.password);await dialog.locator('[name=quota_mb]').fill('32');await submit(dialog,'/mailboxes');await row().waitFor();
  dialog=await edit();data.mailboxID=Number(await dialog.locator('[name=resource_id]').inputValue());assert.equal(await dialog.locator('[name=password]').inputValue(),'');
  await dialog.locator('[name=quota_mb]').fill('64');await submit(dialog,'/mailboxes');assert.ok((await row().innerText()).includes('64 MB'));
  dialog=await edit();data.oldPassword=data.password;data.password='Np!'+crypto.randomBytes(24).toString('base64url');await dialog.locator('[name=password]').fill(data.password);await submit(dialog,'/mailboxes');fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  await page.getByRole('link',{name:/Aliases \(/}).click();await page.getByRole('link',{name:'Create alias',exact:true}).click();dialog=page.locator('dialog[open]');await dialog.locator('[name=local_part]').fill(data.prefix+'-alias');await dialog.locator('[name=destinations]').fill(data.address);await submit(dialog,'/mail-aliases');
  await page.getByRole('link',{name:/Aliases \(/}).click();let aliasRow=page.locator('.np-mail-table tbody tr').filter({hasText:data.alias});await aliasRow.waitFor();await aliasRow.locator('[title="Edit alias"]').click();dialog=page.locator('dialog[open]');data.aliasID=Number(await dialog.locator('[name=resource_id]').inputValue());await submit(dialog,'/mail-aliases');
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  await page.goto(target);await page.locator('[data-np-mail-settings]').click();dialog=page.locator('dialog[open]');await submit(dialog,'/mail-domains');
  await page.locator('.np-domain-mail .np-mail-toolbar-actions a:has-text("Import mail")').click();assert.ok(new URL(page.url()).pathname.endsWith('/mail-imports'));await page.goto(target);
  // Support navigation retains the actor identity and the current mailbox context.
  const support=await page.locator('a[href*="/support/customers/"]').first().getAttribute('href').catch(()=>null);
  if(support){await page.goto(new URL(support,base).href);}
 } else if(stage==='webmail') {
  await row().locator('[data-np-mail-connect]').click();let dialog=page.locator('#np-mail-connect-dialog');await dialog.locator('[data-np-mail-client-view]').waitFor();assert.ok((await dialog.innerText()).includes(data.address));assert.ok((await dialog.innerText()).includes('993'));assert.ok((await dialog.innerText()).includes('465'));await page.keyboard.press('Escape');
  const popupEvent=page.waitForEvent('popup');await row().getByRole('link',{name:/Open webmail/}).click();const webmail=await popupEvent;await webmail.waitForLoadState('domcontentloaded');assert.equal(new URL(webmail.url()).protocol,'https:');await webmail.locator('[name=_user]').fill(data.address);await webmail.locator('[name=_pass]').fill(data.password);await webmail.locator('button[type=submit],input[type=submit]').first().click();await webmail.waitForURL(url=>url.searchParams.get('_task')==='mail');await webmail.close();
 } else if(stage==='cleanup') {
  assert.match(data.prefix,/^mailux-[a-z0-9]+$/);assert.ok(data.address.startsWith(data.prefix+'@'));
  let dialog=await edit();await dialog.locator('[name=enabled]').uncheck();await submit(dialog,'/mailboxes');assert.equal(await row().getByRole('link',{name:/Open webmail/}).count(),0);await row().locator('[data-np-mail-connect]').click();dialog=page.locator('#np-mail-connect-dialog');await dialog.locator('[data-np-mail-client-view]').waitFor();assert.ok((await dialog.innerText()).includes('mailbox is suspended'));await page.keyboard.press('Escape');
  dialog=await edit();assert.equal(await dialog.locator('[name=enabled]').isChecked(),false);await dialog.locator('[name=enabled]').check();await submit(dialog,'/mailboxes');
  await page.getByRole('link',{name:/Aliases \(/}).click();let aliasRow=page.locator('.np-mail-table tbody tr').filter({hasText:data.alias});await remove(aliasRow.locator('button[title=Delete]'));await page.goto(target+'&mail_view=aliases');assert.equal(await page.locator('.np-mail-table tbody tr').filter({hasText:data.alias}).count(),0);
  await page.goto(target);await row().locator('summary').click();await remove(row().locator('button[title=Delete]'));await page.goto(target);assert.equal(await row().count(),0);
 } else throw new Error('unsupported QA stage');
 assert.deepEqual(errors,[]);console.log(JSON.stringify({ok:true,stage,qaAddress:data.address,mailboxID:data.mailboxID,aliasID:data.aliasID}));await browser.close();
})().catch(async error=>{console.error(error);if(browser)await browser.close();process.exit(1);});
