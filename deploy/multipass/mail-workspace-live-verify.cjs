// Explicitly creates/removes only a fresh QA mailbox and alias on the selected site.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const crypto=require('node:crypto');
const base=process.env.NAKPANEL_QA_URL,site=process.env.NAKPANEL_QA_SITE_ID||'1',stateFile=process.env.NAKPANEL_QA_MAIL_STATE,stage=process.env.NAKPANEL_QA_STAGE||'prepare';
if(!base||!/^\d+$/.test(site)||!stateFile)throw new Error('Explicit QA URL, site and private state path required');
const browserConfig=require('./qualification-browser-config.cjs')(process.env);
const supportCustomer=process.env.NAKPANEL_QA_SUPPORT_CUSTOMER_ID||'3';
assert.ok(/^[1-9][0-9]*$/.test(supportCustomer),'explicit support customer ID must be numeric');
let browser;
(async()=>{
 browser=await chromium.launch(browserConfig.launch);
 const context=await browser.newContext({...browserConfig.context,viewport:{width:1440,height:1000}}),page=await context.newPage(),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.goto(base+'/login');await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL||'admin@nakpanel.com');await page.locator('[name=password]').fill(fs.readFileSync(process.env.NAKPANEL_QA_PASSWORD_FILE,'utf8').trim());await page.locator('button[type=submit]').click();await page.waitForURL('**/dashboard');
 const target=base+'/sites/'+site+'?tab=mail';await page.goto(target);
 const data=stage==='prepare'?{prefix:'mailux-'+Date.now().toString(36),password:'Np!'+crypto.randomBytes(24).toString('base64url')}:JSON.parse(fs.readFileSync(stateFile,'utf8'));
 async function ready(){await page.waitForLoadState('networkidle');await page.waitForFunction(()=>document.readyState==='complete'&&window.NakpanelUI&&window.NakpanelUI.dialogs);}
 async function aliases(){await page.getByRole('link',{name:/Aliases \(/}).click();await page.waitForURL(url=>url.searchParams.get('mail_view')==='aliases');await ready();}
 async function submit(dialog,endpoint){const result=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith(endpoint));await dialog.locator('button[type=submit]').click();const response=await result;assert.ok(response.status()<400,'mail operation failed: '+response.status());await dialog.waitFor({state:'hidden'});await ready();}
 function row(){return page.locator('[data-np-mail-row]').filter({has:page.getByText(data.address,{exact:true})});}
 async function edit(){await row().locator('summary').click();await row().getByRole('link',{name:'Edit email address'}).click();return page.locator('dialog[open]');}
 async function remove(button){const response=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/delete'));await button.click();await page.locator('[data-np-confirmation-accept]').click();assert.ok((await response).status()<400,'QA removal rejected');}
 if(stage==='prepare'||stage==='resume-prepare'){
  if(stage==='prepare'){
  assert.equal(fs.existsSync(stateFile),false,'refuse to replace QA state');
  await page.getByRole('link',{name:'Create email address',exact:true}).click();let dialog=page.locator('dialog[open]');
  data.domain=(await dialog.locator('.np-mail-address-input>span').innerText()).replace(/^@/,'');data.address=data.prefix+'@'+data.domain;data.alias=data.prefix+'-alias@'+data.domain;
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600,flag:'wx'});
  await dialog.locator('[name=local_part]').fill(data.prefix);await dialog.locator('[name=password]').fill(data.password);await dialog.locator('[name=quota_mb]').fill('32');await submit(dialog,'/mailboxes');await row().waitFor();
  dialog=await edit();data.mailboxID=Number(await dialog.locator('[name=resource_id]').inputValue());assert.equal(await dialog.locator('[name=password]').inputValue(),'');
  await dialog.locator('[name=quota_mb]').fill('64');await submit(dialog,'/mailboxes');assert.ok((await row().innerText()).includes('64 MB'));
  dialog=await edit();data.oldPassword=data.password;data.password='Np!'+crypto.randomBytes(24).toString('base64url');await dialog.locator('[name=password]').fill(data.password);await submit(dialog,'/mailboxes');fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  }
  await aliases();await page.getByRole('link',{name:'Create alias',exact:true}).click();let dialog=page.locator('dialog[open]');await dialog.locator('[name=local_part]').fill(data.prefix+'-alias');await dialog.locator('[name=destinations]').fill(data.address);await submit(dialog,'/mail-aliases');
  await aliases();let aliasRow=page.locator('.np-mail-table tbody tr').filter({hasText:data.alias});await aliasRow.waitFor();await aliasRow.locator('[title="Edit alias"]').click();dialog=page.locator('dialog[open]');data.aliasID=Number(await dialog.locator('[name=resource_id]').inputValue());await submit(dialog,'/mail-aliases');
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  await page.goto(target);await page.locator('[data-np-mail-settings]:visible').click();dialog=page.locator('dialog[open]');await submit(dialog,'/mail-domains');
  await page.locator('.np-domain-mail .np-mail-toolbar-actions a:has-text("Import mail")').click();await page.waitForURL(url=>url.pathname.endsWith('/mail-imports'));await page.goto(target);
  // Support navigation retains the actor identity and the current mailbox context.
  const support=await page.locator('a[href*="/support/customers/"]').first().getAttribute('href').catch(()=>null);
  if(support){await page.goto(new URL(support,base).href);}
 } else if(stage==='webmail') {
  await row().locator('[data-np-mail-connect]').click();let dialog=page.locator('#np-mail-connect-dialog');await dialog.locator('[data-np-mail-client-view]').waitFor();assert.ok((await dialog.innerText()).includes(data.address));assert.ok((await dialog.innerText()).includes('993'));assert.ok((await dialog.innerText()).includes('465'));await page.keyboard.press('Escape');
  const popupEvent=page.waitForEvent('popup');await row().getByRole('link',{name:/Open webmail/}).click();const webmail=await popupEvent;await webmail.waitForLoadState('domcontentloaded');assert.equal(new URL(webmail.url()).protocol,'https:');await webmail.locator('[name=_user]').fill(data.address);await webmail.locator('[name=_pass]').fill(data.password);await webmail.locator('button[type=submit],input[type=submit]').first().click();await webmail.waitForURL(url=>url.searchParams.get('_task')==='mail');await webmail.close();
 } else if(stage==='scope'||stage==='resume-scope') {
  const support=await context.request.get(base+'/support/customers/'+supportCustomer+'/sites/'+site+'?tab=mail');assert.equal(support.status(),200);const supportHTML=await support.text();assert.ok(supportHTML.includes('Support view')&&supportHTML.includes('/support/customers/'+supportCustomer+'/sites/'+site+'?tab=mail&amp;mail_view=connection'));
  const token=await page.locator('meta[name=nakpanel-csrf]').getAttribute('content');
  data.scopeEmail=data.prefix+'-scope@nakpanel.invalid';data.scopePassword='Np!'+crypto.randomBytes(24).toString('base64url');
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  if(stage==='scope'){
   const created=await context.request.post(base+'/customers',{headers:{Referer:base+'/customers'},form:{csrf_token:token,customer_email:data.scopeEmail,customer_name:'Mail UX isolation QA',enable_login:'true',password:data.scopePassword},maxRedirects:0});assert.equal(created.status(),303);const customerURL=new URL(created.headers().location,base);data.customerID=Number(customerURL.pathname.split('/').pop());assert.ok(data.customerID>0);
  } else {
   data.customerID=Number(process.env.NAKPANEL_QA_CUSTOMER_ID);assert.ok(data.customerID>0);assert.ok(data.scopeEmail.startsWith(data.prefix+'-scope@'));
   const reset=await context.request.post(base+'/customers/login',{form:{csrf_token:token,customer_id:String(data.customerID),email:data.scopeEmail,password:data.scopePassword},maxRedirects:0});assert.equal(reset.status(),303);
  }
  fs.writeFileSync(stateFile,JSON.stringify(data),{mode:0o600});
  const isolated=await browser.newContext(browserConfig.context),client=await isolated.newPage();await client.goto(base+'/login');await client.locator('[name=email]').fill(data.scopeEmail);await client.locator('[name=password]').fill(data.scopePassword);await client.locator('button[type=submit]').click();await client.waitForURL('**/dashboard');
  let response=await isolated.request.get(base+'/mail');assert.equal(response.status(),200);const html=await response.text();for(const secretResource of [data.address,data.alias])assert.equal(html.includes(secretResource),false,'unrelated customer saw fixture mailbox');assert.equal(html.includes('admin@nakpanel.com'),false);assert.equal(html.includes('notifications@nakpanel.com'),false);assert.equal(html.includes('mail.nakpanel.com'),false);
  const protectedMailbox=Number((supportHTML.match(/mailbox_id=(\d+)/)||[])[1]);assert.ok(protectedMailbox>0);
  for(const url of ['/sites/'+site+'?tab=mail','/sites/'+site+'?tab=mail&mail_view=connection&mailbox_id='+protectedMailbox,'/sites/'+site+'?tab=mail&mail_view=edit-address&resource_id='+protectedMailbox]){response=await isolated.request.get(base+url);assert.equal(response.status(),404,'cross-customer resource should be hidden');}
  response=await isolated.request.get(base+'/mail/status');assert.equal(response.status(),403);
  const clientToken=await client.locator('meta[name=nakpanel-csrf]').getAttribute('content');response=await isolated.request.post(base+'/settings/mail',{form:{csrf_token:clientToken,mail_hostname:'not-allowed.invalid'}});assert.equal(response.status(),403);
  response=await context.request.post(base+'/customers/status',{form:{csrf_token:token,customer_id:String(data.customerID),status:'suspended'},maxRedirects:0});assert.equal(response.status(),303);await isolated.close();
 } else if(stage==='cleanup') {
  assert.match(data.prefix,/^mailux-[a-z0-9]+$/);assert.ok(data.address.startsWith(data.prefix+'@'));
  let dialog=await edit();await dialog.locator('[name=enabled]').uncheck();await submit(dialog,'/mailboxes');assert.equal(await row().getByRole('link',{name:/Open webmail/}).count(),0);await row().locator('[data-np-mail-connect]').click();dialog=page.locator('#np-mail-connect-dialog');await dialog.locator('[data-np-mail-client-view]').waitFor();assert.ok((await dialog.innerText()).includes('mailbox is suspended'));await page.keyboard.press('Escape');
  dialog=await edit();assert.equal(await dialog.locator('[name=enabled]').isChecked(),false);await dialog.locator('[name=enabled]').check();await submit(dialog,'/mailboxes');
  await aliases();let aliasRow=page.locator('.np-mail-table tbody tr').filter({hasText:data.alias});await remove(aliasRow.locator('button[title=Delete]'));await page.goto(target+'&mail_view=aliases');assert.equal(await page.locator('.np-mail-table tbody tr').filter({hasText:data.alias}).count(),0);
  await page.goto(target);await row().locator('summary').click();await remove(row().locator('button[title=Delete]'));await page.goto(target);assert.equal(await row().count(),0);
 } else throw new Error('unsupported QA stage');
 assert.deepEqual(errors,[]);console.log(JSON.stringify({ok:true,stage,qaAddress:data.address,mailboxID:data.mailboxID,aliasID:data.aliasID}));await browser.close();
})().catch(async error=>{console.error(error);if(browser)await browser.close();process.exit(1);});
