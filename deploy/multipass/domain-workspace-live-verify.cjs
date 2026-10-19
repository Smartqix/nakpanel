// Explicitly opt-in: creates/removes only new, dated domain-workspace fixtures.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const cp=require('node:child_process');
const crypto=require('node:crypto');
const base=process.env.NAKPANEL_QA_URL;
const parent=process.env.NAKPANEL_QA_PARENT;
const fixtureSuffix=process.env.NAKPANEL_QA_DOMAIN_SUFFIX||parent;
const sub=Number(process.env.NAKPANEL_QA_SUBSCRIPTION_ID);
const primary=Number(process.env.NAKPANEL_QA_PRIMARY_ID);
const ssh=process.env.NAKPANEL_QA_SSH_TARGET;
const known=process.env.NAKPANEL_QA_KNOWN_HOSTS;
const run=process.env.NAKPANEL_QA_RUN;
const output=process.env.NAKPANEL_QA_SCREENSHOT_DIR||'/tmp/nakpanel-domain-live';
if(process.env.NAKPANEL_QA_MUTATIONS!=='allow-new-fixtures'||!base||!parent||!ssh||!known||!/^\d{8,14}$/.test(run||'')||!Number.isSafeInteger(sub)||sub<1||!Number.isSafeInteger(primary)||primary<1||!/^[a-z0-9.-]+$/.test(parent)||!/^[a-z0-9.-]+$/.test(fixtureSuffix))throw Error('Explicit mutation opt-in, URL, parent, IDs, SSH trust file and dated run required');
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
function db(sql){
  assert.match(sql,/^SELECT /);
  return cp.execFileSync('ssh',['-o','ControlPath=/tmp/np-fresh-%C','-o','BatchMode=yes','-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes',ssh,'runuser -u postgres -- psql -XAtq -d nakpanel -c '+quote(sql)],{encoding:'utf8',timeout:15000}).trim();
}
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check,label,seconds=240){for(let i=0;i<seconds;i++){if(await check())return;await sleep(1000);}throw Error('Timed out: '+label);}
let browser;
(async()=>{
  fs.mkdirSync(output,{recursive:true});
  assert.equal(db(`SELECT id FROM sites WHERE id=${primary} AND subscription_id=${sub} AND domain='${parent}'`),String(primary),'primary fixture context changed');
  const before=JSON.parse(db('SELECT json_build_object(\'sites\',(SELECT count(*) FROM sites),\'mailboxes\',(SELECT count(*) FROM mailboxes),\'backups\',(SELECT count(*) FROM backups))'));
  browser=await chromium.launch({channel:'chrome',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage(),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto(base+'/login');
  await page.locator('[name=email]').fill(process.env.NAKPANEL_QA_EMAIL||'admin@nakpanel.com');
  await page.locator('[name=password]').fill(fs.readFileSync(process.env.NAKPANEL_QA_PASSWORD_FILE,'utf8').trim());
  await page.locator('button[type=submit]').click();await page.waitForURL('**/dashboard');
  const csrf=await page.locator('meta[name=nakpanel-csrf]').getAttribute('content');
  async function post(route,form,statuses=[202,303]){
    const response=await context.request.post(base+route,{form:{...form,csrf_token:csrf},headers:{'X-Nakpanel-CSRF':csrf,'X-Nakpanel-SPA':'true'},maxRedirects:0});
    assert.ok(statuses.includes(response.status()),route+' returned '+response.status()+': '+(await response.text()).slice(0,300));
    return response;
  }
  const results=[];
  for(const [index,word]of ['one','two'].entries()){
    const domain=`figma-${word}-${run}.${fixtureSuffix}`,child='child.'+domain,name=`figma_${word}_${run}`;
    if(process.env.NAKPANEL_QA_RESUME!=='1')assert.equal(db(`SELECT count(*) FROM sites WHERE domain IN ('${domain}','${child}')`),'0','fixture already exists; do not duplicate');
    console.log('Pass '+(index+1)+': creating isolated QA domain '+domain);
    let site=Number(db(`SELECT id FROM sites WHERE domain='${domain}' AND subscription_id=${sub}`));
    if(!site){
    await page.goto(base+'/sites');
    await page.locator('[data-np-dialog-open="site-dialog"]').click();
    const create=page.locator('#site-dialog');
    await create.locator('[name=domain]').fill(domain);
    await create.locator('[name=subscription_id]').selectOption(String(sub));
    await create.locator('[name=php_version]').selectOption('8.4');
    await create.locator('[name=secure_with_ssl]').check();
    const created=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname==='/sites');
    await create.locator('[data-np-create-submit]').click();
    const createdResponse=await created;assert.equal(createdResponse.status(),202,await createdResponse.text());
    const accepted=await createdResponse.json();site=Number(accepted.site_id);
    assert.ok(site>primary);
    await page.waitForURL(url=>url.pathname==='/sites/'+site&&url.searchParams.get('notice')==='website-secured',{timeout:360000});
    }else{
      assert.equal(process.env.NAKPANEL_QA_RESUME,'1');
      await page.goto(base+'/sites/'+site);
    }
    assert.equal(db(`SELECT status||'|'||tls_status||'|'||https_redirect FROM sites WHERE id=${site}`),'active|active|true');
    assert.equal((await context.request.get('https://'+domain)).status(),200,'trusted QA HTTPS');
    const http=await context.request.get('http://'+domain,{maxRedirects:0});assert.ok([301,302,307,308].includes(http.status()));
    for(const hidden of ['.env','.git/config','.ssh/authorized_keys'])assert.ok([403,404].includes((await context.request.get('https://'+domain+'/'+hidden)).status()),'hidden file exposed');
    assert.equal((await context.request.get('http://'+domain+'/.well-known/acme-challenge/missing-domain-design-probe',{maxRedirects:0})).status(),404,'ACME path must bypass hidden-file denial');
    await page.locator('.np-domain-header-actions [data-np-dialog-open]').click();
    const childDialog=page.locator('dialog.np-subdomain-dialog');
    await childDialog.locator('[name=label]').fill('invalid_label');
    assert.equal(await childDialog.locator('[data-np-create-submit]').isDisabled(),true);
    await childDialog.locator('[name=label]').fill('child.'+domain);
    await childDialog.locator('[name=label]').blur();
    assert.equal(await childDialog.locator('[name=label]').inputValue(),'child');
    let childID=Number(db(`SELECT id FROM sites WHERE domain='${child}' AND subscription_id=${sub} AND parent_site_id=${site}`));
    if(!childID){
    const childCreated=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname===`/sites/${site}/subdomains`);
    await childDialog.locator('[data-np-create-submit]').click();
    const childResponse=await childCreated;assert.equal(childResponse.status(),202);
    const childAccepted=await childResponse.json();childID=Number(childAccepted.site_id);
    await page.waitForURL(url=>url.pathname==='/sites/'+childID&&url.searchParams.get('notice')==='website-secured',{timeout:360000});
    }else{
      assert.equal(process.env.NAKPANEL_QA_RESUME,'1');
      await page.keyboard.press('Escape');await page.goto(base+'/sites/'+childID);
    }
    assert.equal(await page.locator('.np-domain-header-actions button:has-text("Add subdomain")').count(),0);
    assert.equal((await context.request.get('https://'+child)).status(),200);
    await post(`/sites/${childID}/subdomains`,{label:'nested',secure_with_ssl:'false'},[400]);
    for(const suffix of ['?tab=overview','/web-server','?tab=php','?tab=mail','?tab=dns','?tab=ssl','?tab=databases','?tab=backups','/files','/access','/logs','/scheduled-tasks','/statistics','/git','/wordpress','/applications','/containers','/staging','/redis']){
      const response=await page.goto(base+'/sites/'+site+suffix);assert.equal(response.status(),200,suffix+' inaccessible');
      assert.equal(await page.locator('.np-domain-primary-nav').count(),1,suffix+' lost navigation');
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false,suffix+' overflow');
    }
    await page.goto(base+`/sites/${site}?tab=databases`);
    await page.locator(`[data-np-dialog-open="database-create-dialog-${site}"]`).click();
    const database=page.locator(`#database-create-dialog-${site}`);
    await database.locator('[name=db_name]').fill(name);await database.locator('[name=db_user]').fill(name);
    await database.locator('[name=password]').fill('Invalid!PasswordForQA');
    assert.equal(await database.locator('[name=password]').evaluate(e=>e.checkValidity()),false,'invalid password must be caught before submission');
    await database.locator('[name=password]').fill(crypto.randomBytes(24).toString('base64url'));
    const databaseCreated=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname==='/databases');
    await database.locator('button[type=submit]').click();
    const dbResponse=await databaseCreated;assert.equal(dbResponse.status(),202,await dbResponse.text());
    const dbID=Number((await dbResponse.json()).database_id);
    await page.locator(`[data-np-db-id="${dbID}"][data-np-db-state="active"]`).waitFor({timeout:180000});
    const launch=await post(`/databases/${dbID}/manager`,{},[303]);
    const manager=await context.request.get(new URL(launch.headers().location,base).href);assert.equal(manager.status(),200,'database manager unavailable');
    await page.goto(base+`/sites/${site}?tab=backups`);
    await page.locator(`[data-np-dialog-open="backup-create-dialog-${site}"]`).click();
    const creatingBackup=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname==='/backups');
    await page.locator(`#backup-create-dialog-${site} button[type=submit]`).click();
    const backupResponse=await creatingBackup;assert.ok([202,303].includes(backupResponse.status()),'Backup returned '+backupResponse.status());
    await page.waitForURL(url=>url.pathname==='/sites/'+site&&url.searchParams.get('notice')==='backup-queued');
    await until(()=>db(`SELECT count(*) FROM backups WHERE site_id=${site} AND status='active'`)==='1','QA backup');
    const backupID=Number(db(`SELECT id FROM backups WHERE site_id=${site} AND status='active'`));
    await page.goto(base+'/sites/'+site);await page.screenshot({path:path.join(output,`pass-${index+1}-desktop.png`),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.locator('.np-domain-tools-trigger').click();await page.locator('.np-domain-tools-dialog').waitFor({state:'visible'});
    await page.screenshot({path:path.join(output,`pass-${index+1}-mobile-tools.png`)});await page.keyboard.press('Escape');
    await page.setViewportSize({width:1440,height:1000});
    async function remove(id,expected,withChild){
      assert.ok(expected===domain||expected===child,'only exact QA domains can be removed');
      assert.equal(db(`SELECT domain FROM sites WHERE id=${id} AND subscription_id=${sub}`),expected);
      await page.goto(base+'/sites/'+id);await page.locator('.np-domain-header-actions summary').click();
      await page.locator('.np-domain-header-actions [data-np-removal-open]').click();
      const dialog=page.locator('#np-site-removal-dialog');await dialog.locator('[name=confirm_domain]').waitFor();
      assert.equal(await dialog.locator('[name=delete_database_ids]:checked').count(),0);
      assert.equal(await dialog.locator('button[type=submit]').isDisabled(),true);
      await dialog.locator('[name=confirm_domain]').fill(expected);
      await dialog.locator('[name=acknowledge_permanent]').check();
      if(withChild){assert.equal(await dialog.locator('button[type=submit]').isDisabled(),true);await dialog.locator('[name=include_children]').check();}
      await page.screenshot({path:path.join(output,`pass-${index+1}-removal-${id}.png`),fullPage:true});
      const removing=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname===`/sites/${id}/remove`);
      await dialog.locator('button[type=submit]').click();
      const response=await removing;assert.equal(response.status(),202);
      const operation=await response.json();assert.ok(operation.status_url);
      let destination;
      await until(async()=>{const r=await context.request.get(new URL(operation.status_url,base).href);const state=await r.json();if(state.state==='failed')throw Error('Removal failed: '+state.error);if(state.state==='completed'){destination=new URL(state.redirect,base);return true;}return false;},'QA removal',300);
      await until(()=>db(`SELECT count(*) FROM sites WHERE id=${id}`)==='0','site finalization');
      assert.equal(destination.origin,new URL(base).origin);
      await page.waitForURL(destination.href,{timeout:60000});
    }
    if(index===0)await remove(childID,child,false);
    await remove(site,domain,index===1);
    assert.equal(db(`SELECT count(*) FROM sites WHERE id IN (${site},${childID})`),'0');
    assert.equal(db(`SELECT status||'|'||(site_id IS NULL)::text FROM databases WHERE id=${dbID}`),'active|true');
    assert.equal(db(`SELECT status||'|'||(site_id IS NULL)::text FROM backups WHERE id=${backupID}`),'active|true');
    const download=await context.request.get(base+`/backups/${backupID}/download`);assert.equal(download.status(),200);assert.ok((await download.body()).length>0);
    results.push({pass:index+1,domain,site,childID,databaseID:dbID,backupID,retained:true});
    fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({before,passes:results},null,2));
    console.log('Pass '+(index+1)+' passed: creation/SSL, child boundary, tool routes, database auto-refresh/manager, backup, responsive navigation, removal and retained recovery data.');
  }
  assert.equal(db(`SELECT status||'|'||tls_status FROM sites WHERE id=${primary}`),'active|active');
  assert.equal(Number(db('SELECT count(*) FROM mailboxes')),before.mailboxes,'existing mailbox inventory changed');
  assert.deepEqual(errors,[],'browser runtime errors');
  await browser.close();
})().catch(async error=>{if(browser)await browser.close();console.error(error);process.exitCode=1;});
