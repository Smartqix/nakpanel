const assert = require('node:assert/strict');
const fs = require('node:fs');

// Run only against a disposable database created by the workspace verifier.
module.exports = async function verifyManager(page, context, name) {
  assert.match(name, /^npws\d+$/);
  const url = new URL(page.url());
  const prefix = url.origin + url.pathname.split('/').slice(0, 3).join('/') + '/';
  async function sql(query) {
    await page.goto(prefix+'index.php?route=/database/sql&db='+name);
    await page.waitForLoadState('networkidle');
    await page.evaluate(query => {
      const editor = [...document.querySelectorAll('.CodeMirror')]
        .map(el => el.CodeMirror).find(cm => cm.getTextArea?.().name === 'sql_query');
      if (editor) { editor.setValue(query); editor.save(); }
      else { document.querySelector('textarea[name=sql_query]').value = query; }
    }, query);
    await page.getByRole('button', {name:'Go',exact:true}).last().click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1500);
    return page.locator('body').innerText();
  }
  assert.match(await sql("CREATE TABLE ux_probe (id INT PRIMARY KEY, value VARCHAR(30)); INSERT INTO ux_probe VALUES (1,'ready'); SELECT * FROM ux_probe;"), /ready/);
  assert.match(await sql('SELECT User FROM mysql.user;'), /denied|1142/i);
  await page.goto(prefix+'index.php?route=/database/export&db='+name);
  await page.waitForLoadState('networkidle');
  const download = await Promise.all([
    page.waitForEvent('download'), page.getByRole('button',{name:'Export',exact:true}).click(),
  ]).then(results => results[0]);
  assert.match(fs.readFileSync(await download.path(),'utf8'), /ux_probe/);
  await page.goto(prefix+'index.php?route=/database/import&db='+name);
  await page.waitForLoadState('networkidle');
  await page.locator('input[type=file]').first().setInputFiles({name:'probe.sql',mimeType:'application/sql',buffer:Buffer.from("INSERT INTO ux_probe VALUES (2,'imported');")});
  await page.getByRole('button',{name:'Import',exact:true}).click();
  await page.waitForLoadState('networkidle');
  assert.match(await sql('SELECT * FROM ux_probe;'), /imported/);
  await sql('DROP TABLE ux_probe;');
  await page.goto(prefix+'logout');
  await page.getByRole('button',{name:'End database session'}).click();
  await page.waitForURL('**/databases');
  assert.equal((await context.request.get(prefix)).status(),404);
  console.log('PASS SQL, import/export, privilege denial, and manager logout');
};
