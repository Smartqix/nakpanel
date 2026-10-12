const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
test('site policy keeps checked settings when hidden false fallbacks share the name', () => {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function buildSitePolicyPatch(form)');
  const end = source.indexOf('\n  function ', start + 1);
  const context = vm.createContext({});
  vm.runInContext(source.slice(start, end), context);
  const output = { value: '' };
  const elements = { site_fpm_mode: {value:'ondemand'}, site_fpm_children:{value:'20'}, site_fpm_requests:{value:'500'}, site_php_memory:{value:'512'}, site_php_log_errors:[{value:'false'},{value:'true',checked:true}] };
  context.form = {elements, querySelector(selector) {
    if(selector==='[data-np-policy-patch]')return output;
    return {checked: /site_php_log_errors|site_php_opcache/.test(selector)};
  }};
  vm.runInContext('buildSitePolicyPatch(form)', context);
  const patch = JSON.parse(output.value);
  assert.equal(patch.php.log_errors,true);
  assert.equal(patch.php.opcache_enabled,true);
  assert.equal(patch.php.exec_enabled,false);
  assert.equal(patch.php.fpm_max_requests,500);
});
