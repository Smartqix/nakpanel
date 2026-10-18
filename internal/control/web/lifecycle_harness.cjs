const fs = require('node:fs');
const vm = require('node:vm');
const {createLifecycle} = require('./static/navigation.js');
// Execute the production mount/timer helpers in each existing VM fixture, so
// polling tests exercise the same cancellation path as the browser.
module.exports = function installLifecycle(context) {
 const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
 const start = source.indexOf('  var initialized = new WeakMap();');
 const end = source.indexOf('  function refreshPage()', start);
 context.testLifecycle = createLifecycle();
 vm.runInContext('var lifecycle = testLifecycle;\n' + source.slice(start, end), context);
 return context.testLifecycle;
};
