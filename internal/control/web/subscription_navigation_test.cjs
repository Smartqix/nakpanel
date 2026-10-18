const installLifecycle = require('./lifecycle_harness.cjs');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function initialize(nav) {
  const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');
  const start = source.indexOf('  function initializeSubscriptionTabs(root)');
  assert.ok(start >= 0, 'subscription navigation must reveal the active mobile tab');
  assert.match(source, /initializeSubscriptionTabs\(root\);/);
  const end = source.indexOf('\n  function ', start + 1);
  const context = vm.createContext({document: {querySelectorAll:()=>[nav]}});
  installLifecycle(context);
  vm.runInContext(source.slice(start, end) + '\ninitializeSubscriptionTabs();', context);
}

function navigation(left, scrollLeft = 0) {
  return {
    clientWidth: 390, scrollWidth: 1200, scrollLeft,
    getBoundingClientRect: () => ({left: 0, right: 390}),
    querySelector: () => ({getBoundingClientRect: () => ({left, right: left + 100, width: 100})})
  };
}

test('an offscreen active tab is revealed without scrolling the document', () => {
  const nav = navigation(920);
  initialize(nav);
  assert.equal(nav.scrollLeft, 775);
});

test('a tab hidden on the left is also brought into view', () => {
  const nav = navigation(-100, 600);
  initialize(nav);
  assert.equal(nav.scrollLeft, 355);
});

test('already visible and non-overflowing navigation is left unchanged', () => {
  const nav = navigation(100);
  initialize(nav);
  assert.equal(nav.scrollLeft, 0);
  nav.scrollWidth = 390;
  initialize(nav);
  assert.equal(nav.scrollLeft, 0);
});

test('a missing active tab does not break other workspace interactions', () => {
  const nav = navigation(100);
  nav.querySelector = () => null;
  initialize(nav);
  assert.equal(nav.scrollLeft, 0);
});
