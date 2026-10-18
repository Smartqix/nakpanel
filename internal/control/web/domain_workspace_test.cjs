const test = require('node:test');
const assert = require('node:assert/strict');
const {removalReady, normalizeSubdomainLabel, menuOpensUp} = require('./static/domains.js');

function form(name, children, loss, busy = false) {
  const controls = {
    confirm_domain: {value:name},
    include_children: {checked:children},
    acknowledge_permanent: {checked:loss}
  };
  return {
    dataset:{npConfirmDomain:'example.test'},
    getAttribute:key=>key==='aria-busy'&&busy?'true':null,
    querySelector:selector=>controls[(selector.match(/name=["']?([^"'\]]+)/)||[])[1]]||null
  };
}
test('removal needs all three independent confirmations', () => {
  for (let mask=0; mask<8; mask++) {
    const typed=!!(mask&1), children=!!(mask&2), loss=!!(mask&4);
    assert.equal(removalReady(form(typed?'example.test':'wrong.test',children,loss)),mask===7);
  }
});
test('confirmation uses the same exact, trimmed domain as the server', () => {
  assert.equal(removalReady(form(' example.test ',true,true)),true);
  assert.equal(removalReady(form('EXAMPLE.TEST',true,true)),false);
});
test('busy, uncertain and stale removals cannot become enabled by typing', () => {
  assert.equal(removalReady(form('example.test',true,true,true)),false);
  for(const key of ['npRemovalUncertain','npRemovalStale']) {
    const f=form('example.test',true,true); f.dataset[key]='true';
    assert.equal(removalReady(f),false);
  }
});
test('optional database deletion is not selected by gate evaluation', () => {
  const f=form('example.test',true,true);
  const before=JSON.stringify(f.dataset);
  assert.equal(removalReady(f),true);
  assert.equal(JSON.stringify(f.dataset),before);
});
test('matching full subdomain input is shortened without accepting nested labels', () => {
  assert.equal(normalizeSubdomainLabel(' BLOG.Example.test. ','example.test'),'blog');
  assert.equal(normalizeSubdomainLabel('blog','example.test'),'blog');
  assert.equal(normalizeSubdomainLabel('api.blog.example.test','example.test'),'api.blog.example.test');
  assert.equal(normalizeSubdomainLabel('blog.other.test','example.test'),'blog.other.test');
  assert.equal(normalizeSubdomainLabel('blog_dev','example.test'),'blog_dev');
});
test('menus flip only when there is room above', () => {
  assert.equal(menuOpensUp({top:680,bottom:950,height:270},800),true);
  assert.equal(menuOpensUp({top:30,bottom:950,height:920},800),false);
  assert.equal(menuOpensUp({top:80,bottom:350,height:270},800),false);
});
