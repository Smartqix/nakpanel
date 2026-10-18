const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {removalReady, normalizeSubdomainLabel} = require('./static/domains.js');

test('long menus use the larger available viewport side and scroll within it', () => {
  const {menuLayout}=require('./static/domains.js');
  assert.deepEqual(menuLayout({top:300,bottom:344},600,620),{up:true,maxHeight:282});
  assert.deepEqual(menuLayout({top:100,bottom:144},600,620),{up:false,maxHeight:458});
  assert.deepEqual(menuLayout({top:300,bottom:344},120,620),{up:false,maxHeight:258});
});

test('HTML validation patterns compile under modern Unicode sets semantics', () => {
  for (const name of fs.readdirSync(__dirname).filter(name=>name.endsWith('.templ'))) {
    const source=fs.readFileSync(path.join(__dirname,name),'utf8');
    for(const match of source.matchAll(/\bpattern="([^"]+)"/g)) {
      assert.doesNotThrow(()=>new RegExp(match[1],'v'),name+': invalid HTML pattern '+match[1]);
    }
  }
});

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
