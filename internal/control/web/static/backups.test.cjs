const test = require('node:test');
const assert = require('node:assert/strict');
const {matchesBackup, backupStateSignature, backupPending, backupOperationMessage, revealBackupTab} = require('./backups.js');
test('mobile navigation reveals the active backup tab without scrolling the document', () => {
  const active={clientWidth:90,getBoundingClientRect:()=>({left:640})};
  const nav={scrollWidth:800,clientWidth:360,scrollLeft:0,querySelector:()=>active,getBoundingClientRect:()=>({left:15})};
  revealBackupTab(nav);
  assert.equal(nav.scrollLeft,490);
  nav.scrollWidth=360;revealBackupTab(nav);assert.equal(nav.scrollLeft,490);
  revealBackupTab(null);
});
test('backup filtering is case insensitive and domain exact', () => {
  assert.equal(matchesBackup('Blog.Example.com','2026-10-19','blog',''),true);
  assert.equal(matchesBackup('blog.example.com','2026-10-19','','example.com'),false);
  assert.equal(matchesBackup('blog.example.com','2026-10-19','2026','blog.example.com'),true);
});
test('fast completion never leaves a permanent removing or creating notice',()=>{
  assert.match(backupOperationMessage(true,{},['12']),/backups removed/);
  assert.match(backupOperationMessage(true,{'12':'delete_failed'},['12']),/could not/);
  assert.match(backupOperationMessage(false,{'12':'active'},['12']),/ready/);
  assert.match(backupOperationMessage(false,{'12':'pending'},['12']),/Creating/);
});
test('polling detects removal and ignores key ordering', () => {
  assert.equal(backupStateSignature({2:'active',1:'pending'}),backupStateSignature({1:'pending',2:'active'}));
  assert.notEqual(backupStateSignature({1:'deleting'}),backupStateSignature({}));
  assert.equal(backupPending({1:'deleting'}),true);
  assert.equal(backupPending({1:'delete_failed'}),false);
});
