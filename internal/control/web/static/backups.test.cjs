const test = require('node:test');
const assert = require('node:assert/strict');
const {matchesBackup, backupStateSignature, backupPending} = require('./backups.js');
test('backup filtering is case insensitive and domain exact', () => {
  assert.equal(matchesBackup('Blog.Example.com','2026-10-19','blog',''),true);
  assert.equal(matchesBackup('blog.example.com','2026-10-19','','example.com'),false);
  assert.equal(matchesBackup('blog.example.com','2026-10-19','2026','blog.example.com'),true);
});
test('polling detects removal and ignores key ordering', () => {
  assert.equal(backupStateSignature({2:'active',1:'pending'}),backupStateSignature({1:'pending',2:'active'}));
  assert.notEqual(backupStateSignature({1:'deleting'}),backupStateSignature({}));
  assert.equal(backupPending({1:'deleting'}),true);
  assert.equal(backupPending({1:'delete_failed'}),false);
});
