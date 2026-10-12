const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/static/git.js', 'utf8');
const {actionDisabled, operationFields, operationKey, safeError, logOutput, readResponse} = require('./static/git.js');
test('empty operation logs show a status-appropriate message', () => {
 assert.equal(logOutput('null','success'),'Operation completed.');
 assert.equal(logOutput('[]','pending'),'No log output yet.');
 assert.equal(logOutput('','failed'),'No log output available.');
});
const repository = {operation_revision:8, fetched_revision:'f'.repeat(40), previous_revision:'a'.repeat(40), connection_status:'connected', deployment_mode:'manual', convergence_status:'active'};
test('repository labels and connection failures use customer language', () => {
 const {repositoryName,connectionError} = require('./static/git.js');
 assert.equal(repositoryName('git@github.com:team/website.git'),'website');
 assert.match(connectionError('fatal: Remote branch missing not found in upstream origin'),/^Branch not found/);
 assert.match(connectionError('Permission denied (publickey)'),/Add the public key/);
});
test('key preparation is separate from saving and keeps the dialog in place', () => {
 assert.match(source, /git\/key/);
 assert.doesNotMatch(source, /submit\(form, null, true\)/);
 assert.doesNotMatch(source, /#git-settings'\)/);
});
test('partial replacement removes scripting-disabled fallback form controls', () => {
 assert.match(source,/next\.querySelectorAll\('noscript'\).*node\.remove\(\)/);
});
test('completed removal returns to empty state but pending removal remains visible', () => {
 const {removed} = require('./static/git.js');
 assert.equal(removed({...repository,connection_status:'disconnected',convergence_status:'in_sync'}),true);
 assert.equal(removed({...repository,connection_status:'disconnected',convergence_status:'pending'}),false);
 assert.equal(removed(repository),false);
});
test('SSH onboarding prepares once without publication or trusting an unverified host', () => {
 const {sshRemote, preparationFields} = require('./static/git.js');
 assert.equal(sshRemote('git@github.com:owner/repo.git'),true);
 assert.equal(sshRemote('ssh://git@github.com/owner/repo.git'),true);
 assert.equal(sshRemote('https://github.com/owner/repo.git'),false);
 const data = preparationFields(new URLSearchParams('deployment_mode=automatic&known_host_key=untrusted&branch=main'));
 assert.equal(data.get('deployment_mode'),'manual');
 assert.equal(data.get('known_host_key'),'');
 assert.equal(data.get('branch'),'main');
});
test('preview uses the fetched revision and stale-operation token', () => {
 const fields = operationFields(new URLSearchParams(), repository, 'preview');
 assert.equal(fields.get('revision'), repository.fetched_revision);
 assert.equal(fields.get('expected_revision'), '8');
 assert.equal(fields.get('confirm'), null);
});
test('rollback uses previous revision and explicit confirmation', () => {
 const fields = operationFields(new URLSearchParams(), repository, 'rollback');
 assert.equal(fields.get('revision'), repository.previous_revision);
 assert.equal(fields.get('confirm'), 'yes');
});
test('missing and disabled repositories cannot deploy or preview prematurely', () => {
 for (const action of ['deploy','rollback','preview','disconnect']) assert.equal(actionDisabled(null,action,false),true);
 assert.equal(actionDisabled(repository,'deploy',false),false);
 assert.equal(actionDisabled({...repository,deployment_mode:'disabled'},'deploy',false),true);
 assert.equal(actionDisabled({...repository,fetched_revision:''},'preview',false),true);
 assert.equal(actionDisabled(null,'save',false),false);
});
test('uncertain retry reuses a key but different revisions do not', () => {
 const keys = new Map(); let calls=0; const create=()=>String(++calls);
 const data = operationFields(new URLSearchParams(),repository,'deploy');
 assert.equal(operationKey(keys,'deploy',data,create).key,'1');
 assert.equal(operationKey(keys,'deploy',data,create).key,'1');
 data.set('revision','b'.repeat(40));
 assert.equal(operationKey(keys,'deploy',data,create).key,'2');
});
test('errors redact credential-bearing URLs', () => {
 assert.equal(safeError('failed https://user:secret@example.test/repo'), 'failed [repository URL redacted]');
});
test('Git refresh is bounded, scoped and does not reload the document', () => {
 assert.match(source, /attempts < 150/);
 assert.match(source, /AbortController/);
 assert.match(source, /event.stopPropagation\(\)/);
 assert.doesNotMatch(source, /location\.reload|setInterval|innerHTML\s*=/);
 assert.match(source, /expected_revision/);
 assert.match(source, /idempotency_key/);
 assert.match(source, /confirm_overwrite/);
 assert.match(source, /'X-Nakpanel-SPA': 'true'/);
 assert.match(source, /querySelectorAll\('\[data-git-message\]'\)/);
});
test('connection testing never dispatches the auto-publishing fetch action', () => {
 assert.match(source, /submit\(event\.target\.closest\('form'\), 'test'\)/);
});
test('disconnected repositories cannot run fetch, rollback or disconnect', () => {
 const disconnected = {...repository, connection_status:'disconnected'};
 for (const action of ['fetch','rollback','disconnect','test']) assert.equal(actionDisabled(disconnected,action,false),true,action);
 assert.equal(actionDisabled(disconnected,'save',false),false);
});
test('expired sessions and non-JSON failures have actionable errors', async () => {
 await assert.rejects(() => readResponse(new Response('login', {status:401})), /session.*sign in/i);
 await assert.rejects(() => readResponse(new Response('<html>proxy error</html>', {status:502})), /unavailable.*502/i);
 await assert.rejects(() => readResponse(new Response('invalid', {status:200})), /invalid response/i);
 assert.deepEqual(await readResponse(new Response('{"ok":true}', {status:200})), {ok:true});
});
