(function () {
  'use strict';
  var fetch = typeof window !== 'undefined' && window.NakpanelUI ? window.NakpanelUI.fetch : typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;
  function sshRemote(value) { return /^(ssh:\/\/[^\s]+\/[^\s]+|[^\s@]+@[^\s:]+:[^\s]+)$/.test(value.trim()); }
  function removed(repo) { return Boolean(repo && repo.connection_status === 'disconnected' && repo.convergence_status === 'in_sync'); }
  function repositoryName(remote) { return String(remote || '').split(/[/:]/).pop().replace(/\.git$/,'') || 'Repository'; }
  function confirmAction(message, form) {
    return window.NakpanelUI && window.NakpanelUI.confirm ? window.NakpanelUI.confirm(message,form.querySelector('[type=submit]')) : Promise.resolve(window.confirm(message));
  }
  function preparationFields(data) {
    data.set('deployment_mode','manual'); data.set('automatic','false');
    data.set('known_host_key',''); data.delete('trust_host');
    return data;
  }
  function actionDisabled(repo, action, busy) {
    if (busy || repo && /pending|running|queued|applying/.test(repo.convergence_status || '')) return true;
    if (action === 'save') return false;
    if (!repo) return true;
    if (repo.connection_status === 'disconnected') return true;
    if (action === 'preview' || action === 'deploy') return !repo.fetched_revision || repo.connection_status !== 'connected' || action === 'deploy' && repo.deployment_mode === 'disabled';
    if (action === 'rollback') return !repo.previous_revision || repo.deployment_mode === 'disabled';
    return false;
  }
  function operationFields(data, repo, action) {
    data.set('expected_revision', repo ? repo.operation_revision : 0);
    if (action === 'deploy' || action === 'preview') data.set('revision', repo.fetched_revision);
    if (action === 'rollback') data.set('revision', repo.previous_revision);
    if (['deploy', 'rollback', 'disconnect'].includes(action)) { data.set('confirm', 'yes'); data.set('confirm_overwrite', 'true'); }
    return data;
  }
  function operationKey(keys, action, data, create) {
    var identity = action + ':' + new URLSearchParams(data).toString();
    if (!keys.has(identity)) keys.set(identity, create());
    return {identity: identity, key: keys.get(identity)};
  }
  function safeError(value) { return String(value || 'Git operation failed.').replace(/(?:https?|ssh):\/\/[^\s<>]+|git@[^\s<>]+/gi, '[repository URL redacted]'); }
  function connectionError(value) {
    if (/Remote branch .* not found|resolve Git branch/i.test(value || '')) return 'Branch not found. Check the branch name in Deployment options and try again.';
    if (/Permission denied \(publickey\)|Could not read from remote repository/i.test(value || '')) return 'Repository access was denied. Add the public key to your Git provider with read-only access, then retry.';
    if (/Host key verification failed/i.test(value || '')) return 'The Git server identity could not be verified. Check SSH server verification before retrying.';
    return safeError(value);
  }
  async function readResponse(response) {
    if (response.status === 401 || response.redirected) throw new Error('Your session may have expired. Refresh the page and sign in again.');
    var result;
    try { result = await response.json(); }
    catch (_) { throw new Error(response.ok ? 'The server returned an invalid response. Refresh status before retrying.' : 'Git service is unavailable (HTTP ' + response.status + '). Refresh status before retrying.'); }
    if (!result || typeof result !== 'object') throw new Error('The server returned an invalid response. Refresh status before retrying.');
    if (!response.ok || result.ok === false) throw new Error(safeError(result.error || result.message));
    return result;
  }
  function logOutput(value, status) {
    if (!value || ['null','[]'].includes(value.trim())) return ['pending','running','queued'].includes(status) ? 'No log output yet.' : status === 'failed' ? 'No log output available.' : 'Operation completed.';
    return safeError(value);
  }
  function init(root) {
    if (!root || root.dataset.gitReady) return;
    root.dataset.gitReady = 'true';
    var repository = null, loaded = false, busy = false, timer = null, keyTimer = null, attempts = 0, dirty = false, retryKeys = new Map(), preparedURL = '', keyBusy = false, joining = false, working = false;
    function authenticationFields() {
      root.querySelectorAll('[data-git-action="save"]').forEach(function (form) {
        var remote = form.querySelector('[name="remote_url"]');
        form.querySelectorAll('[data-git-ssh-field]').forEach(function (field) { field.hidden = !remote || !sshRemote(remote.value); });
      });
    }
    authenticationFields();
    root.querySelectorAll('dialog').forEach(function(dialog) {
      dialog.addEventListener('close', function() {
        clearTimeout(keyTimer);
        if (!joining) dirty = false;
      });
    });
    function text(selector, value) { var node = root.querySelector(selector); if (node) node.textContent = value || ''; }
    function message(value) { root.querySelectorAll('[data-git-message]').forEach(function (node) { node.textContent = value || ''; }); }
    function pending(repo) { return repo && /pending|running|queued|applying/.test(repo.convergence_status || ''); }
    function selectTab(id) {
      if (!['git-overview','git-deployments','git-history','git-settings'].includes(id)) id = 'git-overview';
      root.querySelectorAll('[data-git-panel]').forEach(function (panel) { panel.hidden = panel.id !== id; });
      root.querySelectorAll('[data-git-tabs] a').forEach(function (tab) { tab.setAttribute('aria-selected', String(tab.hash === '#' + id)); tab.tabIndex = tab.hash === '#' + id ? 0 : -1; });
      history.replaceState(null, '', location.pathname + location.search + '#' + id);
    }
    var tabs = root.querySelector('[data-git-tabs]');
    if (tabs) {
      tabs.setAttribute('role', 'tablist');
      tabs.querySelectorAll('a').forEach(function (tab) { tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', tab.hash.slice(1)); tab.addEventListener('click', function (event) { event.preventDefault(); selectTab(tab.hash.slice(1)); }); });
      tabs.addEventListener('keydown', function (event) { var links = Array.from(tabs.querySelectorAll('a')); var index = links.indexOf(document.activeElement); if (index < 0) return; if (event.key === 'ArrowRight') index = (index + 1) % links.length; else if (event.key === 'ArrowLeft') index = (index + links.length - 1) % links.length; else if (event.key === 'Home') index = 0; else if (event.key === 'End') index = links.length - 1; else return; event.preventDefault(); links[index].focus(); selectTab(links[index].hash.slice(1)); });
      selectTab(location.hash.slice(1));
      window.addEventListener('hashchange', function () { if (root.isConnected) selectTab(location.hash.slice(1)); });
    }
    async function request(url, options) {
      var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 15000);
      try {
        var response = await fetch(url, Object.assign({ credentials: 'same-origin', headers: { Accept: 'application/json', 'X-Nakpanel-SPA': 'true', 'X-Requested-With': 'XMLHttpRequest' }, signal: controller.signal }, options));
        return await readResponse(response);
      } finally { clearTimeout(timeout); }
    }
    function rows(selector, entries, columns) {
      var body = root.querySelector(selector); if (!body) return; body.replaceChildren();
      (entries || []).forEach(function (entry) { var tr = document.createElement('tr'); columns.forEach(function (column) { var td = document.createElement('td'); td.textContent = entry[column] || ''; tr.appendChild(td); }); if (selector === '[data-git-deployments]') { var td = document.createElement('td'), details = document.createElement('details'), summary = document.createElement('summary'), pre = document.createElement('pre'); summary.textContent = 'View log'; pre.textContent = logOutput(entry.output,entry.status); details.append(summary, pre); td.appendChild(details); tr.appendChild(td); } body.appendChild(tr); });
    }
    function controls() {
      root.querySelectorAll('[data-git-action]').forEach(function (form) { var button = form.querySelector('[type=submit]'); if (button) button.disabled = !loaded || actionDisabled(repository,form.dataset.gitAction,busy || keyBusy); });
      root.querySelectorAll('[data-git-prepare]').forEach(function(button) { button.disabled = busy || keyBusy || pending(repository); });
      root.querySelectorAll('[data-git-test]').forEach(function (button) { button.disabled = actionDisabled(repository,'test',busy); });
    }
    function render(state) {
      loaded = true;
      repository = state.repository;
      if (repository) {
        text('[data-git-remote]', repositoryName(repository.remote_url)); text('[data-git-status]', pending(repository) ? 'Working...' : repository.connection_status === 'connected' ? 'Connected' : repository.convergence_status === 'failed' ? 'Needs attention' : 'Not connected'); text('[data-git-branch]', repository.branch);
        text('[data-git-fetched]', repository.fetched_revision || 'Not fetched'); text('[data-git-deployed]', repository.deployed_revision || repository.last_revision || 'Not deployed'); text('[data-git-error]', repository.last_error ? connectionError(repository.last_error) : '');
        text('[data-git-key]', repository.deploy_public_key || (repository.connection_status === 'disconnected' ? 'Repository disconnected. Save the repository to generate a new deploy key.' : 'Save the repository to generate a deploy key.'));
        text('[data-git-key-title]',state.key_title); text('[data-git-key-fingerprint]',state.key_fingerprint || 'Preparing fingerprint...');
        root.querySelectorAll('[data-git-copy], [data-git-download]').forEach(function (button) { button.disabled = !repository.deploy_public_key; });
        text('[data-git-conflicts]', repository.conflicts && repository.conflicts.length ? 'Destination conflicts: ' + repository.conflicts.join(', ') : '');
        rows('[data-git-commits]', repository.commits, ['revision', 'subject', 'author', 'authored_at']);
        text('[data-git-commits-empty]', repository.commits && repository.commits.length ? '' : 'No fetched commits available.');
        var branches = root.querySelector('[data-git-branches]'); if (branches) { branches.replaceChildren(); (repository.branches || []).forEach(function (branch) { var option = document.createElement('option'); option.value = branch; branches.appendChild(option); }); }
      }
      var deployments = (state.deployments || []).filter(function (entry) { return ['deploy','rollback'].includes(entry.action); });
      rows('[data-git-deployments]', deployments, ['id', 'action', 'revision', 'status', 'finished_at']); text('[data-git-deployments-empty]', deployments.length ? '' : 'No deployments yet.'); controls();
    }
    async function refresh() {
      clearTimeout(timer);
      if (!root.isConnected) return;
      try {
        var state = await request(root.dataset.statusUrl);
        if (removed(state.repository) && !root.querySelector('#git-connect') || joining && state.repository && !pending(state.repository) && state.repository.connection_status === 'connected') {
          history.replaceState(null,'',location.pathname + location.search + '#git-overview');
          await reloadWorkspace();
          return;
        }
        render(state);
        if (joining && repository && repository.convergence_status === 'failed') { joining = false; message(connectionError(repository.last_error || 'Connection failed. Check repository access and retry.')); }
        if (pending(repository)) { working = true; attempts++; if (attempts < 150) timer = setTimeout(refresh, 2000); else message('Operation is still pending after five minutes. Use Refresh status to check again; do not resubmit.'); }
        else { attempts = 0; if (working) { working = false; message(repository && repository.convergence_status === 'failed' ? connectionError(repository.last_error || 'Operation failed. Retry after checking the error.') : 'Operation completed.'); } }
      } catch (error) { message('Status could not refresh. ' + error.message + ' Use Refresh status to retry.'); }
    }
    async function reloadWorkspace() {
      var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 15000);
      try {
        var response = await fetch(location.href, { credentials: 'same-origin', headers:{Accept:'text/html'}, signal: controller.signal }); if (!response.ok) throw new Error('Workspace refresh failed.');
        var parsed = new DOMParser().parseFromString(await response.text(), 'text/html'), next = parsed.querySelector('[data-np-git]');
        if (!next) throw new Error('Workspace refresh failed.'); clearTimeout(timer);
        // DOMParser uses scripting-disabled parsing: fallback required inputs
        // inside noscript would otherwise block enhanced form submissions.
        next.querySelectorAll('noscript').forEach(function(node) { node.remove(); });
        root.querySelectorAll('dialog[open]').forEach(function(dialog) { dialog.close(); });
        root.replaceWith(next); init(next);
        var focus = next.querySelector('[data-git-panel]:not([hidden]) button'); if (focus) focus.focus();
      } finally { clearTimeout(timeout); }
    }
    async function submit(form, override) {
      if (!loaded || busy || keyBusy || pending(repository)) return;
      var action = override || form.dataset.gitAction, data = new FormData(form), url = form.action;
      if (actionDisabled(repository,action,busy)) return;
      if (override) url = form.action.replace(/\/git$/, '/git/' + override);
      if (override && repository && ['remote_url', 'branch', 'deploy_target', 'known_host_key'].some(function (field) { return (data.get(field) || '') !== (repository[field] || ''); })) { message('Save the changed repository settings before testing the connection.'); return; }
      if (action === 'save' && sshRemote(data.get('remote_url') || '') && (!data.get('known_host_key') || data.get('trust_host') !== 'yes')) { form.querySelector('[data-git-host-details]').open = true; message('Verify the SSH server key before connecting.'); return; }
      if (action === 'disconnect' && !await confirmAction('Remove Repository?\nPublished website files, uploads, databases, and the remote repository will stay unchanged. Local Git access and the webhook will be removed.',form)) return;
      if (action === 'webhook' && !await confirmAction('Rotate the webhook URL? The previous URL will stop working.',form)) return;
      if (action === 'fetch' && repository.deployment_mode === 'automatic' && !await confirmAction('Pull updates and automatically publish the configured branch if destination checks pass?',form)) return;
      if (action === 'rollback' && !await confirmAction('Restore previously published commit ' + repository.previous_revision + '?',form)) return;
      operationFields(data,repository,action);
      var retry = operationKey(retryKeys,action,data,function () { return crypto.randomUUID(); });
      data.set('idempotency_key',retry.key);
      busy = true; controls(); message('Submitting operation...');
      try {
        if (action === 'deploy') {
          message('Checking destination files...');
          var preview = operationFields(new FormData(form), repository, 'preview');
          preview.delete('confirm'); preview.delete('confirm_overwrite');
          preview.set('idempotency_key',crypto.randomUUID());
          await request(url.replace(/\/deploy$/, '/preview'),{method:'POST',body:new URLSearchParams(preview)});
          var completed = false;
          for (var check = 0; check < 150 && root.isConnected; check++) {
            await new Promise(function(resolve) { setTimeout(resolve,2000); });
            render(await request(root.dataset.statusUrl));
            if (!pending(repository)) { completed = true; break; }
          }
          if (!completed) throw new Error('Destination check is still pending. Refresh status before retrying.');
          if (repository.convergence_status === 'failed') throw new Error(repository.last_error || 'Destination check failed.');
          var conflicts = repository.conflicts || [];
          if (!await confirmAction(conflicts.length ? 'Replace these destination files?\n' + conflicts.slice(0,20).join('\n') + '\nPublish the fetched commit?' : 'Publish the fetched commit to this website? No destination conflicts were found.',form)) { message('Deployment cancelled. Website unchanged.'); return; }
          operationFields(data,repository,action);
          data.set('idempotency_key',crypto.randomUUID());
        }
        var result = await request(url, { method: 'POST', body: new URLSearchParams(data) });
        retryKeys.delete(retry.identity);
        if (action === 'save' || action === 'disconnect') dirty = false;
        if (action === 'webhook' && result.webhook_path) { text('[data-git-webhook]', new URL(result.webhook_path, location.origin).href); message('Webhook URL shown once. Store it securely at your Git provider.'); return; }
        joining = action === 'save';
        message(action === 'save' ? 'Connecting and fetching repository...' : action === 'disconnect' ? 'Removing repository access. Your website stays unchanged...' : 'Operation accepted. Checking status...'); attempts = 0;
        await refresh();
      } catch (error) { message(safeError(error.message) + ' Check status before trying again.'); }
      finally { busy = false; controls(); }
    }
    root.addEventListener('submit', function (event) { var form = event.target.closest('[data-git-form]'); if (!form) return; event.preventDefault(); event.stopPropagation(); submit(form); });
    root.addEventListener('input', function (event) {
      var form = event.target.closest('[data-git-action="save"]');
      if (!form) return;
      dirty = true; authenticationFields();
      if (event.target.name === 'remote_url') {
        clearTimeout(keyTimer);
        var value = event.target.value.trim();
        if (value !== preparedURL) {
          form.querySelector('[data-git-prepared]').hidden = true;
          form.querySelector('[data-git-prepare]').hidden = false;
          if (sshRemote(value)) keyTimer = setTimeout(function() { prepareKey(form); },600);
        }
      }
    });
    async function prepareKey(form) {
      if (!root.isConnected || !form || keyBusy || busy || pending(repository)) return;
      clearTimeout(keyTimer);
      var remote = form.querySelector('[name="remote_url"]').value.trim();
      if (!sshRemote(remote)) return;
      var data = new FormData(form);
      keyBusy = true; controls(); message('Preparing SSH public key...');
      try {
        var result = await request(form.action.replace(/\/git$/, '/git/key'), {method:'POST',body:new URLSearchParams(data)});
        if (form.querySelector('[name="remote_url"]').value.trim() !== remote || !root.isConnected) return;
        preparedURL = remote;
        form.querySelector('[data-git-prepared]').hidden = false;
        form.querySelector('[data-git-prepared-key]').textContent = result.public_key;
        form.querySelector('[data-git-prepared-title]').textContent = result.key_title;
        form.querySelector('[data-git-prepare]').hidden = true;
        if (result.trusted_host_key) {
          form.querySelector('[name="known_host_key"]').value = result.trusted_host_key;
          form.querySelector('[name="trust_host"]').checked = true;
          form.querySelector('[data-git-host-details] summary').textContent = 'GitHub SSH server verified';
        }
        message('Add this key to your Git provider, then select Add Repository. Nothing has been connected yet.');
      } catch(error) { form.querySelector('[data-git-prepare]').hidden = false; message(safeError(error.message)); }
      finally { keyBusy = false; controls(); }
    }
    root.addEventListener('focusout', function (event) {
      if (event.target.name !== 'remote_url' || busy) return;
      var form = event.target.closest('[data-git-action="save"]'), value = event.target.value.trim();
      if (!form || !sshRemote(value) || value === preparedURL) return;
      prepareKey(form);
    });
    window.addEventListener('beforeunload', function (event) { if (root.isConnected && dirty) { event.preventDefault(); event.returnValue = ''; } });
    root.addEventListener('click', async function (event) {
      if (event.target.closest('[data-git-prepare]')) prepareKey(event.target.closest('form'));
      var copy = event.target.closest('[data-git-copy-prepared], [data-git-copy-prepared-title]');
      if (copy) {
        var selector = copy.hasAttribute('data-git-copy-prepared-title') ? '[data-git-prepared-title]' : '[data-git-prepared-key]';
        try { await navigator.clipboard.writeText(copy.closest('form').querySelector(selector).textContent); message('Copied.'); }
        catch (_) { message('Copy failed. Select the text and copy it manually.'); }
      }
      if (event.target.closest('[data-git-refresh]')) { attempts = 0; refresh(); }
      if (event.target.closest('[data-git-test]')) submit(event.target.closest('form'), 'test');
      if (event.target.closest('[data-git-copy]')) { try { await navigator.clipboard.writeText(repository.deploy_public_key); message('Public key copied.'); } catch (_) { message('Copy failed. Select the public key and copy it manually.'); } }
      if (event.target.closest('[data-git-copy-title]')) { try { await navigator.clipboard.writeText(root.querySelector('[data-git-key-title]').textContent); message('Key title copied.'); } catch (_) { message('Copy failed. Select the title and copy it manually.'); } }
      if (event.target.closest('[data-git-download]') && repository && repository.deploy_public_key) {
        var blobURL = URL.createObjectURL(new Blob([repository.deploy_public_key + '\n'], {type:'text/plain'}));
        var link = document.createElement('a'); link.href = blobURL; link.download = 'nakpanel-deploy-key.pub'; link.click();
        setTimeout(function () { URL.revokeObjectURL(blobURL); },1000);
      }
    });
    controls();
    refresh();
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {actionDisabled, operationFields, operationKey, safeError, logOutput, readResponse, sshRemote, preparationFields, removed, repositoryName, connectionError};
  if (typeof document !== 'undefined') document.querySelectorAll('[data-np-git]').forEach(init);
})();
