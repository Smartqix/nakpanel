(function () {
  'use strict';
  function running(state) { return ['queued','discovering','copying','verifying'].includes(state); }
  function count(value) { return Number.isSafeInteger(value) && value >= 0 ? String(value) : '0'; }
  if (typeof module !== 'undefined' && module.exports) module.exports = {running:running, count:count};
  if (typeof document === 'undefined') return;
  function request(url, options) {
    if (window.NakpanelUI) return window.NakpanelUI.fetch(url, options);
    return fetch(url, options);
  }
  document.querySelectorAll('[data-mail-import-source]').forEach(function (form) {
    var type = form.querySelector('[name=source_kind]'), button = form.querySelector('button[type=submit]');
    function mode() {
      form.querySelectorAll('[data-mail-source]').forEach(function (group) {
        group.hidden = group.getAttribute('data-mail-source') !== type.value;
        group.querySelectorAll('input').forEach(function (field) { field.disabled = group.hidden; });
      });
    }
    type.addEventListener('change', mode); mode();
    form.addEventListener('submit', function (event) {
      event.preventDefault(); if (form.dataset.pending === 'true') return;
      form.dataset.pending = 'true'; button.disabled = true; button.textContent = 'Checking source...';
      var error = form.querySelector('[data-mail-import-form-error]'); error.hidden = true;
      request(form.action, {method:'POST',body:new FormData(form),credentials:'same-origin',headers:{'X-Nakpanel-SPA':'true','X-Nakpanel-CSRF':form.querySelector('[name=csrf_token]').value}})
        .then(function (response) { return response.json(); })
        .then(function (data) { if (!data.ok) throw new Error(data.error || 'Source could not be checked.'); window.location.assign(data.redirect); })
        .catch(function (failure) { error.textContent = failure.message || 'Connection failed. Your entries are preserved.'; error.hidden = false; error.focus(); })
        .finally(function () { form.dataset.pending = 'false'; button.disabled = false; button.textContent = 'Check source and review'; });
    });
  });
  document.querySelectorAll('[data-np-mail-import-progress]').forEach(function (panel) {
    var timer, attempts = 0, closed = false, state = panel.getAttribute('data-state');
    var initialRunning = running(state), refreshButton = panel.querySelector('[data-mail-import-refresh]');
    function refresh() {
      if (closed) return;
      window.clearTimeout(timer); refreshButton.disabled = true;
      request(panel.getAttribute('data-status-url'), {credentials:'same-origin',headers:{Accept:'application/json'}})
        .then(function (response) { if (!response.ok) throw new Error('Could not refresh. Sign in again if your session expired.'); return response.json(); })
        .then(function (data) {
          if (closed) return; var item = data.import;
          panel.querySelectorAll('[data-mail-import-count]').forEach(function (node) { node.textContent = count(item[node.getAttribute('data-mail-import-count')]); });
          panel.querySelector('[data-mail-import-state]').textContent = String(item.state).replaceAll('_',' ');
          var error = panel.querySelector('[data-mail-import-error]'); error.textContent = item.last_error || ''; error.hidden = !item.last_error;
          if (initialRunning && !running(item.state)) { window.location.reload(); return; }
          if (running(item.state) && ++attempts < 120) timer = window.setTimeout(refresh, 2000);
        }).catch(function (failure) { var error = panel.querySelector('[data-mail-import-error]');error.textContent = failure.message;error.hidden = false; })
        .finally(function () { if (!closed) refreshButton.disabled = false; });
    }
    refreshButton.addEventListener('click', function () { attempts = 0;refresh(); });
    window.addEventListener('pagehide', function () { closed = true;window.clearTimeout(timer); }, {once:true});
    if (running(state)) refresh();
  });
}());
