(function () {
  'use strict';
  function pending(state) { return state === 'pending' || state === 'running'; }
  function formBody(data) { return new URLSearchParams(data); }
  function targetURL(raw, current) {
    var target = new URL(raw, current), before = new URL(current);
    if (target.pathname === before.pathname && !target.hash) target.hash = target.searchParams.has('run') ? '#dns-sync' : before.hash;
    return target;
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {pending: pending, formBody: formBody, targetURL: targetURL};
  if (typeof document === 'undefined') return;
  var workspace = document.querySelector('[data-np-dns-settings-workspace]');
  if (!workspace) return;
  workspace.querySelectorAll('form[method="post"]').forEach(function (form) {
    if (form.matches('[data-np-reauth-form]')) return;
    form.addEventListener('submit', async function (event) {
      event.preventDefault(); event.stopPropagation();
      if (form.dataset.pending === 'true') return;
      var body = formBody(new FormData(form)), buttons = Array.from(form.querySelectorAll('[type=submit]'));
      var error = form.querySelector('[data-np-dns-error]');
      if (!error) { error = document.createElement('p'); error.className = 'np-gate is-blocked'; error.setAttribute('role','alert'); error.dataset.npDnsError = ''; form.prepend(error); }
      error.hidden = true; form.dataset.pending = 'true'; buttons.forEach(function (button) { button.disabled = true; });
      try {
        var response = await window.NakpanelUI.fetch(form.action, {method:'POST', body:body, credentials:'same-origin', headers:{'X-Nakpanel-SPA':'true'}});
        if (!response.ok) {
          if (response.status === 428) throw new Error('Confirm your administrator password with Authorize, then retry. Your entries are preserved.');
          var data = (response.headers.get('Content-Type') || '').includes('application/json') ? await response.json() : null;
          throw new Error(data && data.error || 'The request was not accepted. Check authorization and try again.');
        }
        var target = targetURL(response.url || window.location.href, window.location.href);
        if (target.origin !== window.location.origin) throw new Error('Unexpected redirect.');
        window.location.assign(target.href);
      } catch (failure) { error.textContent = failure.message; error.hidden = false; error.tabIndex=-1; error.focus(); }
      finally { form.dataset.pending = 'false'; buttons.forEach(function (button) { button.disabled = false; }); }
    });
  });
  workspace.querySelectorAll('[data-np-dns-progress-url]').forEach(function (panel) {
    var state = panel.dataset.state, attempts = 0, stopped = false;
    if (!pending(state)) return;
    async function refresh() {
      if (stopped) return;
      var error = panel.querySelector('[data-np-dns-progress-error]');
      if (++attempts > 90) { error.hidden=false;error.textContent='DNS is still pending. Refresh this page to check the applied state.';return; }
      try {
        var response = await window.NakpanelUI.fetch(panel.dataset.npDnsProgressUrl, {headers:{Accept:'application/json'},credentials:'same-origin'});
        if (!response.ok) throw new Error('DNS status could not be loaded.');
        var data = await response.json();
        if (!pending(data.run.status)) { window.location.reload(); return; }
      } catch (_) { error.hidden=false;error.textContent='Status could not be refreshed. Reload this page to check DNS convergence.';return; }
      window.setTimeout(refresh, 2000);
    }
    window.addEventListener('pagehide',function(){stopped=true;},{once:true});
    window.setTimeout(refresh, 1000);
  });
}());
