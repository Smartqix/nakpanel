(function () {
  'use strict';
  function createDialogController(environment) {
    var document = environment.document, frames = [], prepared = new WeakSet();
    function top() { return frames.length ? frames[frames.length - 1].dialog : null; }
    function focusable(dialog) {
      return Array.from(dialog.querySelectorAll('a[href], button, input:not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])')).filter(function (control) {
        return !control.disabled && !control.hidden && !control.closest('[hidden], [inert]') && control.getClientRects().length > 0;
      });
    }
    function focus(dialog) {
      var controls = focusable(dialog);
      var cancel = dialog.querySelector('[data-np-confirmation-cancel]');
      var target = cancel && controls.includes(cancel) ? cancel : controls.find(function (control) { return control.matches('[autofocus], [data-np-autofocus]'); });
      if (!target) target = controls.find(function (control) { return /^(INPUT|SELECT|TEXTAREA)$/.test(control.tagName); });
      if (!target) target = controls.find(function (control) { return control.matches('.np-dialog-actions [data-np-dialog-close]'); });
      if (!target) target = controls.find(function (control) { return !control.matches('[data-np-dialog-close], .np-dialog-close button'); });
      (target || controls[0] || dialog).focus();
    }
    function closed(dialog) {
      var index = frames.findIndex(function (frame) { return frame.dialog === dialog; });
      if (index < 0) return;
      var wasTop = index === frames.length - 1, frame = frames.splice(index, 1)[0];
      document.body.classList.toggle('np-modal-open', frames.length > 0);
      if (environment.onClose) environment.onClose(dialog);
      if (!wasTop) return;
      var parent = frame.trigger && frame.trigger.closest('dialog');
      if (frame.trigger && frame.trigger.isConnected && !frame.trigger.disabled && (!parent || parent.open)) frame.trigger.focus();
      else if (top()) focus(top());
    }
    function prepare(dialog) {
      if (!dialog || prepared.has(dialog)) return;
      prepared.add(dialog);
      var heading = dialog.querySelector('.np-dialog-head h2, h2');
      if (heading && !dialog.getAttribute('aria-label') && !dialog.getAttribute('aria-labelledby')) {
        if (!heading.id) heading.id = dialog.id + '-title';
        dialog.setAttribute('aria-labelledby', heading.id);
      }
      var description = dialog.querySelector('.np-dialog-head p');
      if (description && !dialog.getAttribute('aria-describedby')) {
        if (!description.id) description.id = dialog.id + '-description';
        dialog.setAttribute('aria-describedby', description.id);
      }
      dialog.setAttribute('tabindex', '-1');
      dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(dialog); });
      // Native close events are queued; an older event must not close a reopened dialog.
      dialog.addEventListener('close', function () { if (!dialog.open) closed(dialog); });
    }
    function open(dialog, trigger) {
      if (!dialog || !dialog.showModal) return;
      prepare(dialog);
      if (dialog.open) { focus(dialog); return; }
      var opener = trigger || document.activeElement;
      dialog.showModal();
      frames.push({dialog: dialog, trigger: opener});
      document.body.classList.toggle('np-modal-open', true);
      focus(dialog);
    }
    function close(dialog) {
      if (!dialog) return;
      if (dialog.open) dialog.close();
      closed(dialog);
    }
    return {open: open, close: close, prepare: prepare, top: top, focusable: focusable};
  }
  function createClient(environment) {
    async function request(input, options) {
      options = options || {};
      var url = new URL(input, environment.baseURL);
      if (url.origin !== new URL(environment.baseURL).origin) throw new Error('Panel requests must be same-origin.');
      var headers = new Headers(options.headers), method = (options.method || 'GET').toUpperCase();
      if (!headers.has('Accept')) headers.set('Accept','application/json');
      var json = headers.get('Accept').includes('application/json');
      if (method !== 'GET' && method !== 'HEAD') {
        if (json && !headers.has('X-Nakpanel-SPA')) headers.set('X-Nakpanel-SPA','true');
        var token = environment.csrf ? environment.csrf() : '';
        if (token && !headers.has('X-Nakpanel-CSRF')) headers.set('X-Nakpanel-CSRF',token);
      }
      var controller = new AbortController();
      var abort = function () { controller.abort(); };
      if (options.signal) { if (options.signal.aborted) abort(); else options.signal.addEventListener('abort',abort,{once:true}); }
      var timeout = setTimeout(abort,30000);
      try {
        var response;
        try { response = await environment.fetch(url.href,Object.assign({},options,{headers:headers,credentials:'same-origin',cache:'no-store',signal:controller.signal})); }
        catch (_) { throw new Error('The request could not finish. Check status before trying again; the operation may already have been accepted.'); }
        if (response.status === 401 || response.redirected && response.url && new URL(response.url).pathname === '/login') throw new Error('Your session expired. Refresh this page and sign in again.');
        if (response.url && new URL(response.url).origin !== url.origin) throw new Error('The server returned a response outside this panel. Check status before retrying.');
        if (options.allowPageResponse && response.ok && (response.redirected || (response.headers.get('Content-Type') || '').includes('text/html'))) return response;
        if (response.redirected && json) throw new Error('The server returned a page instead of an operation result. Check status before resubmitting.');
        if (json) {
          var payload;
          try { payload = await response.clone().json(); }
          catch (_) { throw new Error('The server returned an unexpected response (HTTP ' + response.status + '). Check status before retrying.'); }
          if (!response.ok || payload && payload.ok === false) {
            var error = new Error(payload && (payload.error || payload.message) || 'Request failed (HTTP ' + response.status + ').');
            error.payload = payload;
            error.status = response.status;
            throw error;
          }
        } else if (!response.ok) throw new Error('The view could not refresh (HTTP ' + response.status + ').');
        return response;
      } finally {
        clearTimeout(timeout);
        if (options.signal) options.signal.removeEventListener('abort',abort);
      }
    }
    var states = new WeakMap();
    function setBusy(form,busy) {
      if (busy && !states.has(form)) {
        var controls = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"]'));
        states.set(form,controls.map(function (control) { return [control,control.disabled]; }));
        controls.forEach(function (control) { control.disabled = true; });
      } else if (!busy && states.has(form)) {
        states.get(form).forEach(function (entry) { entry[0].disabled = entry[1]; }); states.delete(form);
      }
      form.setAttribute('aria-busy',busy ? 'true' : 'false');
    }
    return {fetch:request,setBusy:setBusy};
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {createClient:createClient,createDialogController:createDialogController};
  if (typeof window !== 'undefined') {
    window.NakpanelUI = createClient({baseURL:window.location.href,fetch:window.fetch.bind(window),csrf:function () { var meta=document.querySelector('meta[name="nakpanel-csrf"]'); return meta ? meta.content : ''; }});
    window.NakpanelUI.createDialogController = createDialogController;
  }
})();
