(function () {
  'use strict';
  function createDialogController(environment) {
    var document = environment.document, frames = [], prepared = new WeakMap();
    function top() { return frames.length ? frames[frames.length - 1].dialog : null; }
    function focusable(dialog) {
      return Array.from(dialog.querySelectorAll('a[href], button, summary, input:not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])')).filter(function (control) {
        var collapsed = control.closest('details:not([open])'), summary = collapsed && collapsed.querySelector('summary');
        return !control.disabled && !control.hidden && !control.closest('[hidden], [inert]') && (!collapsed || summary && summary.contains(control)) && control.getClientRects().length > 0;
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
      var cancel = function (event) { event.preventDefault(); close(dialog); };
      // Native close events are queued; an older event must not close a reopened dialog.
      var onClose = function () { if (!dialog.open) closed(dialog); };
      dialog.addEventListener('cancel', cancel);
      dialog.addEventListener('close', onClose);
      prepared.set(dialog, {cancel:cancel, close:onClose});
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
    function unmount(root) {
      // Close from the top down while triggers still belong to the live DOM.
      frames.slice().reverse().forEach(function (frame) {
        if (frame.dialog === root || root.contains(frame.dialog) || frame.trigger && (frame.trigger === root || root.contains(frame.trigger))) close(frame.dialog);
      });
      var dialogs = Array.from(root.querySelectorAll('dialog[data-np-dialog]'));
      if (prepared.has(root)) dialogs.push(root);
      dialogs.forEach(function (dialog) {
        var listeners = prepared.get(dialog);
        if (!listeners) return;
        dialog.removeEventListener('cancel', listeners.cancel);
        dialog.removeEventListener('close', listeners.close);
        prepared.delete(dialog);
      });
    }
    function sensitiveField(field) {
      return /^(password|file)$/i.test(field.type) || /password|private_key/i.test(field.name || '') || field.name === 'secrets' ||
        field.hasAttribute && field.hasAttribute('data-np-sensitive');
    }
    function safeFields(form) {
      return Array.from(form.elements).filter(function (field) {
        return field.name && !sensitiveField(field) && !/^(submit|button|reset|image)$/i.test(field.type) && !(field.type === 'hidden' && /csrf/i.test(field.name));
      });
    }
    function prefill(dialog, trigger) {
      var values;
      try { values = JSON.parse(trigger && trigger.getAttribute('data-np-dialog-prefill')); } catch (_) { return; }
      if (!values || typeof values !== 'object' || Array.isArray(values)) return;
      dialog.querySelectorAll('input[name], select[name], textarea[name]').forEach(function (field) {
        if (!Object.prototype.hasOwnProperty.call(values, field.name) || /^(password|file|hidden)$/i.test(field.type)) return;
        if (/^(checkbox|radio)$/.test(field.type)) field.checked = field.type === 'checkbox' && typeof values[field.name] === 'boolean' ? values[field.name] : String(values[field.name]) === field.value;
        else field.value = String(values[field.name]);
        field.dispatchEvent(new Event('change', {bubbles:true}));
      });
    }
    function capture(form) {
      var dialog = form.closest('dialog.np-drawer, dialog.np-mail-dialog');
      if (!dialog || !dialog.id) return null;
      return {id:dialog.id, fields:safeFields(form).map(function (field) {
        return {name:field.name, type:field.type, value:field.value, checked:field.checked,
          selected:field.multiple ? Array.from(field.options).filter(function (option) { return option.selected; }).map(function (option) { return option.value; }) : null};
      })};
    }
    function restore(snapshot, main) {
      if (!snapshot) return false;
      var error = main.querySelector('.np-notice[role="alert"]');
      var dialog = document.getElementById(snapshot.id);
      if (!error || !dialog || !dialog.matches('dialog.np-drawer, dialog.np-mail-dialog')) return false;
      var form = dialog.querySelector('form[method="post"]');
      if (!form) return false;
      // Shell drawers survive the swap. Clear their old sensitive inputs too;
      // newly rendered content drawers already start with these fields empty.
      Array.from(form.elements).forEach(function (field) { if (sensitiveField(field)) field.value = ''; });
      var fields = safeFields(form), restored = [];
      snapshot.fields.forEach(function (entry) {
        var index = fields.findIndex(function (field) { return field.name === entry.name && field.type === entry.type; });
        if (index < 0) return;
        var field = fields.splice(index, 1)[0];
        if (entry.selected) Array.from(field.options).forEach(function (option) { option.selected = entry.selected.includes(option.value); });
        else if (/^(checkbox|radio)$/.test(field.type)) field.checked = entry.checked;
        else field.value = entry.value;
        if (field.type !== 'hidden') restored.push(field);
      });
      // Apply the complete snapshot before dependent controls recompute their
      // visibility, disabled and required state (for example OCI route/health).
      restored.forEach(function (field) { field.dispatchEvent(new Event('change', {bubbles:true})); });
      var prior = dialog.querySelector('[data-np-drawer-error]'); if (prior) prior.remove();
      // The page notice is inert behind a native modal. Repeat it inside the
      // drawer so keyboard and screen-reader users can reach the failure.
      var notice = error.cloneNode(true);
      notice.setAttribute('data-np-drawer-error', ''); notice.setAttribute('tabindex', '-1');
      var body = dialog.querySelector('.np-drawer-body') || form;
      body.prepend(notice);
      var trigger = Array.from(document.querySelectorAll('[data-np-dialog-open]')).find(function (element) { return element.getAttribute('data-np-dialog-open') === snapshot.id; });
      open(dialog, trigger);
      body.scrollTop = 0; notice.focus({preventScroll:true});
      return true;
    }
    return {open: open, close: close, prepare: prepare, top: top, focusable: focusable, unmount:unmount, prefill:prefill, capture:capture, restore:restore};
  }
  function createClient(environment) {
    async function request(input, options) {
      options = options || {};
      var baseURL = typeof environment.baseURL === 'function' ? environment.baseURL() : environment.baseURL;
      var url = new URL(input, baseURL);
      if (url.origin !== new URL(baseURL).origin) throw new Error('Panel requests must be same-origin.');
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
        if (response.url && new URL(response.url).origin !== url.origin) throw new Error('The server returned a response outside this panel. Check status before retrying.');
        if (response.status === 401 || response.redirected && response.url && new URL(response.url).pathname === '/login') {
          var authError = new Error('Your session expired. Refresh this page and sign in again.');
          authError.status = 401;
          authError.location = response.headers.get('X-Nakpanel-Location') || '/login';
          throw authError;
        }
        if (options.allowPageResponse && (!json && method === 'POST' || response.ok && (response.redirected || (response.headers.get('Content-Type') || '').includes('text/html')))) return response;
        if (response.redirected && json) throw new Error('The server returned a page instead of an operation result. Check status before resubmitting.');
        if (json && response.status !== 204 && !(response.status === 202 && !(response.headers.get("Content-Type") || "").includes("json"))) {
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
        // form.elements includes controls linked with a form attribute and
        // excludes nested controls owned by a different form.
        var controls = Array.from(form.elements).filter(function (control) {
          return control.matches('button[type="submit"], input[type="submit"]');
        });
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
    window.NakpanelUI = createClient({baseURL:function () { return document.baseURI || window.location.href; },fetch:window.fetch.bind(window),csrf:function () { var meta=document.querySelector('meta[name="nakpanel-csrf"]'); return meta ? meta.content : ''; }});
    window.NakpanelUI.createDialogController = createDialogController;
  }
})();
