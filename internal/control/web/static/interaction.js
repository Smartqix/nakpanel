(function () {
  'use strict';
  function createClient(environment) {
    async function request(input, options) {
      options = options || {};
      var url = new URL(input, environment.baseURL);
      if (url.origin !== new URL(environment.baseURL).origin) throw new Error('Panel requests must be same-origin.');
      var headers = new Headers(options.headers), method = (options.method || 'GET').toUpperCase();
      if (!headers.has('Accept')) headers.set('Accept','application/json');
      var json = headers.get('Accept').includes('application/json');
      if (method !== 'GET' && method !== 'HEAD') {
        if (json) headers.set('X-Nakpanel-SPA','true');
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
        if (response.redirected && json) throw new Error('The server returned a page instead of an operation result. Check status before resubmitting.');
        if (json) {
          var payload;
          try { payload = await response.clone().json(); }
          catch (_) { throw new Error('The server returned an unexpected response (HTTP ' + response.status + '). Check status before retrying.'); }
          if (!response.ok || payload && payload.ok === false) throw new Error(payload && (payload.error || payload.message) || 'Request failed (HTTP ' + response.status + ').');
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
  if (typeof module !== 'undefined' && module.exports) module.exports = {createClient:createClient};
  if (typeof window !== 'undefined') window.NakpanelUI = createClient({baseURL:window.location.href,fetch:window.fetch.bind(window),csrf:function () { var meta=document.querySelector('meta[name="nakpanel-csrf"]'); return meta ? meta.content : ''; }});
})();
