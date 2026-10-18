(function () {
  'use strict';
  // Server routes that launch another document or change authentication context:
  // /db, /database-manager/{grantID}/{path...}, POST /databases/{id}/manager,
  // /login, /logout, /support/... and assets/downloads/exports. Webmail is
  // currently POST /webmail; terminal has no GET route yet, so reserve it too.
  var EXCLUDED_PATHS = ['/logout', '/login', '/assets', '/support', '/db', '/database-manager', '/webmail', '/terminal', '/tools-settings/terminal'];
  function excludedPath(pathname) {
    return EXCLUDED_PATHS.some(function (path) { return pathname === path || pathname.indexOf(path + '/') === 0; }) || /\/(?:download|export)/i.test(pathname) || /^\/databases\/[^/]+\/manager(?:\/|$)/.test(pathname);
  }
  function linkEligible(anchor, event, current) {
    if (!anchor || event.defaultPrevented || event.button != null && event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;
    var href = anchor.getAttribute('href'), target = anchor.getAttribute('target');
    if (!href || target !== null && target.toLowerCase() !== '_self' || anchor.hasAttribute('download') || anchor.hasAttribute('data-np-full-nav') || anchor.closest('[data-np-full-nav]')) return false;
    try {
      var url = new URL(href, current), before = new URL(current);
      if (!/^https?:$/.test(url.protocol) || url.origin !== before.origin) return false;
      if (url.pathname === before.pathname && url.search === before.search && (href.charAt(0) === '#' || url.hash || url.hash !== before.hash)) return false;
      return !excludedPath(url.pathname);
    } catch (_) { return false; }
  }
  function isCurrent(id, latest, signal) { return id === latest && !signal.aborted; }
  function decode(value) {
    return value.replace(/&(#x[\da-f]+|#\d+|amp|quot|apos|lt|gt);/gi, function (all, entity) {
      if (entity.charAt(0) === '#') {
        var code = entity.charAt(1).toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
        return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '\ufffd';
      }
      return {amp:'&', quot:'"', apos:"'", lt:'<', gt:'>'}[entity.toLowerCase()];
    });
  }
  // Only parse the envelope here. The browser parses the nested page markup once
  // the response has passed this DOM-independent contract check.
  function parseFragment(html) {
    var tags = html.match(/<template\b[^>]*>/gi) || [], meta;
    tags.forEach(function (tag) {
      var attrs = {};
      tag.replace(/([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g, function (_, key, double, single) { attrs[key] = decode(double == null ? single : double); });
      if (attrs['data-np-shell'] === 'meta') meta = attrs;
    });
    if (!meta) throw new Error('Invalid panel fragment.');
    // site-dialog is an optional shell template for older fragment responses.
    var full = meta['data-full-document'] === 'true', keep = meta['data-keep-shell'] === 'true';
    if (!full && (!/<div\b[^>]*\bdata-np-fragment=["']main["']/i.test(html) || !keep && !['sidebar', 'topbar', 'support'].every(function (part) { return tags.some(function (tag) { return new RegExp('data-np-shell=["\']' + part + '["\']').test(tag); }); }))) throw new Error('Incomplete panel fragment.');
    return {title:meta['data-title'] || '', bodyClass:meta['data-body-class'] || '', route:meta['data-route'] || '', fullDocument:full, keepShell:keep};
  }
  function optimisticActive(links, clicked) {
    var previous = Array.from(links).map(function (link) { return [link, link.classList.contains('is-active'), link.getAttribute('aria-current')]; });
    previous.forEach(function (entry) {
      entry[0].classList.toggle('is-active', entry[0] === clicked);
      if (entry[0] === clicked) entry[0].setAttribute('aria-current', 'page'); else entry[0].removeAttribute('aria-current');
    });
    var restored = false;
    return function () { if (restored) return; restored = true; previous.forEach(function (entry) {
      entry[0].classList.toggle('is-active', entry[1]);
      if (entry[2] === null) entry[0].removeAttribute('aria-current'); else entry[0].setAttribute('aria-current', entry[2]);
    }); };
  }
  function formMethod(form, submitter) { return ((submitter && submitter.getAttribute('formmethod')) || form.getAttribute('method') || 'get').toLowerCase(); }
  function formAction(form, submitter, current) { return new URL((submitter && submitter.getAttribute('formaction')) || form.getAttribute('action') || form.action || current, current).href; }
  function formEligible(form, event, current) {
    var submitter = event.submitter;
    if (typeof document !== 'undefined' && document.body.hasAttribute('data-np-document-only')) return false;
    if (!form || event.defaultPrevented || !form.closest('#main-content, dialog[open], [role="dialog"][aria-modal="true"], [data-np-drawer][open]')) return false;
    if (!/^(get|post)$/.test(formMethod(form, submitter)) || form.hasAttribute('data-np-full-nav') || form.hasAttribute('target') || submitter && (submitter.hasAttribute('data-np-full-nav') || submitter.hasAttribute('formtarget'))) return false;
    if (formEnctype(form, submitter) === 'text/plain') return false;
    if (Array.from(form.querySelectorAll('input[type="file"]')).some(function (input) { return input.files && input.files.length || input.value; })) return false;
    try { var url = new URL(formAction(form, submitter, current)); return url.origin === new URL(current).origin && !excludedPath(url.pathname); } catch (_) { return false; }
  }
  function urlencoded(entries) {
    var params = new URLSearchParams();
    for (var entry of entries) params.append(entry[0], typeof entry[1] === 'string' ? entry[1] : entry[1].name);
    return params;
  }
  function formURL(action, entries, current) {
    var url = new URL(action, current);
    url.search = urlencoded(entries).toString(); return url.href;
  }
  function formEnctype(form, submitter) { return ((submitter && submitter.getAttribute('formenctype')) || form.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase(); }
  function createPrefetchCache(environment) {
    var entries = new Map(), pending = new Map(), queue = [], active = 0, generation = 0;
    var now = environment.now || Date.now;
    function clear() {
      generation++; entries.clear();
      queue.splice(0).forEach(function (task) { task.resolve(); });
      pending.forEach(function (task) { task.controller.abort(); }); pending.clear();
    }
    function drain() {
      while (active < 2 && queue.length) {
        var task = queue.shift(); active++; run(task);
      }
    }
    async function run(task) {
      try {
        var response = await environment.fetch(task.url, task.controller.signal);
        if (task.generation === generation && !task.controller.signal.aborted) {
          entries.delete(task.url); entries.set(task.url, {response:response, expires:now() + 30000});
          while (entries.size > 8) entries.delete(entries.keys().next().value);
        }
      } catch (_) { if (task.generation === generation) clear(); }
      finally {
        active--; if (pending.get(task.url) === task) pending.delete(task.url);
        task.resolve(); drain();
      }
    }
    return {
      clear:clear,
      get:function (url) {
        var entry = entries.get(url);
        if (!entry) return null;
        if (entry.expires <= now()) { entries.delete(url); return null; }
        return entry.response.clone();
      },
      prefetch:function (url) {
        var connection = environment.connection && environment.connection();
        if (connection && connection.saveData || new URL(url).searchParams.has('notice')) return Promise.resolve();
        if (entries.has(url) && entries.get(url).expires > now()) return Promise.resolve();
        if (pending.has(url)) return pending.get(url).promise;
        var task = {url:url, generation:generation, controller:new AbortController()};
        task.promise = new Promise(function (resolve) { task.resolve = resolve; });
        pending.set(url, task); queue.push(task); drain(); return task.promise;
      }
    };
  }
  function createLifecycle() {
    var mounts = [], unmounts = [], controllers = new WeakMap(), active = new Map();
    function signal(root) {
      if (!controllers.has(root)) {
        var controller = new AbortController(); controllers.set(root, controller); active.set(root, controller);
      }
      return controllers.get(root).signal;
    }
    return {
      onMount: function (fn) { mounts.push(fn); },
      onUnmount: function (fn) { unmounts.push(fn); },
      signal: signal,
      mount: function (root) { if (controllers.has(root) && controllers.get(root).signal.aborted) controllers.delete(root); signal(root); mounts.forEach(function (fn) { fn(root); }); },
      unmount: function (root) {
        active.forEach(function (controller, element) {
          if (element === root || root.contains(element)) { controller.abort(); active.delete(element); }
        });
        unmounts.forEach(function (fn) { fn(root); });
      }
    };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {urlencoded:urlencoded, formEnctype:formEnctype, linkEligible:linkEligible, isCurrent:isCurrent, parseFragment:parseFragment, createLifecycle:createLifecycle, EXCLUDED_PATHS:EXCLUDED_PATHS, optimisticActive:optimisticActive, formEligible:formEligible, formURL:formURL, createPrefetchCache:createPrefetchCache};
  if (typeof window === 'undefined') return;
  var ui = window.NakpanelUI, document = window.document;
  if (!ui) return;
  var lifecycle = ui.lifecycle = createLifecycle();
  if (document.body.dataset.npNav !== 'on') return;
  // Browsers reserve Sec-* request headers; Purpose is the script-settable
  // fallback that lets the server preserve one-shot cookies reliably.
  var prefetch = createPrefetchCache({connection:function () { return window.navigator && window.navigator.connection; }, fetch:async function (url, signal) {
    var response = await ui.fetch(url, {headers:{Accept:'text/html', 'X-Nakpanel-Fragment':'main', 'Sec-Purpose':'prefetch', Purpose:'prefetch'}, allowPageResponse:true, signal:signal});
    if (!(response.headers.get('Content-Type') || '').toLowerCase().includes('text/html') || response.headers.get('X-Nakpanel-Location')) throw new Error('Prefetch unavailable.');
    var meta = parseFragment(await response.clone().text());
    if (meta.fullDocument || meta.keepShell) throw new Error('Document requires navigation.');
    return response;
  }});
  var sequence = 0, controller, currentURL = window.location.href, currentState, renderedIndex, suppressedIndex = null;
  var history = window.history;
  history.scrollRestoration = 'manual';
  // Browsers throttle history writes: Chrome silently ignores them after about
  // 200 in 10 s and Safari throws after 100 in 30 s. Scroll positions therefore
  // live in memory per entry and reach history.state only when an entry is left
  // or scrolling settles, so the pushState a navigation needs stays reliable.
  var scrollMemory = new Map(), historyWrites = [], scrollTimer;
  function newEntryKey() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  function writeHistory(method, state, url, optional) {
    var now = Date.now();
    historyWrites = historyWrites.filter(function (at) { return now - at < 30000; });
    if (optional && historyWrites.length >= 40) return false;
    historyWrites.push(now);
    try { history[method](state, '', url); return true; } catch (_) { return false; }
  }
  function entryIndex(state) { return state && Number.isInteger(state.npIndex) ? state.npIndex : null; }
  renderedIndex = entryIndex(history.state);
  if (renderedIndex === null) renderedIndex = 0;
  currentState = Object.assign({}, history.state, {npNav:true, npKey:(history.state && history.state.npKey) || newEntryKey(), npIndex:renderedIndex, scrollY:window.scrollY});
  writeHistory('replaceState', currentState, currentURL);
  var live = document.createElement('div');
  live.className = 'np-sr-only'; live.setAttribute('aria-live', 'polite'); live.setAttribute('aria-atomic', 'true');
  document.body.appendChild(live);
  function renderedEntryIsCurrent() {
    if (!history.state || history.state.npKey !== currentState.npKey) return false;
    // Tool tabs own their hash within the same entry. Keep it when recording
    // scroll without adopting a pending Back/Forward navigation's address.
    if (window.location.href.split('#')[0] !== currentURL.split('#')[0]) return false;
    currentURL = window.location.href;
    return true;
  }
  function rememberScroll(optional) {
    if (!renderedEntryIsCurrent()) return;
    scrollMemory.set(currentState.npKey, window.scrollY);
    var state = Object.assign({}, currentState, {scrollY:window.scrollY});
    if (writeHistory('replaceState', state, currentURL, optional)) currentState = state;
  }
  function restoreRenderedEntry() {
    var targetIndex = entryIndex(history.state);
    if (renderedIndex !== null && targetIndex !== null) {
      if (renderedIndex !== targetIndex && suppressedIndex !== renderedIndex) {
        suppressedIndex = renderedIndex;
        history.go(renderedIndex - targetIndex);
      }
    } else if (window.location.href !== currentURL) writeHistory('pushState', currentState, currentURL);
  }
  function nextHistoryIndex(replace) {
    // A click may commit while Back is pending. Its native push truncates from
    // that traversed position, so the new index must describe that position.
    var index = entryIndex(history.state);
    if (index === null) index = renderedIndex;
    return index === null ? null : replace ? index : index + 1;
  }
  // popstate arrives after the address bar changes; keep the rendered entry's
  // scroll in memory as well as in history while it is current.
  window.addEventListener('scroll', function () {
    if (!renderedEntryIsCurrent()) return;
    scrollMemory.set(currentState.npKey, window.scrollY);
    window.clearTimeout(scrollTimer);
    scrollTimer = window.setTimeout(function () { rememberScroll(true); }, 250);
  }, {passive:true});
  function assign(url) { window.location.assign(url); }
  function swapRegion(selector, template) {
    var existing = document.querySelector(selector), next = template.content.firstElementChild;
    if (existing && next) {
      var scroll = existing.scrollTop;
      lifecycle.unmount(existing);
      existing.replaceChildren.apply(existing, Array.from(next.childNodes));
      // Root attributes carry state used by delegated handlers and accessibility.
      Array.from(existing.attributes).forEach(function (attr) { existing.removeAttribute(attr.name); });
      Array.from(next.attributes).forEach(function (attr) { existing.setAttribute(attr.name, attr.value); });
      existing.scrollTop = scroll;
      return existing;
    }
    if (existing) { lifecycle.unmount(existing); existing.remove(); }
    if (next) { document.querySelector('#main-content').before(next); return next; }
    return null;
  }
  function replaceShellDialog(template) {
    if (!template) return null;
    var existing = document.querySelector('#' + template.getAttribute('data-np-shell')), next = template.content.firstElementChild;
    if (existing) {
      if (existing.open && ui.dialogs) ui.dialogs.close(existing);
      lifecycle.unmount(existing);
      if (next) existing.replaceWith(next); else existing.remove();
    } else if (next) document.body.appendChild(next);
    return next;
  }
  function showError(main, url, options) {
    var prior = main.querySelector('[data-np-navigation-error]'); if (prior) prior.remove();
    var error = document.createElement('div'); error.dataset.npNavigationError = ''; error.className = 'np-notice'; error.setAttribute('role', 'alert');
    var message = document.createElement('p'); message.textContent = "Couldn't load this page.";
    var retry = document.createElement('button'); retry.type = 'button'; retry.textContent = 'Retry';
    retry.addEventListener('click', function () { navigate(url, options); });
    var link = document.createElement('a'); link.href = url; link.dataset.npFullNav = ''; link.textContent = 'Open normally';
    error.append(message, retry, document.createTextNode(' '), link); main.prepend(error);
  }
  // Domain tools render as adjacent panels. Group only their body in the live
  // document, leaving the full-page response and its existing elements intact.
  function scopeDomainBody() {
    var main = document.querySelector('#main-content');
    if (!main || main.querySelector('[data-np-nav-scope-body]')) return;
    var tabs = main.querySelector('.np-domain-primary-nav');
    if (!tabs || !tabs.nextSibling) return;
    var body = document.createElement('div'); body.setAttribute('data-np-nav-scope-body', '');
    tabs.after(body);
    while (body.nextSibling) body.appendChild(body.nextSibling);
  }
  function feedback(main, url, signal) {
    var progress = document.querySelector('.np-nav-progress'), region = new URL(url).pathname === new URL(currentURL).pathname ? main.querySelector('[data-np-nav-scope-body]') || main : main;
    var skeleton, stopped = false, wasInert = region.inert;
    if (progress) { window.clearTimeout(progress.npFadeTimer); progress.classList.remove('is-pending', 'is-complete'); }
    var barTimer = window.setTimeout(function () { if (progress) progress.classList.add('is-pending'); }, 120);
    var skeletonTimer = window.setTimeout(function () {
      region.classList.add('np-nav-loading'); region.setAttribute('aria-busy', 'true'); region.inert = true;
      skeleton = document.createElement('div'); skeleton.className = 'np-nav-skeleton'; skeleton.setAttribute('aria-hidden', 'true');
      ['np-nav-skeleton-heading', 'np-nav-skeleton-bar', 'np-nav-skeleton-block', 'np-nav-skeleton-bar', 'np-nav-skeleton-block'].forEach(function (name) {
        var block = document.createElement('div'); block.className = name; skeleton.appendChild(block);
      });
      region.appendChild(skeleton);
    }, 300);
    function finish(success) {
      if (stopped) return; stopped = true;
      window.clearTimeout(barTimer); window.clearTimeout(skeletonTimer);
      if (skeleton) skeleton.remove();
      region.classList.remove('np-nav-loading'); region.inert = wasInert; region.removeAttribute('aria-busy');
      if (progress) {
        var visible = progress.classList.contains('is-pending'); progress.classList.remove('is-pending');
        if (success && visible) {
          progress.classList.add('is-complete');
          progress.npFadeTimer = window.setTimeout(function () { progress.classList.remove('is-complete'); }, 200);
        } else progress.classList.remove('is-complete');
      }
    }
    signal.addEventListener('abort', function () { finish(false); }, {once:true});
    return finish;
  }
  async function transition(swap) {
    if (document.startViewTransition && !(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)) {
      var view = document.startViewTransition(swap);
      // A superseded visual transition rejects ready and finished while the DOM
      // update still succeeds. Only the update callback decides navigation success.
      if (view.ready) view.ready.catch(function () {});
      if (view.finished) view.finished.catch(function () {});
      await view.updateCallbackDone;
    } else swap();
  }
  async function commitFragment(html, meta, finalURL, options, main, current, finish) {
    var parsed = new DOMParser().parseFromString(html, 'text/html');
    // DOMParser disables scripting, so noscript fallback controls are real
    // elements here. Template contents are separate trees and need the same pass.
    function stripFallbacks(root) {
      root.querySelectorAll('noscript').forEach(function (node) { node.remove(); });
      root.querySelectorAll('template').forEach(function (template) { stripFallbacks(template.content); });
    }
    stripFallbacks(parsed);
    var content = parsed.querySelector('[data-np-fragment="main"]');
    var sidebar = parsed.querySelector('template[data-np-shell="sidebar"]'), topbar = parsed.querySelector('template[data-np-shell="topbar"]'), support = parsed.querySelector('template[data-np-shell="support"]');
    var dialogs = Array.from(parsed.querySelectorAll('template[data-np-shell]')).filter(function (template) { return /-dialog$/.test(template.getAttribute('data-np-shell')); });
    if (!content || !meta.keepShell && (!sidebar || !topbar || !support)) throw new Error('Incomplete fragment.');
    await transition(function () {
      if (!current()) return;
      finish(true);
      document.querySelectorAll('dialog[open]').forEach(function (dialog) { if (ui.dialogs) ui.dialogs.close(dialog); });
      lifecycle.unmount(main);
      main.replaceChildren.apply(main, Array.from(content.childNodes));
      var regions = meta.keepShell ? [] : [swapRegion('.np-routed-side', sidebar), swapRegion('.np-routed-top', topbar), swapRegion('.np-support-banner', support)].concat(dialogs.map(replaceShellDialog));
      document.title = meta.title;
      if (!meta.keepShell) {
        document.body.className = meta.bodyClass;
        document.body.dataset.npRoute = meta.route;
        document.body.removeAttribute('data-np-document-only');
      }
      var scrim = document.querySelector('[data-np-menu-close]'); if (scrim) scrim.hidden = true;
      var scrollY = options.pop ? options.scrollY || 0 : options.refresh || meta.keepShell ? window.scrollY : 0;
      if (!meta.keepShell && (!options.post || options.redirected)) {
        currentURL = finalURL;
        var key = options.pop ? (options.state && options.state.npKey) || newEntryKey() : options.replace || options.refresh ? currentState.npKey : newEntryKey();
        renderedIndex = options.pop ? entryIndex(options.state) : nextHistoryIndex(options.replace || options.refresh);
        currentState = Object.assign({}, options.pop ? options.state : {}, {npNav:true, npKey:key, scrollY:scrollY});
        if (renderedIndex !== null) currentState.npIndex = renderedIndex;
        writeHistory(options.replace || options.pop || options.refresh ? 'replaceState' : 'pushState', currentState, finalURL);
      }
      scopeDomainBody(); lifecycle.mount(main);
      regions.forEach(function (region) { if (region) lifecycle.mount(region); });
      currentURL = window.location.href; currentState = history.state || currentState;
      var reopened = options.drawer && ui.dialogs && ui.dialogs.restore(options.drawer, main);
      var target = options.post && (main.querySelector('.np-notice, [role="alert"], [role="status"]') || main.querySelector('[aria-invalid="true"]')) || main.querySelector('h1') || main;
      if (!reopened) {
        if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1'); target.focus({preventScroll:true});
      }
      window.scrollTo(0, scrollY); live.textContent = meta.title;
      document.dispatchEvent(new CustomEvent('nakpanel:navigated', {detail:{url:currentURL}}));
    });
  }
  function formError(form, message, normalURL) {
    var prior = form.parentElement && form.parentElement.querySelector('[data-np-form-error]'); if (prior) prior.remove();
    var panel = document.createElement('div'); panel.className = 'np-notice'; panel.setAttribute('role', 'alert'); panel.setAttribute('tabindex', '-1'); panel.dataset.npFormError = '';
    var text = document.createElement('p'); text.textContent = message; panel.appendChild(text);
    if (normalURL) {
      var link = document.createElement('a'); link.href = normalURL; link.dataset.npFullNav = ''; link.textContent = 'Open the form and repeat this action normally'; panel.appendChild(link);
    }
    if (form.hasAttribute('data-np-dirty-guard')) form.dataset.npDirty = 'true';
    form.before(panel); panel.focus();
  }
  function resetSubmittedDialog(form) {
    if (!form.closest('dialog, [role="dialog"], [data-np-drawer]')) return;
    form.reset();
    // reset() restores defaults; even a default password must never persist.
    form.querySelectorAll('input[type="password"]').forEach(function (field) { field.value = ''; });
  }
  async function submitForm(event) {
    // Even forms claimed by another delegate can mutate the page's resources.
    prefetch.clear(); cancelIntents();
    var form = event.target;
    if (!formEligible(form, event, window.location.href)) return;
    event.preventDefault();
    if (form.dataset.npNavSubmitting === 'true') return;
    var submitter = event.submitter, action = formAction(form, submitter, window.location.href);
    // Construct before setBusy disables the successful submitter.
    var body = new FormData(form, submitter);
    if (formMethod(form, submitter) === 'get') { return navigate(formURL(action, body, window.location.href)); }
    var drawer = ui.dialogs && ui.dialogs.capture ? ui.dialogs.capture(form) : null;
    form.dataset.npNavSubmitting = 'true'; ui.setBusy(form, true); rememberScroll();
    if (controller) controller.abort();
    controller = new AbortController();
    var signal = controller.signal, id = ++sequence, main = document.querySelector('#main-content');
    function current() { return isCurrent(id, sequence, signal); }
    var finishFeedback = feedback(main, action, signal), committed = false, leavingDocument = false;
    function finish(success) {
      if (success) {
        committed = true;
        if (form.hasAttribute('data-np-dirty-guard')) form.dataset.npDirty = 'false';
      }
      finishFeedback(success);
    }
    main.setAttribute('aria-busy', 'true');
    try {
      // Match native encoding so handlers see exactly what a normal submission sends.
      var payload = formEnctype(form, submitter) === 'multipart/form-data' ? body : urlencoded(body);
      var response = await ui.fetch(action, {method:'POST', body:payload, headers:{Accept:'text/html', 'X-Nakpanel-Fragment':'main'}, allowPageResponse:true, signal:signal});
      if (!current()) return;
      var location = response.headers.get('X-Nakpanel-Location'); if (location) { leavingDocument = true; assign(location); return; }
      if (!response.ok) {
        var message = '';
        if ((response.headers.get('Content-Type') || '').toLowerCase().includes('text/html')) {
          var failure = new DOMParser().parseFromString(await response.text(), 'text/html');
          if (!current()) return;
          var details = failure.querySelector('#main-content, [data-np-fragment="main"], main') || failure.body;
          message = Array.from(details.querySelectorAll('h1, h2, p')).map(function (node) { return node.textContent; }).join(' ').replace(/\s+/g, ' ').trim().slice(0, 300);
        }
        finish(false); formError(form, message || 'The action failed (HTTP ' + response.status + ')'); return;
      }
      if (!(response.headers.get('Content-Type') || '').toLowerCase().includes('text/html') || /attachment/i.test(response.headers.get('Content-Disposition') || '')) {
        finish(false); formError(form, 'The action returned a download or another response that cannot be displayed here. Check its status before repeating it.', currentURL); return;
      }
      var html = await response.text(); if (!current()) return;
      var meta;
      try { meta = parseFragment(html); } catch (_) { /* An HTML action may still use a standalone legacy response. */ }
      resetSubmittedDialog(form);
      // The action has completed; a destination that needs its own document is
      // loaded with a plain GET rather than shown as an empty panel.
      if (meta && meta.fullDocument && response.redirected) { finish(true); assign(response.url); return; }
      if (meta && !meta.fullDocument) {
        await commitFragment(html, meta, response.url || action, {post:true, redirected:response.redirected, drawer:drawer}, main, current, finish);
      } else {
        var parsed = new DOMParser().parseFromString(html, 'text/html');
        parsed.body.querySelectorAll('script, style').forEach(function (node) { node.remove(); });
        var panel = document.createElement('section'); panel.className = 'np-notice np-nav-response'; panel.setAttribute('tabindex', '-1'); panel.setAttribute('role', 'status'); panel.textContent = parsed.body.textContent;
        await transition(function () {
          if (!current()) return;
          finish(true);
          document.querySelectorAll('dialog[open]').forEach(function (dialog) { if (ui.dialogs) ui.dialogs.close(dialog); });
          lifecycle.unmount(main); main.replaceChildren(panel);
          if (response.redirected) {
            currentURL = response.url || action; currentState = {npNav:true, npKey:newEntryKey(), scrollY:0};
            renderedIndex = nextHistoryIndex(false);
            if (renderedIndex !== null) currentState.npIndex = renderedIndex;
            writeHistory('pushState', currentState, currentURL); window.scrollTo(0, 0);
          }
          lifecycle.mount(main); panel.focus(); live.textContent = 'Action response';
          document.dispatchEvent(new CustomEvent('nakpanel:navigated', {detail:{url:currentURL}}));
        });
      }
    } catch (error) {
      prefetch.clear(); cancelIntents();
      if (!current()) return;
      if (error.status === 401) { leavingDocument = true; assign(error.location || '/login'); return; }
      finish(false); formError(form, 'The request could not finish. Your values are still here. Check status before submitting again; the action may already have been accepted.');
    } finally {
      prefetch.clear(); finish(false);
      if (current() && !committed && !leavingDocument) restoreRenderedEntry();
      if (current()) main.removeAttribute('aria-busy');
      form.dataset.npNavSubmitting = 'false'; ui.setBusy(form, false);
    }
  }
  async function navigate(raw, options) {
    options = Object.assign({}, options);
    if (options.pop) options.state = history.state;
    var url = new URL(raw, window.location.href).href;
    if (controller) controller.abort();
    controller = new AbortController();
    var signal = controller.signal, id = ++sequence, main = document.querySelector('#main-content');
    // The Add Website document intentionally has no shell site dialog. Leaving
    // it needs a document load to restore that shared dialog.
    if (new URL(url).origin !== window.location.origin || excludedPath(new URL(url).pathname) || document.querySelector('.np-v2-create')) { assign(url); return; }
    if (!main) { assign(url); return; }
    if (!options.pop) rememberScroll();
    var finish = feedback(main, url, signal), committed = false, leavingDocument = false;
    function leaveDocument(target) { assign(target); leavingDocument = true; }
    var bar = options.anchor && options.anchor.closest('.np-domain-tabs, .np-subscription-tabs, .np-routed-nav');
    var restore = bar ? optimisticActive(bar.querySelectorAll('a[href], summary'), options.anchor) : function () {};
    // A newer traversal or click now owns the address bar. Only its eventual
    // failure may recover the rendered entry; aborting must not move history.
    signal.addEventListener('abort', function () { if (!committed) restore(); }, {once:true});
    main.setAttribute('aria-busy', 'true');
    function current() { return isCurrent(id, sequence, signal); }
    async function canLeave() {
      if (!current()) return false;
      if (!main.querySelector('[data-np-dirty-guard][data-np-dirty="true"]')) return true;
      var leave = await ui.confirm('Leave this page? Your changes will be lost.');
      if (!current()) return false;
      if (!leave) restoreRenderedEntry();
      return leave;
    }
    async function openDocument(target) {
      if (!await canLeave() || !current()) return;
      // The explicit confirmation covers these forms; avoid a second native
      // beforeunload prompt while performing the document fallback.
      main.querySelectorAll('[data-np-dirty-guard][data-np-dirty="true"]').forEach(function (form) { form.dataset.npDirty = 'false'; });
      leaveDocument(target);
    }
    try {
      var response = !options.refresh && !options.pop && prefetch.get(url) || await ui.fetch(url, {headers:{Accept:'text/html', 'X-Nakpanel-Fragment':'main'}, allowPageResponse:true, signal:signal});
      if (!current()) return;
      var location = response.headers.get('X-Nakpanel-Location');
      if (location) { leaveDocument(location); return; }
      if (!(response.headers.get('Content-Type') || '').toLowerCase().includes('text/html')) { await openDocument(url); return; }
      var html = await response.text();
      if (!current()) return;
      var meta = parseFragment(html), final = new URL(response.url || url), requested = new URL(url);
      // Fetch response URLs omit anchors; keep anchors that belong to the final
      // route so its mounted tab controller can select the requested panel.
      if (!final.hash && final.pathname === requested.pathname && final.search === requested.search) final.hash = requested.hash;
      var finalURL = final.href;
      if (meta.fullDocument) { await openDocument(finalURL); return; }
      if (!await canLeave() || !current()) return;
      if (!options.pop) rememberScroll();
      await commitFragment(html, meta, finalURL, options, main, current, function (success) { committed = success; finish(success); });
    } catch (error) {
      prefetch.clear(); cancelIntents();
      if (!current()) return;
      if (error.status === 401) { leaveDocument(error.location || '/login'); return; }
      restoreRenderedEntry();
      showError(main, url, Object.assign({}, options, {pop:false}));
    } finally {
      finish(false);
      if (!committed) { restore(); if (id === sequence && !leavingDocument) restoreRenderedEntry(); }
      if (current()) main.removeAttribute('aria-busy');
    }
  }
  ui.navigate = navigate;
  ui.refresh = async function () { prefetch.clear(); cancelIntents(); try { return await navigate(window.location.href, {replace:true, refresh:true}); } finally { prefetch.clear(); cancelIntents(); } };
  // Defer handling until other document delegates have had their chance to claim
  // an interaction (dialogs, tabs and action links).
  window.addEventListener('DOMContentLoaded', function () {
    scopeDomainBody();
    document.addEventListener('click', function (event) {
      var anchor = event.target.closest && event.target.closest('a[href]');
      if (!anchor || !anchor.closest('.np-routed-side, .np-routed-top, #main-content')) return;
      if (!linkEligible(anchor, event, window.location.href)) return;
      event.preventDefault(); navigate(anchor.href, {anchor:anchor});
    });
  }, {once:true});
  var intents = new Map();
  function cancelIntents() { intents.forEach(function (timer) { window.clearTimeout(timer); }); intents.clear(); }
  function intent(event) {
    var anchor = event.target.closest && event.target.closest('a[href]');
    if (!linkEligible(anchor, {}, window.location.href) || intents.has(anchor)) return;
    intents.set(anchor, window.setTimeout(function () { intents.delete(anchor); prefetch.prefetch(new URL(anchor.href, window.location.href).href); }, 65));
  }
  function leaveIntent(event) {
    var anchor = event.target.closest && event.target.closest('a[href]');
    if (anchor && event.relatedTarget && anchor.contains(event.relatedTarget)) return;
    if (intents.has(anchor)) { window.clearTimeout(intents.get(anchor)); intents.delete(anchor); }
  }
  document.addEventListener('pointerenter', intent, true);
  document.addEventListener('pointerleave', leaveIntent, true);
  document.addEventListener('focusin', intent);
  document.addEventListener('focusout', leaveIntent);
  // Capture invalidation also covers feature handlers that stop propagation.
  window.addEventListener('submit', function () { prefetch.clear(); cancelIntents(); }, true);
  window.addEventListener('submit', submitForm);
  window.addEventListener('popstate', function (event) {
    if (suppressedIndex !== null && entryIndex(event.state) === suppressedIndex) { suppressedIndex = null; return; }
    suppressedIndex = null;
    if (!(event.state && event.state.npNav)) return;
    // The outgoing page is still rendered, so its position is still current.
    if (currentState && currentState.npKey) scrollMemory.set(currentState.npKey, window.scrollY);
    var key = event.state.npKey, saved = key && scrollMemory.has(key) ? scrollMemory.get(key) : event.state.scrollY;
    navigate(window.location.href, {replace:true, pop:true, scrollY:saved});
  });
})();
