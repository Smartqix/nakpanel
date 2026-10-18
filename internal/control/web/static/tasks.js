(function () {
  'use strict';
  function active(state) { return ['available', 'scheduled', 'running', 'retryable', 'pending'].indexOf(state) !== -1; }
  function terminal(state) { return ['completed', 'discarded', 'cancelled', 'failed'].indexOf(state) !== -1; }
  // One controller owns the clock and transitions; DOM mounts only replace views.
  function createTaskPoller(env) {
    var timer, busy = false, started = false, open = false, errors = 0, request, previous = new Map();
    var data = {active:0, items:[]};
    function accept(next, announce) {
      next.items.forEach(function (item) {
        var before = previous.get(item.id);
        if (announce && before && active(before.state) && terminal(item.state)) env.toast(item);
        if (active(item.state)) previous.set(item.id, item); else previous.delete(item.id);
      });
      data = next; env.render(data, open);
    }
    function clear() { if (timer != null) env.clearTimeout(timer); timer = null; }
    function delay() { return errors ? Math.min(60000, 4000 * Math.pow(2, errors)) : open || data.active > 0 ? 4000 : 30000; }
    function schedule() { clear(); if (started && !env.hidden() && !busy) timer = env.setTimeout(poll, delay()); }
    async function poll() {
      clear();
      if (!started || env.hidden() || busy) return;
      busy = true; request = new AbortController();
      try {
        var next = await env.fetch(request.signal);
        if (request.signal.aborted) return;
        if (!next || !Number.isInteger(next.active) || next.active < 0 || !Array.isArray(next.items)) throw new Error('Invalid tasks response');
        errors = 0; accept(next, true); if (env.error) env.error(false);
      } catch (_) { if (!request.signal.aborted) { errors++; if (env.error) env.error(true); } }
      finally { busy = false; request = null; schedule(); }
    }
    return {
      start:function (seed) { if (started) { env.render(data, open); return; } started = true; if (seed) accept(seed, false); poll(); },
      setOpen:function (value) { if (open === value) return; open = value; env.render(data, open); if (open) poll(); else schedule(); },
      visibility:function () { clear(); if (env.hidden()) { if (request) request.abort(); } else poll(); },
      mount:function () { if (started) env.render(data, open); },
      stop:function () { started = false; clear(); if (request) request.abort(); }
    };
  }
  function relative(value, now) {
    var minutes = Math.floor(Math.max(0, now - new Date(value).getTime()) / 60000);
    // Same wording as the server's formatRelativeLabel, so a polled refresh
    // never rewords a row the page rendered.
    if (minutes < 1) return 'just now';
    if (minutes < 2) return 'a minute ago';
    if (minutes < 60) return minutes + ' minutes ago';
    if (minutes < 120) return 'an hour ago';
    if (minutes < 1440) return Math.floor(minutes / 60) + ' hours ago';
    if (minutes < 2880) return 'yesterday';
    return Math.floor(minutes / 1440) + ' days ago';
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {createTaskPoller:createTaskPoller, relative:relative};
  if (typeof window === 'undefined') return;
  var document = window.document, ui = window.NakpanelUI;
  if (!ui) return;
  function tray() { return document.querySelector('[data-np-tasks]'); }
  function node(tag, text, className) {
    var element = document.createElement(tag); if (text != null) element.textContent = text; if (className) element.className = className; return element;
  }
  function render(data, open) {
    var root = tray(); if (!root) return;
    var toggle = root.querySelector('[data-np-tasks-toggle]'), badge = root.querySelector('[data-np-tasks-count]'), panel = root.querySelector('#np-tasks-panel');
    toggle.setAttribute('aria-expanded', String(open)); badge.hidden = data.active === 0; badge.textContent = String(data.active); panel.hidden = !open;
    var items = root.querySelector('[data-np-tasks-items]'); items.replaceChildren();
    data.items.forEach(function (item) {
      var row = node('article', null, 'np-task'), stamp = node('time', relative(item.created_at, Date.now()));
      stamp.dateTime = item.created_at; stamp.title = new Date(item.created_at).toLocaleString();
      var tone = ['ok', 'run', 'pend', 'fail'].indexOf(item.tone) === -1 ? 'pend' : item.tone;
      row.append(node('strong', item.label), node('span', item.target), node('span', item.state, 'np-status-pill np-status-pill-' + tone), stamp);
      if (tone === 'fail' && item.error) row.appendChild(node('p', item.error));
      items.appendChild(row);
    });
    if (!data.items.length) items.appendChild(node('p', 'No recent tasks.'));
  }
  function toast(item) {
    var region = document.querySelector('[data-np-task-toasts]');
    if (!region) { region = node('div', null, 'np-task-toasts'); region.dataset.npTaskToasts = ''; document.body.appendChild(region); }
    var message = node('div', null, 'np-task-toast'); message.setAttribute('role', 'status');
    message.appendChild(node('span', (item.state === 'completed' ? 'Finished: ' : 'Failed: ') + item.label));
    var refresh = node('button', 'Refresh', 'np-secondary-button'); refresh.type = 'button';
    refresh.addEventListener('click', function () { if (ui.refresh) ui.refresh(); else window.location.reload(); message.remove(); });
    var dismiss = node('button', 'Dismiss', 'np-secondary-button'); dismiss.type = 'button'; dismiss.addEventListener('click', function () { message.remove(); });
    message.append(refresh, dismiss); region.appendChild(message);
    while (region.children.length > 4) region.firstElementChild.remove();
  }
  var poller = createTaskPoller({
    setTimeout:window.setTimeout.bind(window), clearTimeout:window.clearTimeout.bind(window), hidden:function () { return document.hidden; }, render:render, toast:toast,
    error:function (failed) { var root = tray(), notice = root && root.querySelector('[data-np-tasks-error]'); if (notice) { notice.hidden = !failed; notice.textContent = failed ? 'Tasks are temporarily unavailable. Retrying…' : ''; } },
    fetch:async function (signal) {
      var response = await ui.fetch('/api/workspace/tasks', {headers:{Accept:'application/json', 'X-Nakpanel-SPA':'true'}, cache:'no-store', signal:signal});
      if (!response.ok) throw new Error('Tasks unavailable'); return response.json();
    }
  });
  function mount() {
    var root = tray(); if (!root) return;
    var seed = {active:Number(root.querySelector('[data-np-tasks-count]').textContent), items:[]};
    // Seed transition tracking from the server-rendered tray on the first mount.
    root.querySelectorAll('[data-np-task-id]').forEach(function (row) { seed.items.push({id:Number(row.dataset.npTaskId), state:row.dataset.npTaskState, label:row.dataset.npTaskLabel, target:row.querySelector('span').textContent, created_at:row.querySelector('time').getAttribute('datetime'), tone:row.querySelector('.np-status-pill').className.split('np-status-pill-')[1], error:row.querySelector('p') ? row.querySelector('p').textContent : ''}); });
    poller.start(seed);
  }
  document.addEventListener('click', function (event) {
    var root = tray(); if (!root) return;
    var toggle = root.querySelector('[data-np-tasks-toggle]');
    if (toggle.contains(event.target)) { var open = toggle.getAttribute('aria-expanded') !== 'true'; poller.setOpen(open); if (open) root.querySelector('#np-tasks-panel').focus(); }
    else if (!root.contains(event.target)) poller.setOpen(false);
  });
  document.addEventListener('keydown', function (event) {
    var root = tray(); if (!root || event.key !== 'Escape') return;
    var toggle = root.querySelector('[data-np-tasks-toggle]');
    if (toggle.getAttribute('aria-expanded') === 'true') { event.preventDefault(); poller.setOpen(false); toggle.focus(); }
  });
  document.addEventListener('visibilitychange', poller.visibility);
  if (ui.lifecycle) ui.lifecycle.onMount(mount);
  mount();
})();
