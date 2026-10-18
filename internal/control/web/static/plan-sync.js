(function () {
  "use strict";
  function wordPressError(value) {
    return value.lifecycle === "active" && value.enabled && !value.unlimited && Number(value.limit) === 0
      ? "WordPress Toolkit needs a positive installation limit or Unlimited." : "";
  }
  function summary(value) {
    var parts = [];
    [["synced", "updated"], ["pending", "applying"], ["failed", "failed"], ["excluded", "excluded"]].forEach(function (entry) {
      if (value[entry[0]]) parts.push(value[entry[0]] + " " + entry[1]);
    });
    return parts.join(" / ") || "No linked subscriptions";
  }
  function stateLabel(value) {
    if (value.state === "excluded") return "Excluded (" + (value.mode === "custom" ? "custom" : "locked") + ")";
    return {in_sync: "Updated", pending: "Waiting for plan update", applying: "Applying services", failed: "Needs attention"}[value.state] || "Unknown";
  }
  function shouldPoll(value) { return value.state === "pending"; }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {wordPressError: wordPressError, summary: summary, stateLabel: stateLabel, shouldPoll: shouldPoll};
  }
  if (typeof document === "undefined") return;

  var mounted = new WeakSet();
  function mount(scope) {
    scope.querySelectorAll('[data-np-plan-editor][action="/plans"]').forEach(function (form) {
      if (mounted.has(form)) return; mounted.add(form);
      var field = form.querySelector('[name="max_wordpress_sites"]');
      var permission = form.querySelector('[name="allow_wordpress_toolkit"][type="checkbox"]');
      var unlimited = form.querySelector('[name="max_wordpress_sites_unlimited"]');
      var lifecycle = form.querySelector('[name="lifecycle_status"]');
      var hint = form.querySelector("[data-np-wordpress-plan-error]");
      if (!field || !permission || !unlimited || !lifecycle) return;
      function validate() {
        var message = wordPressError({enabled: permission.checked, unlimited: unlimited.checked, limit: field.value, lifecycle: lifecycle.value});
        field.setCustomValidity(message);
        field.setAttribute("aria-invalid", message ? "true" : "false");
        if (hint) {
          hint.textContent = message || "Installation allowance applies separately to each subscription.";
          hint.classList.toggle("is-blocked", !!message);
          hint.setAttribute("role", message ? "alert" : "note");
        }
      }
      form.addEventListener("input", validate);
      form.addEventListener("change", validate);
      validate();
    });

    scope.querySelectorAll("[data-np-plan-sync]").forEach(function (root) {
      if (mounted.has(root)) return; mounted.add(root);
      var status = root.querySelector("[data-np-sync-summary]");
      var rows = root.querySelector("[data-np-sync-rows]");
      var button = root.querySelector("[data-np-sync-refresh]");
      var id = root.getAttribute("data-plan-id");
      if (!/^[1-9][0-9]*$/.test(id)) return;
      var timer, sequence = 0, controller, attempts = 0, closed = false;
      var signal = window.NakpanelUI && window.NakpanelUI.lifecycle ? window.NakpanelUI.lifecycle.signal(root) : new AbortController().signal;
      function stop() { closed = true; window.clearTimeout(timer); if (controller) controller.abort(); }
      signal.addEventListener('abort', stop, {once:true});
      function render(value) {
        status.textContent = "Revision " + value.revision + ": " + summary(value);
        status.classList.toggle("is-blocked", value.state === "failed");
        rows.replaceChildren();
        (value.subscriptions || []).forEach(function (item) {
          var row = document.createElement("div"), link = document.createElement("a"), state = document.createElement("span");
          row.className = "np-plan-sync-row";
          link.textContent = item.name || "Subscription " + item.id;
          if (Number.isSafeInteger(item.id) && item.id > 0) link.href = "/subscriptions/" + item.id;
          state.textContent = stateLabel(item);
          row.append(link, state);
          rows.appendChild(row);
          if (item.error) {
            var error = document.createElement("p");
            error.className = "np-gate is-blocked";
            error.textContent = item.error;
            rows.appendChild(error);
          }
        });
      }
      function refresh(manual) {
        if (closed) return;
        if (manual) attempts = 0;
        window.clearTimeout(timer);
        if (controller) controller.abort();
        controller = new AbortController();
        var current = ++sequence;
        button.disabled = true;
        fetch("/plans/" + id + "/sync-status", {credentials:"same-origin", signal:controller.signal, headers:{Accept:"application/json"}})
          .then(function (response) {
            if (response.status === 401 || response.status === 403) throw new Error("Sign in again to refresh synchronization.");
            if (!response.ok) throw new Error("Could not refresh synchronization. Your saved plan has not changed.");
            return response.json();
          }).then(function (data) {
            if (closed || current !== sequence) return;
            render(data.synchronization);
            if (shouldPoll(data.synchronization) && ++attempts < 60) timer = window.setTimeout(function () { refresh(false); }, 2000);
          }).catch(function (error) {
            if (error.name !== "AbortError" && !closed && current === sequence) status.textContent = error.message;
          }).finally(function () {
            if (current === sequence && !closed) button.disabled = false;
          });
      }
      button.addEventListener("click", function () { refresh(true); });
      window.addEventListener("pagehide", stop, {once:true,signal:signal});
      refresh(false);
    });
  }
  if (window.NakpanelUI && window.NakpanelUI.lifecycle) window.NakpanelUI.lifecycle.onMount(mount);
  mount(document);
}());
