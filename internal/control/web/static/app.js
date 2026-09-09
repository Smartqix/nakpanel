(function () {
  "use strict";

  document.documentElement.classList.add("nakpanel-js");
  var lastDialogTrigger = null;
  var planSubmitBypass = false;
  var pendingPlanForm = null;
  var confirmationResolver = null;
  var serverInventoryHostname = "";

  function each(selector, scope, callback) {
    Array.prototype.forEach.call((scope || document).querySelectorAll(selector), callback);
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="nakpanel-csrf"]');
    return meta ? meta.content : "";
  }

  function prepareForms() {
    var token = csrfToken();
    if (!token) return;
    each('form[method="post"], form[method="POST"]', document, function (form) {
      if (form.querySelector('input[name="csrf_token"]')) return;
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = "csrf_token";
      input.value = token;
      form.appendChild(input);
    });
  }

  function initializeDirtyForms() {
    each('[data-np-dirty-guard]', document, function (form) {
      if (form.hasAttribute("data-np-editor-form")) return;
      form.dataset.npDirty = "false";
      var submit = form.querySelector("[data-np-dirty-submit]");
      function markDirty() {
        form.dataset.npDirty = "true";
        if (submit) submit.disabled = false;
      }
      form.addEventListener("input", markDirty);
      form.addEventListener("change", markDirty);
      form.addEventListener("submit", function () {
        form.dataset.npDirty = "false";
        if (submit) submit.disabled = false;
      });
    });
  }

  function initializeDNSFilters() {
    each("[data-np-dns-workspace]", document, function (workspace) {
      var search = workspace.querySelector("[data-np-dns-search]");
      var type = workspace.querySelector("[data-np-dns-type]");
      if (!search || !type) return;
      function filter() {
        var query = search.value.trim().toLowerCase();
        var selected = type.value.toUpperCase();
        var visible = 0;
        each("[data-np-dns-row]", workspace, function (row) {
          var matchesQuery = !query || (row.dataset.search || "").toLowerCase().indexOf(query) !== -1;
          var matchesType = !selected || (row.dataset.type || "").toUpperCase() === selected;
          row.hidden = !(matchesQuery && matchesType);
          if (!row.hidden) visible += 1;
        });
        var count = workspace.querySelector("[data-np-dns-result-count]");
        var empty = workspace.querySelector("[data-np-dns-filter-empty]");
        if (count) count.textContent = visible + (visible === 1 ? " record" : " records");
        if (empty) empty.hidden = visible !== 0;
      }
      search.addEventListener("input", filter);
      type.addEventListener("change", filter);
      filter();
    });
  }

  function initializeDNSSettingsTabs() {
    each("[data-np-dns-settings-workspace]", document, function (workspace) {
      var tabs = Array.prototype.slice.call(workspace.querySelectorAll("[data-np-dns-settings-tab]"));
      var panels = Array.prototype.slice.call(workspace.querySelectorAll("[data-np-dns-settings-panel]"));
      if (!tabs.length || !panels.length) return;

      function tabFromHash() {
        var hash = window.location.hash.replace(/^#/, "");
        if (!hash) return "";
        try {
          hash = decodeURIComponent(hash);
        } catch (_) {
          return "";
        }
        var target = document.getElementById(hash);
        if (!target || !workspace.contains(target)) return "";
        if (target.matches("details")) target.open = true;
        var panel = target.matches("[data-np-dns-settings-panel]") ? target : target.closest("[data-np-dns-settings-panel]");
        return panel ? panel.getAttribute("data-np-dns-settings-panel") : "";
      }

      function activate(name, moveFocus) {
        var active = tabs.some(function (tab) {
          return tab.getAttribute("data-np-dns-settings-tab") === name;
        }) ? name : (workspace.dataset.defaultTab || "records");
        tabs.forEach(function (tab) {
          var selected = tab.getAttribute("data-np-dns-settings-tab") === active;
          tab.setAttribute("aria-selected", selected ? "true" : "false");
          tab.setAttribute("tabindex", selected ? "0" : "-1");
          tab.classList.toggle("is-active", selected);
          if (selected && moveFocus) tab.focus();
        });
        panels.forEach(function (panel) {
          panel.hidden = panel.getAttribute("data-np-dns-settings-panel") !== active;
        });
      }

      tabs.forEach(function (tab, index) {
        tab.addEventListener("click", function (event) {
          event.preventDefault();
          var name = tab.getAttribute("data-np-dns-settings-tab");
          activate(name, false);
          window.history.replaceState(null, "", tab.getAttribute("href"));
        });
        tab.addEventListener("keydown", function (event) {
          if (event.key !== "ArrowRight" && event.key !== "ArrowLeft" && event.key !== "Home" && event.key !== "End") return;
          event.preventDefault();
          var next = index;
          if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
          if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
          if (event.key === "Home") next = 0;
          if (event.key === "End") next = tabs.length - 1;
          var nextTab = tabs[next];
          activate(nextTab.getAttribute("data-np-dns-settings-tab"), true);
          window.history.replaceState(null, "", nextTab.getAttribute("href"));
        });
      });
      each("[data-np-dns-settings-jump]", workspace, function (link) {
        link.addEventListener("click", function (event) {
          event.preventDefault();
          activate(link.getAttribute("data-np-dns-settings-jump"), false);
          window.history.replaceState(null, "", link.getAttribute("href"));
          var menu = link.closest("details");
          if (menu) menu.open = false;
        });
      });
      activate(tabFromHash() || workspace.dataset.defaultTab || "records", false);
      window.addEventListener("hashchange", function () {
        var name = tabFromHash();
        if (name) activate(name, false);
      });
    });
  }

  function initializeDNSRecordForms() {
    each("[data-np-dns-record-form]", document, function (form) {
      var type = form.querySelector('select[name="record_type"]');
      if (!type) return;
      function updateFields() {
        var selected = type.value.toUpperCase();
        each("[data-np-dns-field]", form, function (field) {
          var kind = field.getAttribute("data-np-dns-field");
          var visible = kind === "priority" ? (selected === "MX" || selected === "SRV") : selected === "SRV";
          field.hidden = !visible;
          each("input, select, textarea", field, function (input) {
            input.disabled = !visible;
          });
        });
      }
      type.addEventListener("change", updateFields);
      updateFields();
    });
  }

  function setLegacyView(name) {
    if (!name) return;
    each("[data-np-view]", document, function (button) {
      var active = button.getAttribute("data-np-view") === name;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-current", active ? "page" : "false");
    });
    each("[data-np-panel]", document, function (panel) {
      panel.classList.toggle("is-active", panel.getAttribute("data-np-panel") === name);
    });
  }

  function selectedSubscription(form) {
    var select = form && form.querySelector('select[name="subscription_id"]');
    return select && select.selectedOptions.length ? select.selectedOptions[0].dataset : null;
  }

  function gateMessage(data) {
    if (!data || data.hasQuota !== "true") return { blocked: true, text: "Select an active subscription." };
    var max = parseInt(data.maxSites || "-1", 10);
    var used = parseInt(data.sitesUsed || "0", 10);
    if (max >= 0 && used >= max) return { blocked: true, text: (data.planName || "This plan") + " has reached its website limit." };
    return { blocked: false, text: (data.planName || "This plan") + " can provision another website." };
  }

  function updateCreateGate(scope) {
    each("[data-np-create-site-form]", scope || document, function (form) {
      var result = gateMessage(selectedSubscription(form));
      updateSitePHP(form);
      var php = form.querySelector("[data-np-site-php]");
      if (php && php.options.length === 0) {
        result = { blocked: true, text: "No installed PHP-FPM version is allowed by this subscription." };
      }
      var message = form.querySelector("[data-np-customer-gate]");
      var submit = form.querySelector("[data-np-create-submit]");
      if (message) {
        message.textContent = result.text;
        message.classList.toggle("is-blocked", result.blocked);
      }
      if (submit) submit.disabled = result.blocked;
      form.dataset.npGateBlocked = result.blocked ? "true" : "false";
    });
  }

  function updateSitePHP(form) {
    var data = selectedSubscription(form);
    var select = form && form.querySelector("[data-np-site-php]");
    if (!select || !data) return;
    var previous = select.value;
    var versions = (data.phpVersions || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean);
    select.replaceChildren();
    versions.forEach(function (version) {
      var option = document.createElement("option");
      option.value = version;
      option.textContent = version;
      select.appendChild(option);
    });
    if (versions.indexOf(previous) !== -1) select.value = previous;
    select.disabled = versions.length === 0;
  }

  function openDialog(id, trigger) {
    var dialog = document.getElementById(id);
    if (!dialog || !dialog.showModal) return;
    lastDialogTrigger = trigger || null;
	if (trigger && trigger.dataset.npSubscriptionId) {
	  var subscription = dialog.querySelector('select[name="subscription_id"]');
	  if (subscription) subscription.value = trigger.dataset.npSubscriptionId;
	}
    dialog.showModal();
    document.body.classList.add("np-modal-open");
    updateCreateGate(dialog);
    var focus = dialog.querySelector("input:not([type=hidden]), select, button");
    if (focus) focus.focus();
  }

  function closeDialog(dialog) {
    if (!dialog) return;
    dialog.close();
    document.body.classList.remove("np-modal-open");
    if (lastDialogTrigger) lastDialogTrigger.focus();
    lastDialogTrigger = null;
  }

  function askConfirmation(message, trigger) {
    var dialog = document.getElementById("np-confirmation-dialog");
    if (!dialog || !dialog.showModal) return Promise.resolve(false);
    var copy = dialog.querySelector("[data-np-confirmation-copy]");
    if (copy) copy.textContent = message || "Continue with this action?";
    if (confirmationResolver) confirmationResolver(false);
    return new Promise(function (resolve) {
      confirmationResolver = resolve;
      openDialog(dialog.id, trigger);
    });
  }

  function resolveConfirmation(confirmed) {
    var resolve = confirmationResolver;
    confirmationResolver = null;
    if (resolve) resolve(confirmed);
    closeDialog(document.getElementById("np-confirmation-dialog"));
  }

  function setMenu(open) {
    document.body.classList.toggle("np-sidebar-open", open);
    var toggle = document.querySelector("[data-np-menu]");
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
    var scrim = document.querySelector("[data-np-menu-close]");
    if (scrim) scrim.hidden = !open;
  }

  function updateOnboarding() {
    var selected = document.querySelector('input[name="customer_mode"]:checked');
    var mode = selected ? selected.value : "existing";
    each("[data-np-customer-mode]", document, function (section) {
      var active = section.getAttribute("data-np-customer-mode") === mode;
      section.hidden = !active;
      each("input, select", section, function (input) {
        if (input.name === "customer_id" || input.name === "customer_email") input.required = active;
      });
    });
    var createSite = document.querySelector("[data-np-create-first-site]");
    var site = document.querySelector("[data-np-first-site]");
    if (createSite && site) {
      site.hidden = !createSite.checked;
      each("input, select", site, function (input) { input.required = createSite.checked; });
      var plan = document.querySelector("[data-np-onboarding-plan]");
      var php = site.querySelector("[data-np-onboarding-php]");
      var gate = site.querySelector("[data-np-onboarding-php-gate]");
      var option = plan && plan.options[plan.selectedIndex];
      var versions = option ? (option.dataset.phpVersions || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean) : [];
      if (php) {
        var previous = php.value;
        php.replaceChildren();
        versions.forEach(function (version) {
          var item = document.createElement("option");
          item.value = version;
          item.textContent = version;
          php.appendChild(item);
        });
        if (versions.indexOf(previous) !== -1) php.value = previous;
        php.disabled = createSite.checked && versions.length === 0;
      }
      if (gate) gate.hidden = !createSite.checked || versions.length > 0;
      var form = createSite.closest("form");
      var submit = form && form.querySelector('button[type="submit"]');
      if (submit) submit.disabled = createSite.checked && versions.length === 0;
    }
  }

  function updateBulkForm(form) {
    if (!form) return;
    var checks = form.querySelectorAll("[data-np-bulk-check]");
    var selected = form.querySelectorAll("[data-np-bulk-check]:checked").length;
    var all = form.querySelector("[data-np-bulk-all]");
    var count = form.querySelector("[data-np-bulk-count]");
    if (all) {
      all.checked = checks.length > 0 && selected === checks.length;
      all.indeterminate = selected > 0 && selected < checks.length;
    }
    if (count) count.textContent = selected + " selected";
    each('button[type="submit"]', form, function (button) { button.disabled = selected === 0; });
	if (form.matches("[data-np-subscription-bulk]")) {
	  var providers = {};
	  each("[data-np-bulk-check]:checked", form, function (input) {
	    var row = input.closest("[data-np-subscription-row]");
	    if (row) providers[row.getAttribute("data-provider-id") || "0"] = true;
	  });
	  var sameProvider = Object.keys(providers).length <= 1;
	  each('button[formaction="/subscriptions/bulk-plan"],button[formaction="/subscriptions/bulk-subscriber"]', form, function (button) {
	    button.disabled = selected === 0 || !sameProvider;
	  });
	  var warning = form.querySelector("[data-np-provider-warning]");
	  if (warning) warning.textContent = sameProvider ? "" : "Select subscriptions from one provider at a time.";
	  var bulkMenu = form.querySelector("[data-np-bulk-menu]");
	  if (bulkMenu) {
	    var enabled = selected > 0;
	    bulkMenu.dataset.enabled = enabled ? "true" : "false";
	    var bulkSummary = bulkMenu.querySelector("summary");
	    if (bulkSummary) bulkSummary.setAttribute("aria-disabled", enabled ? "false" : "true");
	    if (!enabled) bulkMenu.open = false;
	  }
	}
  }

  function renderSearch(results) {
    var panel = document.querySelector("[data-np-search-results]");
    if (!panel) return;
    panel.replaceChildren();
    if (!results.length) {
      var empty = document.createElement("p");
      empty.textContent = "No matching resources";
      panel.appendChild(empty);
    } else {
      results.forEach(function (result) {
        var link = document.createElement("a");
        link.href = result.url;
        var label = document.createElement("strong");
        label.textContent = result.label;
        var detail = document.createElement("span");
        detail.textContent = result.kind + " · " + result.detail;
        link.append(label, detail);
        panel.appendChild(link);
      });
    }
    panel.hidden = false;
  }

  var searchTimer = 0;
  function runSearch(value) {
    window.clearTimeout(searchTimer);
    var panel = document.querySelector("[data-np-search-results]");
    if (!value.trim()) { if (panel) panel.hidden = true; return; }
    searchTimer = window.setTimeout(function () {
      fetch("/search?q=" + encodeURIComponent(value.trim()), { credentials: "same-origin" })
        .then(function (response) { return response.json(); })
        .then(function (data) { renderSearch(data.results || []); })
        .catch(function () { renderSearch([]); });
    }, 180);
  }

  function filterSettings(value) {
    var page = document.querySelector(".np-settings-page");
    if (!page) return;
    var query = (value || "").trim().toLowerCase();
    var visible = 0;
    each("[data-np-settings-category]", page, function (category) {
      var categoryVisible = 0;
      each("[data-np-settings-tool]", category, function (tool) {
        var content = (tool.textContent + " " + (tool.getAttribute("data-np-settings-keywords") || "")).toLowerCase();
        var matches = !query || content.indexOf(query) !== -1;
        tool.hidden = !matches;
        if (matches) {
          visible += 1;
          categoryVisible += 1;
        }
      });
      category.hidden = categoryVisible === 0;
    });
    var count = page.querySelector("[data-np-settings-result-count]");
    var empty = page.querySelector("[data-np-settings-empty]");
    if (count) count.textContent = visible + (query ? (visible === 1 ? " match" : " matches") : (visible === 1 ? " tool" : " tools"));
    if (empty) empty.hidden = visible !== 0;
  }

  function securePassword(length) {
    var groups = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%*-_+"];
    var alphabet = groups.join("");
    var bytes = new Uint32Array(length);
    window.crypto.getRandomValues(bytes);
    var password = groups.map(function (group, index) { return group[bytes[index] % group.length]; });
    for (var i = groups.length; i < length; i += 1) password.push(alphabet[bytes[i] % alphabet.length]);
    for (var j = password.length - 1; j > 0; j -= 1) {
      var swap = bytes[j] % (j + 1);
      var value = password[j];
      password[j] = password[swap];
      password[swap] = value;
    }
    return password.join("");
  }

  function passwordInput(trigger) {
    var field = trigger && trigger.closest(".np-password-field");
    return field && field.querySelector("[data-np-generated-password]");
  }

  function loadServerInventory() {
    var target = document.querySelector("[data-np-settings-inventory]");
    if (!target || !window.fetch) return Promise.resolve();
    var setText = function (selector, value) {
      each(selector, document, function (element) { element.textContent = value; });
    };
    return fetch("/tools-settings/inventory", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data.ok || !data.inventory) throw new Error("inventory unavailable");
          return data;
        });
      })
      .then(function (payload) {
        var inventory = payload.inventory;
        var cached = payload.cached === true;
        serverInventoryHostname = cached ? "" : (inventory.hostname || "");
        function formatBytes(value) {
          var bytes = Number(value || 0);
          if (!bytes) return "Unknown";
          var units = ["B", "KB", "MB", "GB", "TB"];
          var index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
          return (bytes / Math.pow(1024, index)).toFixed(index > 2 ? 1 : 0) + " " + units[index];
        }
        var status = cached ? "stale" : (inventory.status || "unknown").toLowerCase();
        var statusClass = status === "healthy" ? "np-pill-ok" : (status === "warning" || status === "pending" ? "np-pill-pend" : (status === "critical" ? "np-pill-fail" : "np-pill-susp"));
        var state = document.querySelector("[data-np-server-inventory-state]");
        var indicator = target.querySelector(".np-health-indicator");
        var checked = inventory.checked_at ? new Date(inventory.checked_at).toLocaleString() : "time unknown";
        if (state) { state.textContent = status; state.className = "np-pill " + statusClass; }
        if (indicator) indicator.className = "np-health-indicator " + (status === "healthy" ? "is-live" : (status === "critical" ? "is-failed" : "is-checking"));
        setText("[data-np-server-inventory-copy]", (cached ? "Cached · " : "") + (inventory.hostname || "Host") + " · checked " + checked + (inventory.last_error ? " · " + inventory.last_error : ""));
        setText("[data-np-server-hostname]", (inventory.hostname || "Hostname unavailable") + (inventory.operating_system ? " · " + inventory.operating_system : ""));
        var time = inventory.time || {};
        setText("[data-np-server-time]", time.available ? ((time.timezone || "Timezone unknown") + " · NTP " + (time.synchronized ? "synchronized" : (time.sync_enabled ? "enabled" : "disabled"))) : "Time state unavailable");
        var phpCount = (inventory.php_handlers || []).length;
        var services = inventory.services || [];
        var serviceCount = services.length;
        var serviceRunning = services.filter(function (service) { return service.available && service.active_state === "active"; }).length;
        var serviceStopped = services.filter(function (service) { return service.available && service.active_state !== "active"; }).length;
        var serviceUnavailable = services.filter(function (service) { return !service.available; }).length;
        setText("[data-np-server-php-count]", phpCount + (phpCount === 1 ? " host handler" : " host handlers"));
        setText("[data-np-server-service-count]", serviceCount + (serviceCount === 1 ? " managed service" : " managed services") + " discovered.");
        setText("[data-np-service-running]", String(serviceRunning));
        setText("[data-np-service-stopped]", String(serviceStopped));
        setText("[data-np-service-unavailable]", String(serviceUnavailable));
        setText("[data-np-service-checked]", inventory.checked_at ? new Date(inventory.checked_at).toLocaleTimeString() : "Unknown");
        setText("[data-np-service-host]", (inventory.hostname || "Host") + " · " + serviceCount + " discovered");
        setText("[data-np-focus-hostname]", inventory.hostname || "Unknown");
        setText("[data-np-focus-os]", inventory.operating_system || "Unknown");
        setText("[data-np-focus-kernel]", inventory.kernel || "Unknown");
        setText("[data-np-focus-time]", time.available ? ((time.timezone || "Unknown") + " / " + (time.synchronized ? "synchronized" : "not synchronized")) : "Unknown");
        setText("[data-np-focus-cpu]", inventory.cpu_count ? (inventory.cpu_count + " logical CPUs") : "Unknown");
        setText("[data-np-focus-memory]", inventory.memory && inventory.memory.total_bytes ? (formatBytes(inventory.memory.available_bytes) + " available / " + formatBytes(inventory.memory.total_bytes)) : "Unknown");

        var phpList = document.querySelector("[data-np-focus-php]");
        if (phpList) {
          phpList.replaceChildren();
          (inventory.php_handlers || []).forEach(function (handler) {
            var row = document.createElement("div");
            row.className = "np-settings-runtime";
            var identity = document.createElement("div");
            var title = document.createElement("strong");
            title.textContent = "PHP " + (handler.full_version || handler.version || "unknown");
            var detail = document.createElement("small");
            detail.textContent = (handler.sapi || "FPM") + " · " + (handler.extensions || []).length + " extensions";
            identity.append(title, detail);
            var service = document.createElement("div");
            service.textContent = handler.service_id || "No service";
            var statePill = document.createElement("span");
            statePill.className = "np-pill " + (handler.state === "active" ? "np-pill-ok" : "np-pill-susp");
            statePill.textContent = handler.state || "unknown";
            row.append(identity, service, statePill);
            phpList.appendChild(row);
          });
          if (!phpList.children.length) {
            var empty = document.createElement("p");
            empty.className = "np-empty";
            empty.textContent = "No PHP-FPM handlers were discovered.";
            phpList.appendChild(empty);
          }
        }

        var serviceList = document.querySelector("[data-np-focus-services]");
        if (serviceList) {
          var controllable = {
            "web": true, "dns": true, "mail": true,
            "php-8.1": true, "php-8.2": true, "php-8.3": true,
            "php-8.4": true, "php-8.5": true
          };
          var groupDefinitions = [
            {id: "control", name: "Control plane", description: "Nakpanel application and privileged host agent.", icon: "settings"},
            {id: "hosting", name: "Hosting services", description: "Tenant-facing web, DNS, and mail services.", icon: "globe"},
            {id: "data", name: "Data & platform", description: "Database, container, and host support services.", icon: "database"},
            {id: "php", name: "PHP runtimes", description: "Installed and discoverable PHP-FPM handlers.", icon: "file-code"},
            {id: "other", name: "Other services", description: "Additional allowlisted system services.", icon: "activity"}
          ];
          var grouped = {};
          groupDefinitions.forEach(function (group) { grouped[group.id] = []; });
          services.forEach(function (service) {
            var group = "other";
            if (service.id === "panel" || service.id === "agent") group = "control";
            else if (service.id === "web" || service.id === "dns" || service.id === "mail") group = "hosting";
            else if (service.id.indexOf("php-") === 0) group = "php";
            else if (["mariadb", "postgresql", "podman", "time_sync"].indexOf(service.id) !== -1) group = "data";
            grouped[group].push(service);
          });
          function serviceIcon(name) {
            var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
            svg.setAttribute("class", "np-icon");
            svg.setAttribute("viewBox", "0 0 24 24");
            svg.setAttribute("fill", "none");
            svg.setAttribute("stroke", "currentColor");
            svg.setAttribute("stroke-width", "2");
            svg.setAttribute("stroke-linecap", "round");
            svg.setAttribute("stroke-linejoin", "round");
            svg.setAttribute("aria-hidden", "true");
            use.setAttribute("href", "/assets/icons.svg#" + name);
            svg.appendChild(use);
            return svg;
          }
          function serviceState(service) {
            if (!service.available) return {label: "Unavailable", className: "np-pill-susp", row: "unavailable"};
            if (service.result && service.result !== "success") return {label: "Failed", className: "np-pill-fail", row: "failed"};
            if (service.active_state === "active") return {label: service.sub_state === "running" ? "Running" : "Active", className: "np-pill-ok", row: "running"};
            return {label: "Stopped", className: "np-pill-pend", row: "stopped"};
          }
          function serviceIconName(service) {
            if (service.id === "web") return "globe";
            if (service.id === "dns") return "network";
            if (service.id === "mail") return "mail";
            if (service.id === "mariadb" || service.id === "postgresql") return "database";
            if (service.id.indexOf("php-") === 0) return "file-code";
            if (service.id === "panel" || service.id === "agent") return "settings";
            return "activity";
          }
          serviceList.replaceChildren();
          groupDefinitions.forEach(function (definition) {
            if (!grouped[definition.id].length) return;
            var section = document.createElement("section");
            section.className = "np-settings-service-group";
            section.setAttribute("aria-labelledby", "np-service-group-" + definition.id);
            var header = document.createElement("header");
            var headerIcon = document.createElement("span");
            headerIcon.className = "np-settings-category-icon";
            headerIcon.appendChild(serviceIcon(definition.icon));
            var headerCopy = document.createElement("div");
            var heading = document.createElement("h4");
            heading.id = "np-service-group-" + definition.id;
            heading.textContent = definition.name;
            var description = document.createElement("p");
            description.textContent = definition.description;
            headerCopy.append(heading, description);
            var count = document.createElement("span");
            count.className = "np-service-group-count";
            count.textContent = grouped[definition.id].length + (grouped[definition.id].length === 1 ? " service" : " services");
            header.append(headerIcon, headerCopy, count);
            var rows = document.createElement("div");
            rows.className = "np-settings-service-list";
            grouped[definition.id].forEach(function (service) {
              var state = serviceState(service);
              var row = document.createElement("article");
              row.className = "np-settings-service is-" + state.row;
              var identity = document.createElement("div");
              identity.className = "np-service-identity";
              var identityIcon = document.createElement("span");
              identityIcon.className = "np-service-icon";
              identityIcon.appendChild(serviceIcon(serviceIconName(service)));
              var identityCopy = document.createElement("div");
              var title = document.createElement("strong");
              title.textContent = service.display_name || service.id;
              var detail = document.createElement("small");
              detail.textContent = service.id;
              identityCopy.append(title, detail);
              identity.append(identityIcon, identityCopy);

              var metadata = document.createElement("dl");
              metadata.className = "np-service-metadata";
              [
                ["Unit", service.unit_file_state || "not installed"],
                ["PID", service.main_pid ? String(service.main_pid) : "—"],
                ["Memory", service.memory_bytes ? formatBytes(service.memory_bytes) : "—"]
              ].forEach(function (item) {
                var fact = document.createElement("div");
                var term = document.createElement("dt");
                var value = document.createElement("dd");
                term.textContent = item[0];
                value.textContent = item[1];
                fact.append(term, value);
                metadata.appendChild(fact);
              });

              var stateBlock = document.createElement("div");
              stateBlock.className = "np-service-state";
              var statePill = document.createElement("span");
              statePill.className = "np-pill " + state.className;
              statePill.textContent = state.label;
              var stateDetail = document.createElement("small");
              stateDetail.textContent = service.available ? ((service.sub_state || service.active_state || "unknown") + (service.restart_count ? " · " + service.restart_count + " restarts" : "")) : "Unit not found";
              stateBlock.append(statePill, stateDetail);

              var allowed = (service.allowed_actions || []).filter(function (action) {
                return ["reload", "restart", "start", "stop"].indexOf(action) !== -1;
              });
              var actionControl;
              if (controllable[service.id] && service.available && allowed.length) {
                actionControl = document.createElement("details");
                actionControl.className = "np-settings-service-menu";
                var summary = document.createElement("summary");
                summary.setAttribute("aria-label", "Actions for " + (service.display_name || service.id));
                summary.append(serviceIcon("ellipsis"), document.createTextNode("Actions"));
                var actions = document.createElement("form");
                actions.className = "np-settings-service-actions";
                actions.method = "post";
                actions.action = "/tools-settings/services/action";
                actions.setAttribute("data-np-service-form", "");
                var idInput = document.createElement("input");
                idInput.type = "hidden";
                idInput.name = "service_id";
                idInput.value = service.id;
                actions.appendChild(idInput);
                allowed.forEach(function (action) {
                  var button = document.createElement("button");
                  button.type = "submit";
                  button.name = "action";
                  button.value = action;
                  button.className = action === "stop" ? "np-service-action-danger" : "";
                  button.textContent = action.charAt(0).toUpperCase() + action.slice(1);
                  if (action === "restart" || action === "stop") {
                    button.setAttribute("data-np-confirm", (action === "restart" ? "Restart " : "Stop ") + (service.display_name || service.id) + "? Hosted workloads may be interrupted.");
                  }
                  actions.appendChild(button);
                });
                actionControl.append(summary, actions);
              } else {
                actionControl = document.createElement("span");
                actionControl.className = "np-service-readonly";
                actionControl.textContent = service.available ? "Observed" : "Not installed";
              }
              row.append(identity, metadata, stateBlock, actionControl);
              rows.appendChild(row);
            });
            section.append(header, rows);
            serviceList.appendChild(section);
          });
          if (!serviceList.children.length) {
            var serviceEmpty = document.createElement("p");
            serviceEmpty.className = "np-empty";
            serviceEmpty.textContent = "No managed services were discovered.";
            serviceList.appendChild(serviceEmpty);
          }
        }
      })
      .catch(function () {
        var state = document.querySelector("[data-np-server-inventory-state]");
        var indicator = target.querySelector(".np-health-indicator");
        if (state) { state.textContent = "unavailable"; state.className = "np-pill np-pill-fail"; }
        if (indicator) indicator.className = "np-health-indicator is-failed";
        setText("[data-np-server-inventory-copy]", "Inventory endpoint unavailable");
        setText("[data-np-server-hostname]", "Host inventory unavailable");
        setText("[data-np-server-time]", "Time state unavailable");
        setText("[data-np-server-php-count]", "Host handlers unavailable");
        setText("[data-np-server-service-count]", "Managed service inventory unavailable.");
      });
  }

  function formStatus(form, fallbackSelector) {
    var scope = form.closest(".np-settings-focus, dialog");
    return (scope && scope.querySelector("[data-np-reauth-status]")) ||
      (fallbackSelector && document.querySelector(fallbackSelector));
  }

  function setFormBusy(form, busy) {
    each('button[type="submit"], input[type="submit"]', form, function (control) {
      control.disabled = busy;
    });
    form.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function clearSensitiveInputs(form) {
    each('input[type="password"]', form, function (input) { input.value = ""; });
  }

  function pollServerOperation(operationID, status, onSuccess) {
    if (!operationID || !status || !window.fetch) return;
    var attempts = 0;
    var terminal = {succeeded: true, failed: true, rolled_back: true, cancelled: true};
    function poll() {
      attempts += 1;
      fetch("/tools-settings/operations/" + encodeURIComponent(operationID), {
        credentials: "same-origin",
        headers: {"Accept": "application/json"}
      }).then(function (response) {
        return response.json().then(function (payload) {
          if (!response.ok || !payload.ok || !payload.operation) throw new Error(payload.error || "Operation status is unavailable");
          return payload.operation;
        });
      }).then(function (operation) {
        var state = operation.status || "pending";
        status.hidden = false;
        status.textContent = operationID + " · " + state.replace(/_/g, " ") + (operation.error ? " · " + operation.error : "");
        status.setAttribute("role", state === "failed" ? "alert" : "status");
        if (state === "succeeded" && onSuccess) onSuccess();
        if (!terminal[state] && attempts < 40) window.setTimeout(poll, 1500);
      }).catch(function () {
        if (attempts < 10) window.setTimeout(poll, 2000);
      });
    }
    window.setTimeout(poll, 600);
  }

  function submitServerAdminForm(form, submitter) {
    var isReauthentication = form.matches("[data-np-reauth-form]");
    var status = formStatus(form, "[data-np-service-operation]");
    var data = new FormData(form);
    if (submitter && submitter.name) data.set(submitter.name, submitter.value);
    setFormBusy(form, true);
    if (status) {
      status.hidden = false;
      status.setAttribute("role", "status");
      status.textContent = "Submitting operation...";
    }
    fetch(form.action, {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: {"Accept": "application/json", "X-Nakpanel-CSRF": csrfToken()}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Operation failed");
        return payload;
      });
    }).then(function (payload) {
      var operationID = payload.operation_id || (payload.result && payload.result.operation_id);
      if (status) status.textContent = operationID ? ("Queued as " + operationID + ".") : "Authentication refreshed for 10 minutes.";
      if (form.matches("[data-np-service-form]")) {
        pollServerOperation(operationID, status, loadServerInventory);
      }
    }).catch(function (error) {
      if (status) {
        status.hidden = false;
        status.setAttribute("role", "alert");
        status.textContent = error.message;
      }
    }).then(function () {
      clearSensitiveInputs(form);
      setFormBusy(form, false);
      if (isReauthentication && status && status.getAttribute("role") !== "alert") status.setAttribute("role", "status");
    });
  }

  function loadServerJournal(form) {
    var target = document.querySelector("[data-np-journal-entries]");
    if (!target || !window.fetch) return;
    form = form || document.querySelector("[data-np-journal-filter]");
    if (!form) return;
    var status = document.querySelector("[data-np-journal-state]");
    var params = new URLSearchParams(new FormData(form));
    target.replaceChildren();
    var loadingRow = document.createElement("tr");
    var loadingCell = document.createElement("td");
    loadingCell.colSpan = 4;
    loadingCell.textContent = "Loading bounded journal entries...";
    loadingRow.appendChild(loadingCell);
    target.appendChild(loadingRow);
    fetch("/tools-settings/journal?" + params.toString(), {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok || !payload.result) throw new Error(payload.error || "Journal is unavailable");
        return payload.result;
      });
    }).then(function (result) {
      target.replaceChildren();
      (result.entries || []).forEach(function (entry) {
        var row = document.createElement("tr");
        [
          entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "Unknown",
          entry.source_id || "unknown",
          String(entry.priority),
          entry.message || ""
        ].forEach(function (value, index) {
          var cell = document.createElement("td");
          cell.dataset.label = ["Time", "Source", "Priority", "Message"][index];
          cell.textContent = value;
          row.appendChild(cell);
        });
        target.appendChild(row);
      });
      if (!target.children.length) {
        var row = document.createElement("tr");
        var cell = document.createElement("td");
        cell.colSpan = 4;
        cell.textContent = "No entries matched this source and window.";
        row.appendChild(cell);
        target.appendChild(row);
      }
      if (status) {
        status.hidden = false;
        status.textContent = (result.entries || []).length + " bounded entries loaded" + (result.truncated ? " (messages truncated)" : "") + ".";
      }
    }).catch(function (error) {
      target.replaceChildren();
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 4;
      cell.textContent = "Journal entries could not be loaded.";
      row.appendChild(cell);
      target.appendChild(row);
      if (status) { status.hidden = false; status.textContent = error.message; }
    });
  }

  function renderServerUpdates(state, dryRun) {
    var target = document.querySelector("[data-np-update-packages]");
    if (!target) return;
    var badge = document.querySelector("[data-np-update-state]");
    var summary = document.querySelector("[data-np-update-summary]");
    var packages = state.packages || [];
    var lastRefresh = state.last_refresh_at ? new Date(state.last_refresh_at) : null;
    var repositoryFresh = lastRefresh && !isNaN(lastRefresh.getTime()) && (Date.now() - lastRefresh.getTime()) <= 24 * 60 * 60 * 1000;
    if (badge) {
      badge.textContent = packages.length ? "updates available" : (repositoryFresh ? "up to date" : "inventory stale");
      badge.className = "np-pill " + (packages.length ? "np-pill-pend" : (repositoryFresh ? "np-pill-ok" : "np-pill-susp"));
    }
    var setUpdateText = function (selector, value) {
      var element = document.querySelector(selector);
      if (element) element.textContent = value;
    };
    setUpdateText("[data-np-update-security]", String(Number(state.security_count || 0)));
    setUpdateText("[data-np-update-standard]", String(Number(state.normal_count || 0)));
    setUpdateText("[data-np-update-reboot]", state.reboot_required ? "Required" : "Not required");
    setUpdateText("[data-np-update-freshness]", repositoryFresh ? "Current" : "Stale");
    setUpdateText("[data-np-update-checked]", lastRefresh && !isNaN(lastRefresh.getTime()) ? ("Refreshed " + lastRefresh.toLocaleString()) : "Refresh time unavailable");
    if (summary) {
      summary.textContent = packages.length + (packages.length === 1 ? " package" : " packages") +
        " in the current signed inventory · automatic policy " + (state.automatic_policy || "unknown") + ".";
    }
    target.replaceChildren();
    packages.forEach(function (item) {
      var row = document.createElement("tr");
      var updateClass = item.held ? "held" : (item.security ? "security" : "standard");
      row.dataset.updateName = (item.name || "").toLowerCase();
      row.dataset.updateClass = updateClass;
      var selectCell = document.createElement("td");
      selectCell.dataset.label = "Select";
      var select = document.createElement("input");
      select.type = "checkbox";
      select.name = "package_names";
      select.value = item.name || "";
      select.setAttribute("form", "np-update-install-form");
      select.setAttribute("aria-label", "Select " + (item.name || "package"));
      select.disabled = !item.name || item.held;
      selectCell.appendChild(select);
      row.appendChild(selectCell);
      var packageCell = document.createElement("td");
      packageCell.dataset.label = "Package";
      var packageName = document.createElement("strong");
      packageName.textContent = item.name || "Unknown";
      packageCell.appendChild(packageName);
      row.appendChild(packageCell);
      [item.current || "Not reported", item.candidate || "Not reported"].forEach(function (value, index) {
        var cell = document.createElement("td");
        cell.dataset.label = index === 0 ? "Current" : "Candidate";
        var code = document.createElement("code");
        code.textContent = value;
        cell.appendChild(code);
        row.appendChild(cell);
      });
      var classCell = document.createElement("td");
      classCell.dataset.label = "Class";
      var classPill = document.createElement("span");
      classPill.className = "np-update-class is-" + updateClass;
      classPill.textContent = item.held ? "Held" : (item.security ? "Security" : "Standard");
      classCell.appendChild(classPill);
      row.appendChild(classCell);
      target.appendChild(row);
    });
    if (!target.children.length) {
      var row = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 5;
      cell.textContent = "No available package updates were reported.";
      row.appendChild(cell);
      target.appendChild(row);
    }
    var operation = document.querySelector("[data-np-update-operation]");
    if (dryRun && operation) {
      operation.hidden = false;
      operation.textContent = "Simulation completed. No packages were installed.";
    } else if (operation) {
      operation.hidden = true;
      operation.textContent = "";
    }
    target.dataset.securityCount = String(Number(state.security_count || 0));
    filterServerUpdates();
    updateInstallSelection();
  }

  function updateUpdateSelectAll() {
    var selectAll = document.querySelector("[data-np-update-select-all]");
    if (!selectAll) return;
    var visible = Array.prototype.filter.call(
      document.querySelectorAll('[data-np-update-packages] input[name="package_names"]:not(:disabled)'),
      function (input) { return !input.closest("tr").hidden; }
    );
    var selected = visible.filter(function (input) { return input.checked; }).length;
    selectAll.checked = visible.length > 0 && selected === visible.length;
    selectAll.indeterminate = selected > 0 && selected < visible.length;
    selectAll.disabled = visible.length === 0;
  }

  function filterServerUpdates() {
    var target = document.querySelector("[data-np-update-packages]");
    if (!target) return;
    var search = document.querySelector("[data-np-update-search]");
    var filter = document.querySelector("[data-np-update-filter]");
    var query = search ? search.value.trim().toLowerCase() : "";
    var selectedClass = filter ? filter.value : "all";
    var visible = 0;
    each("tr[data-update-name]", target, function (row) {
      var matchesQuery = !query || row.dataset.updateName.indexOf(query) !== -1;
      var matchesClass = selectedClass === "all" || row.dataset.updateClass === selectedClass;
      row.hidden = !(matchesQuery && matchesClass);
      if (!row.hidden) visible += 1;
    });
    var count = document.querySelector("[data-np-update-visible-count]");
    if (count) count.textContent = visible + (visible === 1 ? " package shown" : " packages shown");
    var empty = document.querySelector("[data-np-update-empty]");
    if (empty) empty.hidden = visible !== 0;
    updateUpdateSelectAll();
  }

  function updateInstallSelection() {
    var form = document.querySelector("[data-np-update-install-form]");
    var button = form && form.querySelector("[data-np-update-install]");
    if (!form || !button || form.getAttribute("aria-busy") === "true") return;
    var selected = document.querySelectorAll('input[name="package_names"][form="np-update-install-form"]:checked:not(:disabled)').length;
    var securityOnly = form.querySelector('input[name="security_only"]');
    var target = document.querySelector("[data-np-update-packages]");
    var securityCount = Number((target && target.dataset.securityCount) || 0);
    button.disabled = selected === 0 && !(securityOnly && securityOnly.checked && securityCount > 0);
    var selectionCopy = document.querySelector("[data-np-update-selected-count]");
    var effectiveCount = securityOnly && securityOnly.checked ? securityCount : selected;
    if (selectionCopy) selectionCopy.textContent = effectiveCount + (effectiveCount === 1 ? " package selected" : " packages selected");
    button.textContent = effectiveCount > 0 ? ("Install " + effectiveCount + (effectiveCount === 1 ? " update" : " updates")) : "Install updates";
    updateUpdateSelectAll();
  }

  function loadServerUpdates(dryRun) {
    var target = document.querySelector("[data-np-update-packages]");
    if (!target || !window.fetch) return Promise.resolve(false);
    var operation = document.querySelector("[data-np-update-operation]");
    var button = document.querySelector("[data-np-update-dry-run]");
    var refresh = document.querySelector("[data-np-update-refresh]");
    var request = {
      method: dryRun ? "POST" : "GET",
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    };
    if (dryRun) request.headers["X-Nakpanel-CSRF"] = csrfToken();
    if (button) button.disabled = true;
    if (refresh) refresh.disabled = true;
    if (operation) { operation.hidden = false; operation.textContent = dryRun ? "Running package simulation..." : "Loading update inventory..."; }
    return fetch(dryRun ? "/tools-settings/updates/dry-run" : "/tools-settings/updates/inventory", request)
      .then(function (response) {
        return response.json().then(function (payload) {
          if (!response.ok || !payload.ok || (!payload.updates && !payload.operation_id)) throw new Error(payload.error || "Update inventory is unavailable");
          return payload;
        });
      })
      .then(function (payload) {
        if (payload.operation_id) {
          if (operation) {
            operation.hidden = false;
            operation.textContent = payload.operation_id + " · simulation queued";
          }
          pollServerOperation(payload.operation_id, operation, function () { loadServerUpdates(false); });
          return true;
        }
        renderServerUpdates(payload.updates, dryRun);
        return true;
      })
      .catch(function (error) {
        if (operation) { operation.hidden = false; operation.textContent = error.message; }
        var badge = document.querySelector("[data-np-update-state]");
        if (badge) { badge.textContent = "unavailable"; badge.className = "np-pill np-pill-fail"; }
        return false;
      })
      .then(function (success) {
        if (button) button.disabled = false;
        if (refresh) refresh.disabled = false;
        return success;
      });
  }

  function loadMailStatus() {
    var status = document.querySelector("[data-np-mail-status]");
    if (!status || !window.fetch) return;
    fetch("/mail/status", { credentials: "same-origin" })
      .then(function (response) { return response.json().then(function (data) { if (!response.ok || !data.ok) throw new Error("status unavailable"); return data.status; }); })
      .then(function (data) {
        var state = document.querySelector("[data-np-mail-state]");
        var version = document.querySelector("[data-np-mail-version]");
        var listeners = document.querySelector("[data-np-mail-listeners]");
        var queue = document.querySelector("[data-np-mail-queue]");
        var healthCopy = document.querySelector("[data-np-mail-health-copy]");
        var healthIndicator = document.querySelector("[data-np-mail-health-indicator]");
		var error = document.querySelector("[data-np-mail-status-error]");
        if (state) { state.textContent = data.state || "unknown"; state.className = "np-pill " + (data.state === "active" ? "np-pill-ok" : "np-pill-fail"); }
        if (version) version.textContent = data.version || data.state || "Unknown";
        if (listeners) listeners.textContent = (data.listeners || []).join(", ") || "None detected";
        if (queue) queue.textContent = String(data.total_queued || 0);
        if (healthCopy) healthCopy.textContent = data.state === "active" ? ((data.version || "Stalwart") + " responding") : (data.last_error || "Agent reported " + (data.state || "unknown"));
        if (healthIndicator) healthIndicator.className = "np-health-indicator " + (data.state === "active" ? "is-live" : "is-failed");
		if (error) { error.textContent = data.last_error || ""; error.hidden = !data.last_error; }
      })
      .catch(function () {
        var state = document.querySelector("[data-np-mail-state]");
        var version = document.querySelector("[data-np-mail-version]");
        var healthCopy = document.querySelector("[data-np-mail-health-copy]");
        var healthIndicator = document.querySelector("[data-np-mail-health-indicator]");
        if (state) { state.textContent = "unavailable"; state.className = "np-pill np-pill-fail"; }
        if (version) version.textContent = "Status unavailable";
        if (healthCopy) healthCopy.textContent = "Agent status unavailable";
        if (healthIndicator) healthIndicator.className = "np-health-indicator is-failed";
		var error = document.querySelector("[data-np-mail-status-error]");
		if (error) { error.textContent = "Could not read Stalwart status from the agent."; error.hidden = false; }
      });
  }

  function loadServerSecurity() {
    var state = document.querySelector("[data-np-security-state]");
    if (!state || !window.fetch) return;
    fetch("/tools-settings/security/status", {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok || !payload.policy) throw new Error(payload.error || "Security inspection is unavailable");
        return payload;
      });
    }).then(function (payload) {
      var policy = payload.policy;
      var capabilities = payload.capabilities || {};
      var firewall = policy.firewall || {};
      var ssh = policy.ssh || {};
      var fail2ban = policy.fail2ban || {};
      state.textContent = capabilities.firewall_mutation ? "managed" : "read only";
      state.className = "np-pill np-pill-ok";
      var smtpWarning = document.querySelector("[data-np-security-smtp-warning]");
      if (smtpWarning) smtpWarning.hidden = !!payload.smtp_configured;
      var firewallCopy = document.querySelector("[data-np-security-firewall]");
      var inboundCopy = document.querySelector("[data-np-security-inbound]");
      var fail2banCopy = document.querySelector("[data-np-security-fail2ban]");
      var sshCopy = document.querySelector("[data-np-security-ssh]");
      var tlsCopy = document.querySelector("[data-np-security-tls]");
      if (firewallCopy) firewallCopy.textContent = firewall.enabled ? ((firewall.rules || []).length + " managed rules") : "Not enabled";
      if (inboundCopy) inboundCopy.textContent = firewall.default_inbound || "Unknown";
      if (fail2banCopy) fail2banCopy.textContent = fail2ban.enabled ? "Running" : "Not running";
      if (sshCopy) sshCopy.textContent = "Port " + (ssh.port || "unknown") + " · root " + (ssh.permit_root_login ? "permitted" : "disabled") + " · password " + (ssh.password_authentication ? "enabled" : "disabled");
      if (tlsCopy) tlsCopy.textContent = policy.tls && policy.tls.profile ? policy.tls.profile : "Unknown";
      loadSecurityBans();
    }).catch(function () {
      state.textContent = "unavailable";
      state.className = "np-pill np-pill-fail";
    });
  }

  function securityAction(url, body, successMessage, confirmMessage) {
    if (confirmMessage && !window.confirm(confirmMessage)) return;
    var status = document.querySelector("[data-np-security-action-state]");
    fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Nakpanel-CSRF": csrfToken()
      },
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (response.status === 428) throw new Error("Recent authentication is required: confirm your password first.");
        if (!response.ok || !payload.ok) throw new Error(payload.error || "The security action failed.");
        return payload;
      });
    }).then(function (payload) {
      if (status) { status.textContent = successMessage || "Done."; status.hidden = false; }
      if (payload.operation_id) trackSecurityOperation(payload.operation_id);
      loadSecurityBans();
    }).catch(function (err) {
      if (status) { status.textContent = err && err.message ? err.message : "The security action failed."; status.hidden = false; }
    });
  }

  function trackSecurityOperation(operationID) {
    var form = document.querySelector("[data-np-security-op-form]");
    var copy = document.querySelector("[data-np-security-op-copy]");
    if (!form) return;
    form.hidden = false;
    var input = form.querySelector('input[name="operation_id"]');
    if (input) input.value = operationID;
    if (copy) copy.textContent = "Staged firewall operation " + operationID + " is awaiting confirmation. Unconfirmed changes auto-revert at the agent's rollback deadline.";
  }

  function loadSecurityBans() {
    var target = document.querySelector("[data-np-security-bans]");
    if (!target || !window.fetch) return;
    fetch("/tools-settings/security/bans", {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Ban list unavailable");
        return payload.bans || {};
      });
    }).then(function (bans) {
      target.replaceChildren();
      if (!bans.running) {
        replaceTableWithMessage(target, 3, "Fail2ban is not running on this server.");
        return;
      }
      var jails = bans.jails || [];
      if (!jails.length) {
        replaceTableWithMessage(target, 3, "Fail2ban is running with no managed jails yet.");
        return;
      }
      jails.forEach(function (jail) {
        var row = document.createElement("tr");
        var name = document.createElement("td");
        name.textContent = jail.jail;
        row.appendChild(name);
        var list = document.createElement("td");
        list.textContent = (jail.banned || []).join(", ") || "none";
        row.appendChild(list);
        var actions = document.createElement("td");
        (jail.banned || []).forEach(function (address) {
          var unban = document.createElement("button");
          unban.type = "button";
          unban.className = "np-secondary-button";
          unban.textContent = "Unban " + address;
          unban.addEventListener("click", function () {
            securityAction("/tools-settings/security/bans/unban", {jail_id: jail.jail, address: address}, address + " unbanned.");
          });
          actions.appendChild(unban);
        });
        row.appendChild(actions);
        target.appendChild(row);
      });
    }).catch(function () {
      replaceTableWithMessage(target, 3, "Jail status is unavailable.");
    });
  }

  function bindSecurityControls() {
    var fail2banButton = document.querySelector("[data-np-security-fail2ban-defaults]");
    if (fail2banButton) {
      fail2banButton.addEventListener("click", function () {
        securityAction("/tools-settings/security/fail2ban", {
          policy: {
            enabled: true,
            jails: [
              {id: "sshd", enabled: true, ban_time_seconds: 3600, find_time_seconds: 600, max_retry: 5},
              {id: "nakpanel-login", enabled: true, ban_time_seconds: 3600, find_time_seconds: 600, max_retry: 5}
            ]
          }
        }, "Fail2ban policy queued.");
      });
    }
    var confirmButton = document.querySelector("[data-np-security-op-confirm]");
    if (confirmButton) {
      confirmButton.addEventListener("click", function () {
        var input = document.querySelector('[data-np-security-op-form] input[name="operation_id"]');
        if (input && input.value) securityAction("/tools-settings/security/firewall/confirm", {operation_id: input.value}, "Firewall change confirmed.");
      });
    }
    var revertButton = document.querySelector("[data-np-security-op-revert]");
    if (revertButton) {
      revertButton.addEventListener("click", function () {
        var input = document.querySelector('[data-np-security-op-form] input[name="operation_id"]');
        if (input && input.value) securityAction("/tools-settings/security/firewall/revert", {operation_id: input.value}, "Firewall change reverted.");
      });
    }
  }

  function loadServerBackups() {
    var state = document.querySelector("[data-np-backup-state]");
    if (!state || !window.fetch) return;
    fetch("/tools-settings/backups/status", {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Server backups are unavailable");
        return payload;
      });
    }).then(function (payload) {
      state.textContent = payload.key_present ? "configured" : "key missing";
      state.className = "np-pill " + (payload.key_present ? "np-pill-ok" : "np-pill-fail");
      var keyCopy = document.querySelector("[data-np-backup-key]");
      if (keyCopy) keyCopy.textContent = payload.key_present ? ("Present (fingerprint " + payload.key_fingerprint + ")") : "Not generated yet";
      var smtpWarning = document.querySelector("[data-np-backup-smtp-warning]");
      if (smtpWarning) smtpWarning.hidden = !!payload.smtp_configured;
      var destinations = payload.destinations || [];
      var countCopy = document.querySelector("[data-np-backup-destination-count]");
      if (countCopy) countCopy.textContent = String(destinations.length);
      var destRows = document.querySelector("[data-np-backup-destinations]");
      if (destRows) {
        destRows.replaceChildren();
        if (!destinations.length) {
          replaceTableWithMessage(destRows, 6, "No destinations configured yet.");
        }
        destinations.forEach(function (dest) {
          var row = document.createElement("tr");
          [dest.name, dest.kind, dest.schedule_cron,
            dest.retention_count + " / " + dest.retention_days + "d",
            dest.last_succeeded_at ? new Date(dest.last_succeeded_at).toLocaleString() : (dest.last_error || "never")
          ].forEach(function (value) {
            var cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
          });
          var actions = document.createElement("td");
          var runButton = document.createElement("button");
          runButton.type = "button";
          runButton.className = "np-secondary-button";
          runButton.textContent = "Run now";
          runButton.addEventListener("click", function () { backupAction("/tools-settings/backups/run", {destination: dest.name}, "Backup queued."); });
          var testButton = document.createElement("button");
          testButton.type = "button";
          testButton.className = "np-secondary-button";
          testButton.textContent = "Test";
          testButton.addEventListener("click", function () { backupAction("/tools-settings/backups/destinations/test", {name: dest.name}, "Destination test passed."); });
          actions.appendChild(runButton);
          actions.appendChild(testButton);
          row.appendChild(actions);
          destRows.appendChild(row);
        });
      }
      var backups = payload.backups || [];
      var latestCopy = document.querySelector("[data-np-backup-latest]");
      if (latestCopy) latestCopy.textContent = backups.length ? (backups[0].status + " · " + (backups[0].archive_name || "pending") + " · " + new Date(backups[0].created_at).toLocaleString()) : "No archives yet";
      var rows = document.querySelector("[data-np-backup-rows]");
      if (rows) {
        rows.replaceChildren();
        if (!backups.length) {
          replaceTableWithMessage(rows, 6, "No server backups recorded yet.");
        }
        backups.forEach(function (item) {
          var row = document.createElement("tr");
          [String(item.id), item.destination_name || "-", item.status, item.archive_name || "-",
            item.size_bytes ? (Math.round(item.size_bytes / 1048576) + " MiB") : "-",
            item.verified_at ? "yes" : "no"
          ].forEach(function (value) {
            var cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
          });
          rows.appendChild(row);
        });
      }
    }).catch(function (err) {
      state.textContent = "unavailable";
      state.className = "np-pill np-pill-fail";
      var error = document.querySelector("[data-np-backup-error]");
      if (error) { error.textContent = err && err.message ? err.message : "Server backups are unavailable."; error.hidden = false; }
    });
  }

  function backupAction(url, body, successMessage) {
    var error = document.querySelector("[data-np-backup-error]");
    fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Nakpanel-CSRF": csrfToken()
      },
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (response.status === 428) throw new Error("Recent authentication is required: confirm your password under Tools & Settings first.");
        if (!response.ok || !payload.ok) throw new Error(payload.error || "The backup action failed.");
        return payload;
      });
    }).then(function (payload) {
      if (payload.key) {
        var output = document.querySelector("[data-np-backup-key-output]");
        if (output) {
          output.textContent = (payload.notice || "") + "\n\n" + payload.key;
          output.hidden = false;
        }
      }
      if (error) { error.textContent = successMessage || "Done."; error.hidden = false; }
      loadServerBackups();
    }).catch(function (err) {
      if (error) { error.textContent = err && err.message ? err.message : "The backup action failed."; error.hidden = false; }
    });
  }

  function bindBackupControls() {
    var keyButton = document.querySelector("[data-np-backup-key-init]");
    if (keyButton) {
      keyButton.addEventListener("click", function () {
        backupAction("/tools-settings/backups/key/init", {}, "Archive key generated - copy it now.");
      });
    }
  }

  function replaceTableWithMessage(target, columns, message) {
    if (!target) return;
    target.replaceChildren();
    var row = document.createElement("tr");
    var cell = document.createElement("td");
    cell.colSpan = columns;
    cell.textContent = message;
    row.appendChild(cell);
    target.appendChild(row);
  }

  function loadMailQueue(form) {
    var target = document.querySelector("[data-np-mail-queue-rows]");
    if (!target || !window.fetch) return;
    form = form || document.querySelector("[data-np-mail-queue-filter]");
    var status = document.querySelector("[data-np-mail-queue-state]");
    var params = form ? new URLSearchParams(new FormData(form)) : new URLSearchParams("limit=50");
    replaceTableWithMessage(target, 6, "Loading queue metadata...");
    fetch("/tools-settings/mail/queue?" + params.toString(), {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok || !payload.queue) throw new Error(payload.error || "Mail queue is unavailable");
        return payload.queue;
      });
    }).then(function (queue) {
      target.replaceChildren();
      (queue.messages || []).forEach(function (message) {
        var recipients = 0;
        (message.domains || []).forEach(function (domain) { recipients += (domain.recipients || []).length; });
        var row = document.createElement("tr");
        [
          message.id || "Unknown",
          message.return_path || "Envelope sender unavailable",
          message.state || "unknown",
          String(recipients),
          message.created_at ? new Date(message.created_at).toLocaleString() : "Unknown",
          String(message.size_bytes || 0) + " B"
        ].forEach(function (value, index) {
          var cell = document.createElement("td");
          cell.dataset.label = ["ID", "Sender", "State", "Recipients", "Created", "Size"][index];
          cell.textContent = value;
          row.appendChild(cell);
        });
        target.appendChild(row);
      });
      if (!target.children.length) replaceTableWithMessage(target, 6, "No queued messages matched this filter.");
      if (status) {
        status.hidden = false;
        status.textContent = String(queue.total || 0) + " queued messages reported" + (queue.truncated ? " (result capped)" : "") + ".";
      }
    }).catch(function (error) {
      replaceTableWithMessage(target, 6, "Mail queue metadata could not be loaded.");
      if (status) { status.hidden = false; status.textContent = error.message; }
    });
  }

  function loadMailLogs(form) {
    var target = document.querySelector("[data-np-mail-log-rows]");
    if (!target || !window.fetch) return;
    form = form || document.querySelector("[data-np-mail-log-filter]");
    var params = form ? new URLSearchParams(new FormData(form)) : new URLSearchParams("since_minutes=60&limit=100");
    replaceTableWithMessage(target, 3, "Loading bounded mail logs...");
    fetch("/tools-settings/mail/logs?" + params.toString(), {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok || !payload.logs) throw new Error(payload.error || "Mail logs are unavailable");
        return payload.logs;
      });
    }).then(function (logs) {
      target.replaceChildren();
      (logs.entries || []).forEach(function (entry) {
        var row = document.createElement("tr");
        [
          entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "Unknown",
          String(entry.priority),
          entry.message || ""
        ].forEach(function (value, index) {
          var cell = document.createElement("td");
          cell.dataset.label = ["Time", "Priority", "Message"][index];
          cell.textContent = value;
          row.appendChild(cell);
        });
        target.appendChild(row);
      });
      if (!target.children.length) replaceTableWithMessage(target, 3, "No mail log entries matched this window.");
    }).catch(function () {
      replaceTableWithMessage(target, 3, "Mail logs could not be loaded.");
    });
  }

  function databaseActionForm(action, databaseID, label) {
    var form = document.createElement("form");
    form.method = "post";
    form.action = "/tools-settings/databases/" + databaseID + "/" + action;
    form.setAttribute("data-np-database-form", "");
    if (action === "role") {
      var role = document.createElement("select");
      role.name = "role";
      [["read-only", "Read only"], ["read-write", "Read/write"], ["schema-manager", "Schema manager"]].forEach(function (option) {
        var item = document.createElement("option");
        item.value = option[0];
        item.textContent = option[1];
        role.appendChild(item);
      });
      role.setAttribute("aria-label", "Database role");
      form.appendChild(role);
    }
    if (action === "password") {
      var password = document.createElement("input");
      password.type = "password";
      password.name = "password";
      password.required = true;
      password.autocomplete = "new-password";
      password.placeholder = "New password";
      password.setAttribute("aria-label", "New database password");
      form.appendChild(password);
    }
    var button = document.createElement("button");
    button.type = "submit";
    button.className = "np-secondary-button";
    button.textContent = label;
    if (action !== "check") button.setAttribute("data-np-confirm", label + " for this tracked principal?");
    form.appendChild(button);
    return form;
  }

  function loadDatabaseAdmin() {
    var target = document.querySelector("[data-np-database-rows]");
    if (!target || !window.fetch) return;
    var state = document.querySelector("[data-np-database-state]");
    var summary = document.querySelector("[data-np-database-summary]");
    fetch("/tools-settings/databases/status", {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok || !payload.database_admin) throw new Error(payload.error || "Database administration is unavailable");
        return payload.database_admin;
      });
    }).then(function (snapshot) {
      var server = snapshot.server || {};
      if (state) {
        state.textContent = server.available ? "available" : "unavailable";
        state.className = "np-pill " + (server.available ? "np-pill-ok" : "np-pill-fail");
      }
      if (summary) summary.textContent = (server.engine || "MariaDB") + " " + (server.version || "") + " · " + String(server.connections || 0) + " connections · " + String(server.threads || 0) + " threads.";
      target.replaceChildren();
      (snapshot.databases || []).forEach(function (database) {
        var row = document.createElement("tr");
        [
          database.name || "Unknown",
          database.principal || "Unknown",
          database.status || "unknown",
          database.database_exists && database.principal_exists ? "Database and principal present" : (database.inspection_error || "Drift detected")
        ].forEach(function (value, index) {
          var cell = document.createElement("td");
          cell.dataset.label = ["Database", "Principal", "Tracked state", "Live state"][index];
          cell.textContent = value;
          row.appendChild(cell);
        });
        var actions = document.createElement("td");
        actions.dataset.label = "Actions";
        var actionList = document.createElement("div");
        actionList.className = "np-settings-db-actions";
        actionList.append(
          databaseActionForm("check", database.id, "Check"),
          databaseActionForm("role", database.id, "Set role"),
          databaseActionForm("password", database.id, "Rotate password")
        );
        actions.appendChild(actionList);
        row.appendChild(actions);
        target.appendChild(row);
      });
      if (!target.children.length) replaceTableWithMessage(target, 5, "No MariaDB databases are tracked.");
      prepareForms();
    }).catch(function (error) {
      if (state) { state.textContent = "unavailable"; state.className = "np-pill np-pill-fail"; }
      if (summary) summary.textContent = error.message;
      replaceTableWithMessage(target, 5, "Database administration could not be loaded.");
    });
  }

  function loadApplicationCatalog() {
    var target = document.querySelector("[data-np-application-rows]");
    if (!target || !window.fetch) return;
    var state = document.querySelector("[data-np-application-state]");
    fetch("/tools-settings/operations/application-catalog", {
      credentials: "same-origin",
      headers: {"Accept": "application/json"}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Application catalog is unavailable");
        return payload.catalog || [];
      });
    }).then(function (catalog) {
      target.replaceChildren();
      catalog.forEach(function (item) {
        var row = document.createElement("tr");
        [
          item.slug || "custom",
          item.runtime || "unknown",
          String(item.instances || 0),
          String(item.running || 0),
          String(item.stopped || 0),
          String(item.failed || 0) + " / " + String(item.pending_convergence || 0),
          item.last_changed_at ? new Date(item.last_changed_at).toLocaleString() : "No changes recorded"
        ].forEach(function (value, index) {
          var cell = document.createElement("td");
          cell.dataset.label = ["Catalog", "Runtime", "Instances", "Running", "Stopped", "Failed / Pending", "Last change"][index];
          cell.textContent = value;
          row.appendChild(cell);
        });
        target.appendChild(row);
      });
      if (!target.children.length) replaceTableWithMessage(target, 7, "No application catalog instances are tracked.");
      if (state) { state.textContent = "current"; state.className = "np-pill np-pill-ok"; }
    }).catch(function () {
      replaceTableWithMessage(target, 7, "Application catalog inventory could not be loaded.");
      if (state) { state.textContent = "unavailable"; state.className = "np-pill np-pill-fail"; }
    });
  }

  function submitPhase26Form(form, statusSelector, submitter) {
    var status = document.querySelector(statusSelector);
    var data = new FormData(form);
    setFormBusy(form, true);
    if (status) { status.hidden = false; status.setAttribute("role", "status"); status.textContent = "Submitting guarded operation..."; }
    fetch(form.action, {
      method: "POST",
      body: data,
      credentials: "same-origin",
      headers: {"Accept": "application/json", "X-Nakpanel-CSRF": csrfToken()}
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Operation failed");
        return payload;
      });
    }).then(function (payload) {
      var operationID = payload.operation_id || (payload.result && payload.result.operation_id);
      if (status) status.textContent = operationID ? ("Queued as " + operationID + ".") : "Operation completed.";
      if (operationID) {
        pollServerOperation(operationID, status, form.matches("[data-np-database-form]") ? loadDatabaseAdmin : (form.matches("[data-np-update-install-form]") ? function () { loadServerUpdates(false); } : null));
      } else if (form.matches("[data-np-database-form]")) {
        window.setTimeout(loadDatabaseAdmin, 500);
      }
      if (form.matches("[data-np-power-form]")) closeDialog(form.closest("dialog"));
    }).catch(function (error) {
      if (status) {
        status.setAttribute("role", "alert");
        status.textContent = error.message;
      }
    }).then(function () {
      clearSensitiveInputs(form);
      setFormBusy(form, false);
      updateInstallSelection();
    });
  }

  function submitSite(form) {
    var submit = form.querySelector("[data-np-create-submit]");
    var gate = form.querySelector("[data-np-customer-gate]");
    if (submit) submit.disabled = true;
    fetch(form.action, {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { "X-Nakpanel-SPA": "true", "X-Nakpanel-CSRF": csrfToken() }
    }).then(function (response) {
      return response.json().then(function (data) { if (!response.ok || !data.ok) throw new Error(data.error || "Request failed"); return data; });
    }).then(function (data) {
      window.location.assign(data.redirect || "/sites");
    }).catch(function (error) {
      if (gate) { gate.textContent = error.message; gate.classList.add("is-blocked"); }
      if (submit) submit.disabled = false;
    });
  }

  function selectPlanTab(tab, updateURL) {
    if (!tab) return;
    each("[data-np-plan-tab]", document, function (link) {
      var active = link.getAttribute("data-np-plan-tab") === tab;
      link.classList.toggle("is-active", active);
      link.setAttribute("aria-current", active ? "page" : "false");
    });
    each("[data-np-plan-panel]", document, function (panel) {
      panel.hidden = panel.getAttribute("data-np-plan-panel") !== tab;
    });
    if (updateURL && window.history && window.history.replaceState) {
      var url = new URL(window.location.href);
      url.searchParams.set("tab", tab);
      window.history.replaceState({}, "", url.pathname + url.search);
    }
  }

  function updateUnlimited(input) {
    var field = input && input.closest(".np-limit-field");
    var number = field && field.querySelector('input[type="number"]');
    if (!number) return;
    number.disabled = input.checked;
    number.setAttribute("aria-disabled", input.checked ? "true" : "false");
    var unit = field.querySelector("select");
    if (unit) unit.disabled = input.checked;
  }

  function populatePlanPreview(preview) {
    var mapping = {
      "[data-np-preview-synced]": preview.synced_subscriptions,
      "[data-np-preview-locked]": preview.locked_subscriptions,
      "[data-np-preview-custom]": preview.custom_subscriptions,
      "[data-np-preview-disk]": preview.committed_disk_mb < 0 ? "Unlimited" : preview.committed_disk_mb + " MB"
    };
    Object.keys(mapping).forEach(function (selector) {
      var target = document.querySelector(selector);
      if (target) target.textContent = mapping[selector];
    });
    var resellerRow = document.querySelector("[data-np-preview-reseller-row]");
    var resellerValue = document.querySelector("[data-np-preview-reseller]");
    if (resellerRow && resellerValue) {
      var hasResellerAllocation = preview.has_reseller_capacity === true;
      resellerRow.hidden = !hasResellerAllocation;
      if (hasResellerAllocation) {
        resellerValue.textContent = (preview.reseller_committed_disk_mb < 0 ? "Unlimited" : preview.reseller_committed_disk_mb + " MB") + " / " + (preview.reseller_capacity_mb < 0 ? "Unlimited" : preview.reseller_capacity_mb + " MB");
      }
    }
    var warning = document.querySelector("[data-np-preview-warning]");
    if (warning) {
      warning.textContent = preview.warning || "Capacity checks passed.";
      warning.classList.toggle("is-blocked", !preview.allowed);
    }
    var confirm = document.querySelector("[data-np-plan-confirm-submit]");
    if (confirm) confirm.disabled = !preview.allowed;
  }

  function reviewPlan(form) {
    pendingPlanForm = form;
    var submit = form.querySelector("[data-np-plan-submit]");
    if (submit) submit.disabled = true;
    fetch("/plans/preview", {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { "X-Nakpanel-SPA": "true", "X-Nakpanel-CSRF": csrfToken() }
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data.ok) throw new Error(data.error || "Plan preview failed");
        return data.preview;
      });
    }).then(function (preview) {
      populatePlanPreview(preview);
      openDialog("plan-preview-dialog", submit);
    }).catch(function (error) {
      var warning = document.querySelector("[data-np-preview-warning]");
      if (warning) { warning.textContent = error.message; warning.classList.add("is-blocked"); }
      var confirm = document.querySelector("[data-np-plan-confirm-submit]");
      if (confirm) confirm.disabled = true;
      openDialog("plan-preview-dialog", submit);
    }).finally(function () {
      if (submit) submit.disabled = false;
    });
  }

  function selectedFilePaths(manager) {
    return Array.prototype.map.call(manager.querySelectorAll("[data-np-file-select]:checked"), function (input) { return input.value; });
  }

  function updateFileSelection(manager) {
    if (!manager) return;
    var selected = selectedFilePaths(manager);
    each("[data-np-file-dialog-open]", manager, function (button) { button.disabled = selected.length === 0; });
    var all = manager.querySelector("[data-np-file-select-all]");
    var items = manager.querySelectorAll("[data-np-file-select]");
    if (all) {
      all.checked = items.length > 0 && selected.length === items.length;
      all.indeterminate = selected.length > 0 && selected.length < items.length;
    }
  }

  function populateFileSelection(dialog, paths) {
    var container = dialog && dialog.querySelector("[data-np-file-selected-inputs]");
    if (!container) return;
    container.innerHTML = "";
    paths.forEach(function (value) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = "paths";
      input.value = value;
      container.appendChild(input);
    });
  }

  function openFileRowDialog(trigger) {
    var action = trigger.getAttribute("data-np-file-row-action");
    var dialog = document.getElementById("file-" + action + "-dialog");
    if (!dialog) return;
    var pathInput = dialog.querySelector("[data-np-row-path]");
    if (pathInput) pathInput.value = trigger.getAttribute("data-path") || "";
    var nameInput = dialog.querySelector("[data-np-row-name]");
    if (nameInput) nameInput.value = trigger.getAttribute("data-name") || "";
    var modeInput = dialog.querySelector("[data-np-row-mode]");
    if (modeInput) modeInput.value = trigger.getAttribute("data-mode") || "0644";
    openDialog(dialog.id, trigger);
  }

  function uploadFiles(manager, input) {
    if (!input.files || !input.files.length) return;
    var entries = Array.prototype.map.call(input.files, function (file) {
      return {file: file, relative: file.webkitRelativePath || file.name};
    });
    uploadFileQueue(manager, entries, input);
  }

  function uploadFileQueue(manager, entries, input) {
    var form = manager && manager.querySelector("[data-np-file-upload-form]");
    if (!form || !entries.length || manager.dataset.npUploading === "true") return;
    manager.dataset.npUploading = "true";
    var progress = manager.querySelector("[data-np-file-upload-progress]");
    var bar = progress && progress.querySelector("[data-np-file-upload-bar]");
    var label = manager.querySelector("[data-np-file-upload-label]");
    var items = manager.querySelector("[data-np-file-upload-items]");
    var rows = [];
    var redirect = "";
    if (items) items.textContent = "";
    entries.forEach(function (entry) {
      var row = document.createElement("div");
      row.className = "np-file-upload-item";
      var name = document.createElement("span");
      var status = document.createElement("span");
      name.textContent = entry.relative;
      status.textContent = "Waiting";
      row.appendChild(name);
      row.appendChild(status);
      if (items) items.appendChild(row);
      rows.push(status);
    });
    if (progress) progress.hidden = false;

    function finish(error) {
      manager.dataset.npUploading = "false";
      if (input) input.value = "";
      if (error) {
        if (label) label.textContent = "Upload stopped";
        window.alert(error);
        return;
      }
      if (label) label.textContent = entries.length + " of " + entries.length;
      if (bar) bar.style.width = "100%";
      if (redirect) window.location.assign(redirect);
      else window.location.reload();
    }

    function send(index, overwrite) {
      if (index >= entries.length) {
        finish("");
        return;
      }
      var entry = entries[index];
      var data = new FormData();
      data.append("file:" + encodeURIComponent(entry.relative), entry.file, entry.file.name);
      var xhr = new XMLHttpRequest();
      var separator = form.action.indexOf("?") === -1 ? "?" : "&";
      xhr.open("POST", form.action + separator + "overwrite=" + (overwrite ? "true" : "false"));
      var token = document.querySelector('meta[name="nakpanel-csrf"]');
      if (token) xhr.setRequestHeader("X-Nakpanel-CSRF", token.content);
      rows[index].textContent = "Starting";
      if (label) label.textContent = (index + 1) + " of " + entries.length;
      xhr.upload.onprogress = function (event) {
        if (!event.lengthComputable) return;
        var filePercent = Math.round((event.loaded / event.total) * 100);
        var totalPercent = Math.round(((index + event.loaded / event.total) / entries.length) * 100);
        rows[index].textContent = filePercent + "%";
        if (bar) bar.style.width = totalPercent + "%";
      };
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          rows[index].textContent = "Done";
          try { redirect = JSON.parse(xhr.responseText).redirect || redirect; } catch (_) {}
          send(index + 1, false);
          return;
        }
        if (xhr.status === 409 && !overwrite) {
          askConfirmation(entry.relative + " already exists. Replace it?", input).then(function (confirmed) {
            if (confirmed) send(index, true);
            else {
              rows[index].textContent = "Skipped";
              send(index + 1, false);
            }
          });
          return;
        }
        rows[index].textContent = "Failed";
        finish((xhr.responseText || "Upload failed").trim());
      };
      xhr.onerror = function () {
        rows[index].textContent = "Failed";
        finish("Upload failed. Check the server connection and try again.");
      };
      xhr.send(data);
    }

    send(0, false);
  }

  function initializeCodeEditor() {
    var textarea = document.querySelector("[data-np-code-editor]");
    var form = textarea && textarea.closest("[data-np-editor-form]");
    if (!textarea || !form) return;
    form.setAttribute("data-np-dirty-guard", "");
    form.dataset.npDirty = "false";
    if (!window.ace) {
      textarea.addEventListener("input", function () { form.dataset.npDirty = "true"; });
      form.addEventListener("submit", function () { form.dataset.npDirty = "false"; });
      return;
    }
    var host = document.createElement("div");
    host.className = "np-ace-editor";
    textarea.hidden = true;
    textarea.parentNode.insertBefore(host, textarea);
    window.ace.config.set("basePath", "/assets/ace");
    var editor = window.ace.edit(host);
    editor.setValue(textarea.value, -1);
    editor.setOptions({fontSize: "14px", showPrintMargin: false, useWorker: false, tabSize: 2});
    var extension = (textarea.closest("form").querySelector('input[name="path"]').value.split(".").pop() || "text").toLowerCase();
    var modes = {php:"php", js:"javascript", json:"json", css:"css", html:"html", htm:"html", xml:"xml", sh:"sh", sql:"sql", yml:"yaml", yaml:"yaml"};
    editor.session.setMode("ace/mode/" + (modes[extension] || "text"));
    editor.session.on("change", function () { form.dataset.npDirty = "true"; });
    form.addEventListener("submit", function () { textarea.value = editor.getValue(); form.dataset.npDirty = "false"; });
  }

  function buildHostingPolicyPatch(form) {
    function number(name) {
      var input = form.elements[name];
      var value = input ? parseInt(input.value, 10) : 0;
      return isNaN(value) ? 0 : value;
    }
    function checked(name) {
      var input = form.elements[name];
      return !!(input && input.checked);
    }
    var registries = (form.elements.policy_registries.value || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean);
    var sftp = checked("policy_sftp");
    var mail = checked("policy_mail");
    var patch = {
      resources: {
        cpu_percent: number("policy_cpu_percent"), memory_mb: number("policy_memory_mb"),
        io_read_mbps: number("policy_io_read_mbps"), io_write_mbps: number("policy_io_write_mbps"),
        max_tasks: number("policy_max_tasks"), max_scheduled_tasks: number("policy_max_scheduled_tasks"),
        max_applications: number("policy_max_applications"), container_storage_mb: number("policy_container_storage_mb")
      },
      permissions: {
        sftp: sftp, scheduled_tasks: checked("policy_scheduled_tasks"), mail: mail,
        applications: checked("policy_applications"), custom_oci_images: checked("policy_custom_images")
      },
      access: {shell_mode: sftp ? "sftp" : "disabled", sftp_only: true},
      mail: {enabled: mail},
      applications: {allowed_registries: registries, rootless: true, allowed_runtimes: ["oci"]}
    };
    form.querySelector("[data-np-policy-patch]").value = JSON.stringify(patch);
  }

  function buildSitePolicyPatch(form) {
    function number(name) {
      var input = form.elements[name];
      var value = input ? parseInt(input.value, 10) : 0;
      return isNaN(value) ? 0 : value;
    }
    function checked(name) {
      var input = form.elements[name];
      return !!(input && input.checked);
    }
    function value(name) {
      var input = form.elements[name];
      return input ? input.value.trim() : "";
    }
    function csv(name) {
      return value(name).split(",").map(function (item) { return item.trim(); }).filter(Boolean);
    }
    var patch = {};
    if (form.elements.site_cgi) patch.permissions = {cgi: checked("site_cgi")};
    if (form.elements.site_request_rate || form.elements.site_preferred_domain) {
      patch.web = {
        preferred_domain: value("site_preferred_domain"), index_files: value("site_index_files"),
        request_body_limit_mb: number("site_body_limit"), compression: checked("site_compression"),
        cache_ttl_seconds: number("site_cache_ttl"), request_rate_per_second: number("site_request_rate"),
        request_burst: number("site_request_burst"), max_connections: number("site_max_connections"),
        connect_timeout_seconds: number("site_connect_timeout"), read_timeout_seconds: number("site_read_timeout"),
        security_header_preset: value("site_security_headers"), allowed_cidrs: csv("site_allowed_cidrs"),
        error_document_404: value("site_error_document_404"), error_document_50x: value("site_error_document_50x"),
        static_cache: checked("site_static_cache"),
        fastcgi_microcache: checked("site_fastcgi_microcache")
      };
    }
    if (form.elements.site_fpm_children || form.elements.site_php_memory) {
      patch.php = {
        fpm_mode: value("site_fpm_mode"), fpm_max_children: number("site_fpm_children"),
        fpm_max_requests: number("site_fpm_requests"), fpm_idle_timeout_seconds: number("site_fpm_idle"),
        request_terminate_timeout_seconds: number("site_fpm_terminate"), memory_limit_mb: number("site_php_memory"),
        max_execution_seconds: number("site_php_execution"), max_input_seconds: number("site_php_input"),
        post_max_mb: number("site_php_post"), upload_max_mb: number("site_php_upload"),
        log_errors: checked("site_php_log_errors"), display_errors: checked("site_php_display_errors"),
        allow_url_fopen: checked("site_php_url_fopen"), opcache_enabled: checked("site_php_opcache"),
        opcache_memory_mb: number("site_php_opcache_memory"),
        exec_enabled: checked("site_php_exec")
      };
    }
    form.querySelector("[data-np-policy-patch]").value = JSON.stringify(patch);
  }

  function initSiteLogs() {
    each("[data-np-site-logs]", document, function (workspace) {
      var form = workspace.querySelector("[data-np-site-log-filter]");
      var output = workspace.querySelector("[data-np-site-log-output]");
      var more = workspace.querySelector("[data-np-site-log-more]");
      var download = workspace.querySelector("[data-np-site-log-download]");
      var cursor = 0;
      function load(reset) {
        if (reset) cursor = 0;
        var params = new URLSearchParams(new FormData(form));
        params.set("cursor", String(cursor));
        params.set("limit", "250");
        params.set("bytes", String(512 * 1024));
        output.textContent = "Loading…";
        fetch("/sites/" + workspace.dataset.siteId + "/logs/data?" + params.toString(), {headers: {"Accept": "application/json"}})
          .then(function (response) { if (!response.ok) throw new Error("Log source is unavailable"); return response.json(); })
          .then(function (result) {
            output.textContent = (result.lines || []).join("\n") || "No matching log entries.";
            cursor = result.next_cursor || 0;
            more.hidden = !result.truncated;
            params.delete("cursor");
            download.href = "/sites/" + workspace.dataset.siteId + "/logs/data?" + params.toString() + "&download=1";
          })
          .catch(function (error) { output.textContent = error.message; more.hidden = true; });
      }
      form.addEventListener("submit", function (event) { event.preventDefault(); load(true); });
      more.addEventListener("click", function () { load(false); });
      load(true);
    });
  }

  function initContainerLogs() {
    each("[data-np-container-logs]", document, function (workspace) {
      var output = workspace.querySelector("[data-np-container-log-output]");
      var refresh = workspace.querySelector("[data-np-container-log-refresh]");
      var truncated = workspace.querySelector("[data-np-container-log-truncated]");
      function load() {
        refresh.disabled = true;
        output.textContent = "Loading container logs…";
        fetch(workspace.dataset.logUrl + "?lines=200&bytes=" + (256 * 1024), {
          headers: {"Accept": "application/json"}
        })
          .then(function (response) {
            if (!response.ok) throw new Error("Container logs are unavailable");
            return response.json();
          })
          .then(function (result) {
            output.textContent = (result.lines || []).join("\n") || "No container output.";
            truncated.hidden = !result.truncated;
          })
          .catch(function (error) {
            output.textContent = error.message;
            truncated.hidden = true;
          })
          .then(function () { refresh.disabled = false; });
      }
      refresh.addEventListener("click", load);
      load();
    });
  }

  function initContainerDeployForms() {
    each("[data-np-container-deploy]", document, function (form) {
      var catalog = form.querySelector("[data-np-container-catalog]");
      var customImageField = form.querySelector("[data-np-custom-image-field]");
      var customImage = form.elements.image_ref;
      var route = form.querySelector("[data-np-container-route]");
      var routePrefixField = form.querySelector("[data-np-route-prefix-field]");
      var routePrefix = form.elements.route_prefix;
      var health = form.querySelector("[data-np-container-health]");
      var healthPathField = form.querySelector("[data-np-health-path-field]");
      var healthPath = form.elements.health_path;
      function sync() {
        var custom = !catalog || catalog.value === "";
        if (customImageField) customImageField.hidden = !custom;
        if (customImage) {
          customImage.disabled = !custom;
          customImage.required = custom;
        }
        var prefixRoute = !route || route.value === "prefix";
        if (routePrefixField) routePrefixField.hidden = !prefixRoute;
        if (routePrefix) {
          routePrefix.disabled = !prefixRoute;
          routePrefix.required = prefixRoute;
        }
        var httpHealth = !health || health.value === "http";
        if (healthPathField) healthPathField.hidden = !httpHealth;
        if (healthPath) {
          healthPath.disabled = !httpHealth;
          healthPath.required = httpHealth;
        }
      }
      [catalog, route, health].forEach(function (control) {
        if (control) control.addEventListener("change", sync);
      });
      each("[data-np-json-object]", form, function (field) {
        function validateJSON() {
          field.setCustomValidity("");
          if (!field.value.trim()) return;
          try {
            var value = JSON.parse(field.value);
            if (!value || Array.isArray(value) || typeof value !== "object" ||
                Object.keys(value).some(function (key) { return typeof value[key] !== "string"; })) {
              field.setCustomValidity("Use a JSON object with string values.");
            }
          } catch (_) {
            field.setCustomValidity("Enter valid JSON.");
          }
        }
        field.addEventListener("input", validateJSON);
        field.addEventListener("blur", validateJSON);
      });
      sync();
    });
  }

  document.addEventListener("click", function (event) {
    var disabledBulkSummary = event.target.closest('[data-np-bulk-menu][data-enabled="false"] > summary');
    if (disabledBulkSummary) {
      event.preventDefault();
      return;
    }
    var dnsMenuSummary = event.target.closest(".np-dns-action-menu > summary");
    each(".np-dns-action-menu[open]", document, function (menu) {
      if (!dnsMenuSummary || dnsMenuSummary.parentElement !== menu) menu.open = false;
    });
    var legacy = event.target.closest("[data-np-view]");
    if (legacy && !legacy.disabled) setLegacyView(legacy.getAttribute("data-np-view"));
    var opener = event.target.closest("[data-np-dialog-open]");
    if (opener) {
      openDialog(opener.getAttribute("data-np-dialog-open"), opener);
      var openerMenu = opener.closest(".np-dns-action-menu");
      if (openerMenu) openerMenu.open = false;
    }
    var advancedDNSLink = event.target.closest('a[href="#dns-zone-advanced"]');
    if (advancedDNSLink) {
      var advancedDNS = document.getElementById("dns-zone-advanced");
      if (advancedDNS) advancedDNS.open = true;
    }
    var closer = event.target.closest("[data-np-dialog-close]");
    if (closer) closeDialog(closer.closest("dialog"));
    if (event.target.closest("[data-np-menu]")) setMenu(true);
    if (event.target.closest("[data-np-menu-close]")) setMenu(false);
    if (event.target.matches("dialog[open]")) closeDialog(event.target);
    var confirmButton = event.target.closest("[data-np-confirm]");
    if (confirmButton && confirmButton.dataset.npConfirmBypass !== "true") {
      event.preventDefault();
      askConfirmation(confirmButton.getAttribute("data-np-confirm"), confirmButton).then(function (confirmed) {
        if (!confirmed) return;
        confirmButton.dataset.npConfirmBypass = "true";
        confirmButton.click();
        delete confirmButton.dataset.npConfirmBypass;
      });
    }
    if (event.target.closest("[data-np-confirmation-accept]")) {
      event.preventDefault();
      resolveConfirmation(true);
    }
    if (event.target.closest("[data-np-confirmation-cancel]")) {
      event.preventDefault();
      resolveConfirmation(false);
    }
    if (event.target.closest("[data-np-update-dry-run]")) {
      event.preventDefault();
      loadServerUpdates(true);
    }
    var powerAction = event.target.closest("[data-np-power-action]");
    if (powerAction) {
      event.preventDefault();
      var action = powerAction.getAttribute("data-np-power-action");
      if (action === "shutdown" && !serverInventoryHostname) {
        var powerStatus = document.querySelector("[data-np-power-operation]");
        if (powerStatus) {
          powerStatus.hidden = false;
          powerStatus.textContent = "Current hostname inventory is required before shutdown can be confirmed.";
        }
        return;
      }
      var dialog = document.getElementById("host-power-dialog");
      var form = dialog && dialog.querySelector("[data-np-power-form]");
      if (form) {
        form.querySelector('input[name="action"]').value = action;
        var title = form.querySelector("[data-np-power-title]");
        var copy = form.querySelector("[data-np-power-copy]");
        var confirmation = form.querySelector("[data-np-power-confirmation]");
        var oob = form.querySelector("[data-np-power-oob]");
        var expected = action === "shutdown" ? (serverInventoryHostname || "current hostname") : "REBOOT";
        if (title) title.textContent = action === "shutdown" ? "Shut down host" : "Reboot host";
        if (copy) copy.textContent = "Type " + expected + " after reauthenticating. The operation is queued and audit logged.";
        if (confirmation) { confirmation.value = ""; confirmation.placeholder = expected; }
        if (oob) oob.hidden = action !== "shutdown";
        var oobInput = oob && oob.querySelector("input");
        if (oobInput) { oobInput.checked = false; oobInput.required = action === "shutdown"; }
        openDialog("host-power-dialog", powerAction);
      }
    }
    var generator = event.target.closest("[data-np-generate-password]");
    if (generator) {
      var generatedInput = passwordInput(generator);
      if (generatedInput && window.crypto && window.crypto.getRandomValues) {
        generatedInput.value = securePassword(24);
        generatedInput.type = "text";
        generatedInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
    var copier = event.target.closest("[data-np-copy-password]");
    if (copier) {
      var copyInput = passwordInput(copier);
      if (copyInput && copyInput.value && navigator.clipboard) {
        navigator.clipboard.writeText(copyInput.value).then(function () {
          copier.setAttribute("title", "Copied");
          window.setTimeout(function () { copier.setAttribute("title", "Copy password"); }, 1500);
        });
      }
    }
    var planTab = event.target.closest("[data-np-plan-tab]");
    if (planTab) {
      event.preventDefault();
      selectPlanTab(planTab.getAttribute("data-np-plan-tab"), true);
    }
    var manager = event.target.closest("[data-np-file-manager]");
    var uploadTrigger = event.target.closest("[data-np-file-upload-trigger]");
    if (manager && uploadTrigger) {
      var fileInput = manager.querySelector('[data-np-file-input="' + uploadTrigger.getAttribute("data-np-file-upload-trigger") + '"]');
      if (fileInput) fileInput.click();
    }
    var fileDialogTrigger = event.target.closest("[data-np-file-dialog-open]");
    if (manager && fileDialogTrigger) {
      var paths = selectedFilePaths(manager);
      if (paths.length) {
        var fileDialog = document.getElementById(fileDialogTrigger.getAttribute("data-np-file-dialog-open"));
        populateFileSelection(fileDialog, paths);
        openDialog(fileDialog.id, fileDialogTrigger);
      }
    }
    var rowAction = event.target.closest("[data-np-file-row-action]");
    if (rowAction) openFileRowDialog(rowAction);
    if (event.target.closest("[data-np-file-tree-open]")) document.body.classList.add("np-file-tree-open");
    if (event.target.closest("[data-np-file-tree-close]")) document.body.classList.remove("np-file-tree-open");
    if (event.target.closest("[data-np-plan-confirm-submit]") && pendingPlanForm) {
      planSubmitBypass = true;
      pendingPlanForm.dataset.npDirty = "false";
      closeDialog(document.getElementById("plan-preview-dialog"));
      pendingPlanForm.requestSubmit();
    }
  });

  document.addEventListener("change", function (event) {
    if (event.target.matches('[data-np-create-site-form] select[name="subscription_id"]')) updateCreateGate(event.target.closest("form"));
    if (event.target.matches('input[name="customer_mode"], [data-np-create-first-site], [data-np-onboarding-plan]')) updateOnboarding();
    if (event.target.matches("[data-np-subscription-nav]") && event.target.value) window.location.assign(event.target.value);
    if (event.target.matches("[data-np-bulk-all]")) {
      var bulkForm = event.target.closest("[data-np-bulk-form]");
      each("[data-np-bulk-check]", bulkForm, function (input) { input.checked = event.target.checked; });
      updateBulkForm(bulkForm);
    } else if (event.target.matches("[data-np-bulk-check]")) {
      updateBulkForm(event.target.closest("[data-np-bulk-form]"));
    }
	    if (event.target.matches("[data-np-unlimited]")) updateUnlimited(event.target);
	    if (event.target.matches('input[name="package_names"][form="np-update-install-form"], [data-np-update-install-form] input[name="security_only"]')) updateInstallSelection();
    if (event.target.matches("[data-np-update-filter]")) filterServerUpdates();
    if (event.target.matches("[data-np-update-select-all]")) {
      each('[data-np-update-packages] input[name="package_names"]:not(:disabled)', document, function (input) {
        if (!input.closest("tr").hidden) input.checked = event.target.checked;
      });
      updateInstallSelection();
    }
	if (event.target.matches("[data-np-file-select-all]")) {
	  var fileManager = event.target.closest("[data-np-file-manager]");
	  each("[data-np-file-select]", fileManager, function (input) { input.checked = event.target.checked; });
	  updateFileSelection(fileManager);
	} else if (event.target.matches("[data-np-file-select]")) {
	  updateFileSelection(event.target.closest("[data-np-file-manager]"));
	}
	if (event.target.matches("[data-np-file-input]")) uploadFiles(event.target.closest("[data-np-file-manager]"), event.target);
	var editor = event.target.closest("[data-np-plan-editor]");
	if (editor) editor.dataset.npDirty = "true";
  });

  document.addEventListener("input", function (event) {
    if (event.target.matches("[data-np-search-input]")) runSearch(event.target.value);
    if (event.target.matches("[data-np-settings-search]")) filterSettings(event.target.value);
    if (event.target.matches("[data-np-update-search]")) filterServerUpdates();
    if (event.target.matches("[data-np-subscription-filter]")) {
      var query = event.target.value.toLowerCase();
      each("[data-np-subscription-row]", document, function (row) { row.hidden = query && row.textContent.toLowerCase().indexOf(query) === -1; });
    }
    var editor = event.target.closest("[data-np-plan-editor]");
    if (editor) editor.dataset.npDirty = "true";
  });

  // Reusable list-report controller. Any panel marked [data-np-list] gets
  // filtering, sorting and paging over rows that are already in the document,
  // so a list of every hosted domain stays usable without a round trip.
  function listRows(list) {
    return Array.prototype.slice.call(list.querySelectorAll("[data-np-list-row]"));
  }

  function listMatches(row, query, filters) {
    for (var key in filters) {
      if (!filters[key]) continue;
      if ((row.dataset[key] || "") !== filters[key]) return false;
    }
    if (!query) return true;
    return row.textContent.toLowerCase().indexOf(query) !== -1;
  }

  function applyList(list) {
    var searchField = list.querySelector("[data-np-list-search]");
    var query = searchField ? searchField.value.trim().toLowerCase() : "";
    var filters = {};
    each("[data-np-list-filter]", list, function (select) {
      filters[select.getAttribute("data-np-list-filter")] = select.value;
    });

    var rows = listRows(list);
    var matched = [];
    rows.forEach(function (row) {
      if (listMatches(row, query, filters)) matched.push(row);
      else row.hidden = true;
    });

    var pageSize = parseInt(list.getAttribute("data-np-list-page-size"), 10) || 25;
    var shown = parseInt(list.dataset.npListShown, 10) || pageSize;
    if (shown < pageSize) shown = pageSize;
    matched.forEach(function (row, index) { row.hidden = index >= shown; });

    var visible = Math.min(shown, matched.length);
    var count = list.querySelector("[data-np-list-count]");
    if (count) {
      count.textContent = matched.length === rows.length
        ? rows.length + (rows.length === 1 ? " website" : " websites")
        : matched.length + " of " + rows.length + " match";
    }
    var status = list.querySelector("[data-np-list-status]");
    if (status) status.textContent = "Showing " + visible + " of " + matched.length;
    var foot = list.querySelector("[data-np-list-foot]");
    if (foot) foot.hidden = matched.length <= pageSize;
    var more = list.querySelector("[data-np-list-more]");
    if (more) more.hidden = visible >= matched.length;
    var empty = list.querySelector("[data-np-list-empty]");
    if (empty) empty.hidden = matched.length !== 0;
  }

  function sortList(list, columnIndex, button) {
    var body = list.querySelector("[data-np-list-body]");
    if (!body) return;
    var ascending = button.getAttribute("data-np-sorted") !== "asc";
    each("[data-np-list-sort]", list, function (other) {
      other.removeAttribute("data-np-sorted");
      var header = other.closest("th");
      if (header) header.removeAttribute("aria-sort");
    });
    button.setAttribute("data-np-sorted", ascending ? "asc" : "desc");
    var header = button.closest("th");
    if (header) header.setAttribute("aria-sort", ascending ? "ascending" : "descending");

    var rows = listRows(list);
    rows.sort(function (a, b) {
      var left = (a.children[columnIndex] || {}).textContent || "";
      var right = (b.children[columnIndex] || {}).textContent || "";
      return ascending
        ? left.trim().localeCompare(right.trim(), undefined, { numeric: true })
        : right.trim().localeCompare(left.trim(), undefined, { numeric: true });
    });
    rows.forEach(function (row) { body.appendChild(row); });
    applyList(list);
  }

  each("[data-np-list]", document, function (list) { applyList(list); });

  document.addEventListener("input", function (event) {
    var list = event.target.closest ? event.target.closest("[data-np-list]") : null;
    if (list && event.target.matches("[data-np-list-search]")) {
      list.dataset.npListShown = "";
      applyList(list);
    }
  });

  document.addEventListener("change", function (event) {
    var list = event.target.closest ? event.target.closest("[data-np-list]") : null;
    if (list && event.target.matches("[data-np-list-filter]")) {
      list.dataset.npListShown = "";
      applyList(list);
    }
  });

  document.addEventListener("click", function (event) {
    var sortButton = event.target.closest ? event.target.closest("[data-np-list-sort]") : null;
    if (sortButton) {
      var list = sortButton.closest("[data-np-list]");
      if (list) sortList(list, parseInt(sortButton.getAttribute("data-np-list-sort"), 10) || 0, sortButton);
      return;
    }
    var moreButton = event.target.closest ? event.target.closest("[data-np-list-more]") : null;
    if (moreButton) {
      var moreList = moreButton.closest("[data-np-list]");
      if (!moreList) return;
      var pageSize = parseInt(moreList.getAttribute("data-np-list-page-size"), 10) || 25;
      var shown = parseInt(moreList.dataset.npListShown, 10) || pageSize;
      moreList.dataset.npListShown = String(shown + pageSize);
      applyList(moreList);
    }
  });

  document.addEventListener("submit", function (event) {
    var mailQueueFilter = event.target.closest("[data-np-mail-queue-filter]");
    if (mailQueueFilter && window.fetch) {
      event.preventDefault();
      loadMailQueue(mailQueueFilter);
      return;
    }
    var mailLogFilter = event.target.closest("[data-np-mail-log-filter]");
    if (mailLogFilter && window.fetch) {
      event.preventDefault();
      loadMailLogs(mailLogFilter);
      return;
    }
    var journalFilter = event.target.closest("[data-np-journal-filter]");
    if (journalFilter && window.fetch) {
      event.preventDefault();
      loadServerJournal(journalFilter);
      return;
    }
    var serverAdminForm = event.target.closest("[data-np-service-form], [data-np-reauth-form]");
    if (serverAdminForm && window.fetch) {
      event.preventDefault();
      submitServerAdminForm(serverAdminForm, event.submitter);
      return;
    }
    var phase26Form = event.target.closest("[data-np-database-form], [data-np-update-install-form], [data-np-power-form]");
    if (phase26Form && window.fetch) {
      event.preventDefault();
      var statusSelector = phase26Form.matches("[data-np-database-form]") ? "[data-np-database-operation]" :
        (phase26Form.matches("[data-np-power-form]") ? "[data-np-power-operation]" : "[data-np-update-operation]");
	      submitPhase26Form(phase26Form, statusSelector, event.submitter);
      return;
    }
	var policyForm = event.target.closest("[data-np-policy-builder]");
	if (policyForm) buildHostingPolicyPatch(policyForm);
	var sitePolicyForm = event.target.closest("[data-np-site-policy-builder]");
	if (sitePolicyForm) buildSitePolicyPatch(sitePolicyForm);
    prepareForms();
	var planEditorForm = event.target.closest("[data-np-plan-editor]");
	var planForm = event.target.closest('[data-np-plan-editor][action="/plans"]');
	if (planForm) {
	  if (!planSubmitBypass && parseInt(planForm.dataset.npPlanId || "0", 10) > 0 && document.getElementById("plan-preview-dialog")) {
        event.preventDefault();
        reviewPlan(planForm);
        return;
      }
      planSubmitBypass = false;
    }
	if (planEditorForm) planEditorForm.dataset.npDirty = "false";
    var form = event.target.closest("[data-np-create-site-form]");
    if (!form) return;
    updateCreateGate(form);
    if (form.dataset.npGateBlocked === "true") { event.preventDefault(); return; }
    if (!window.fetch) return;
    event.preventDefault();
    submitSite(form);
  });

  initSiteLogs();
  initContainerLogs();
  initContainerDeployForms();

  document.addEventListener("dragover", function (event) {
    var manager = event.target.closest && event.target.closest("[data-np-file-manager]");
    if (!manager || manager.hasAttribute("data-np-file-unavailable")) return;
    event.preventDefault();
    manager.classList.add("is-dragging");
  });

  document.addEventListener("dragleave", function (event) {
    var manager = event.target.closest && event.target.closest("[data-np-file-manager]");
    if (manager && (!event.relatedTarget || !manager.contains(event.relatedTarget))) manager.classList.remove("is-dragging");
  });

  document.addEventListener("drop", function (event) {
    var manager = event.target.closest && event.target.closest("[data-np-file-manager]");
    if (!manager || manager.hasAttribute("data-np-file-unavailable")) return;
    event.preventDefault();
    manager.classList.remove("is-dragging");
    var files = event.dataTransfer && event.dataTransfer.files;
    if (!files || !files.length) return;
    var entries = Array.prototype.map.call(files, function (file) { return {file: file, relative: file.name}; });
    uploadFileQueue(manager, entries, null);
  });

  window.addEventListener("beforeunload", function (event) {
    var dirty = document.querySelector('[data-np-dirty-guard][data-np-dirty="true"]');
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  document.addEventListener("keydown", function (event) {
    var openDialog = document.querySelector("dialog[open]");
    if (event.key === "Tab" && openDialog) {
      var focusable = Array.prototype.filter.call(openDialog.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'), function (item) {
        return !item.hidden && item.offsetParent !== null;
      });
      if (focusable.length) {
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
      return;
    }
    if (event.key === "ArrowDown" && event.target.matches("[data-np-search-input]")) {
      var firstResult = document.querySelector("[data-np-search-results] a");
      if (firstResult) { event.preventDefault(); firstResult.focus(); }
      return;
    }
    if (event.key !== "Escape") return;
    if (openDialog) closeDialog(openDialog);
    each(".np-dns-action-menu[open]", document, function (menu) { menu.open = false; });
    setMenu(false);
    var results = document.querySelector("[data-np-search-results]");
    if (results) results.hidden = true;
  });

  prepareForms();
  each("dialog[data-np-dialog]", document, function (dialog) {
    dialog.addEventListener("close", function () {
      if (dialog.id === "np-confirmation-dialog" && confirmationResolver) {
        var resolve = confirmationResolver;
        confirmationResolver = null;
        resolve(false);
      }
      document.body.classList.remove("np-modal-open");
      if (lastDialogTrigger) lastDialogTrigger.focus();
      lastDialogTrigger = null;
    });
  });
  updateCreateGate(document);
  updateOnboarding();
  each("[data-np-bulk-form]", document, updateBulkForm);
  each("[data-np-unlimited]", document, updateUnlimited);
  each("[data-np-file-manager]", document, updateFileSelection);
  filterSettings("");
  initializeDirtyForms();
  initializeDNSFilters();
  initializeDNSSettingsTabs();
  initializeDNSRecordForms();
  initializeCodeEditor();
  each("[data-np-service-refresh]", document, function (button) {
    button.addEventListener("click", function () {
      var label = button.querySelector("[data-np-service-refresh-label]");
      button.disabled = true;
      if (label) label.textContent = "Refreshing…";
      loadServerInventory().then(function () {
        if (label) label.textContent = "Refreshed";
        window.setTimeout(function () {
          if (label) label.textContent = "Refresh";
        }, 1200);
      }, function () {
        if (label) label.textContent = "Try again";
      }).then(function () {
        button.disabled = false;
      });
    });
  });
  each("[data-np-update-refresh]", document, function (button) {
    button.addEventListener("click", function () {
      var label = button.querySelector("[data-np-update-refresh-label]");
      if (label) label.textContent = "Refreshing…";
      loadServerUpdates(false).then(function (success) {
        if (label) label.textContent = success ? "Inventory refreshed" : "Try again";
        if (success) window.setTimeout(function () { label.textContent = "Refresh inventory"; }, 1200);
      });
    });
  });
  loadServerInventory();
  loadServerJournal();
  loadServerUpdates(false);
  loadMailStatus();
  loadServerSecurity();
  bindSecurityControls();
  loadServerBackups();
  bindBackupControls();
  loadMailQueue();
  loadMailLogs();
  loadDatabaseAdmin();
  loadApplicationCatalog();
})();
