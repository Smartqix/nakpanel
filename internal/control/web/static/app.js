(function () {
  "use strict";

  document.documentElement.classList.add("nakpanel-js");
  var lastDialogTrigger = null;
  var planSubmitBypass = false;
  var pendingPlanForm = null;

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
      var message = form.querySelector("[data-np-customer-gate]");
      var submit = form.querySelector("[data-np-create-submit]");
      if (message) {
        message.textContent = result.text;
        message.classList.toggle("is-blocked", result.blocked);
      }
      if (submit) submit.disabled = result.blocked;
      form.dataset.npGateBlocked = result.blocked ? "true" : "false";
      updateSitePHP(form);
    });
  }

  function updateSitePHP(form) {
    var data = selectedSubscription(form);
    var select = form && form.querySelector("[data-np-site-php]");
    if (!select || !data) return;
    var previous = select.value;
    var versions = (data.phpVersions || "").split(",").map(function (value) { return value.trim(); }).filter(Boolean);
    if (!versions.length) return;
    select.replaceChildren();
    versions.forEach(function (version) {
      var option = document.createElement("option");
      option.value = version;
      option.textContent = version;
      select.appendChild(option);
    });
    if (versions.indexOf(previous) !== -1) select.value = previous;
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
          if (window.confirm(entry.relative + " already exists. Replace it?")) {
            send(index, true);
          } else {
            rows[index].textContent = "Skipped";
            send(index + 1, false);
          }
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
      applications: {allowed_registries: registries, rootless: true, allowed_runtimes: ["php", "python", "node", "oci"]}
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
    var patch = {
      permissions: {cgi: checked("site_cgi")},
      web: {
        request_rate_per_second: number("site_request_rate"), request_burst: number("site_request_burst"),
        max_connections: number("site_max_connections"), static_cache: checked("site_static_cache"),
        fastcgi_microcache: checked("site_fastcgi_microcache")
      },
      php: {
        fpm_max_children: number("site_fpm_children"), memory_limit_mb: number("site_php_memory"),
        max_execution_seconds: number("site_php_execution"), exec_enabled: checked("site_php_exec")
      }
    };
    form.querySelector("[data-np-policy-patch]").value = JSON.stringify(patch);
  }

  document.addEventListener("click", function (event) {
    var legacy = event.target.closest("[data-np-view]");
    if (legacy && !legacy.disabled) setLegacyView(legacy.getAttribute("data-np-view"));
    var opener = event.target.closest("[data-np-dialog-open]");
    if (opener) openDialog(opener.getAttribute("data-np-dialog-open"), opener);
    var closer = event.target.closest("[data-np-dialog-close]");
    if (closer) closeDialog(closer.closest("dialog"));
    if (event.target.closest("[data-np-menu]")) setMenu(true);
    if (event.target.closest("[data-np-menu-close]")) setMenu(false);
    if (event.target.matches("dialog[open]")) closeDialog(event.target);
    var confirmButton = event.target.closest("[data-np-confirm]");
    if (confirmButton && !window.confirm(confirmButton.getAttribute("data-np-confirm"))) event.preventDefault();
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
    if (event.target.matches('input[name="customer_mode"], [data-np-create-first-site]')) updateOnboarding();
    if (event.target.matches("[data-np-subscription-nav]") && event.target.value) window.location.assign(event.target.value);
    if (event.target.matches("[data-np-bulk-all]")) {
      var bulkForm = event.target.closest("[data-np-bulk-form]");
      each("[data-np-bulk-check]", bulkForm, function (input) { input.checked = event.target.checked; });
      updateBulkForm(bulkForm);
    } else if (event.target.matches("[data-np-bulk-check]")) {
      updateBulkForm(event.target.closest("[data-np-bulk-form]"));
    }
    if (event.target.matches("[data-np-unlimited]")) updateUnlimited(event.target);
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
    if (event.target.matches("[data-np-subscription-filter]")) {
      var query = event.target.value.toLowerCase();
      each("[data-np-subscription-row]", document, function (row) { row.hidden = query && row.textContent.toLowerCase().indexOf(query) === -1; });
    }
    var editor = event.target.closest("[data-np-plan-editor]");
    if (editor) editor.dataset.npDirty = "true";
  });

  document.addEventListener("submit", function (event) {
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
    setMenu(false);
    var results = document.querySelector("[data-np-search-results]");
    if (results) results.hidden = true;
  });

  prepareForms();
  each("dialog[data-np-dialog]", document, function (dialog) {
    dialog.addEventListener("close", function () {
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
  initializeCodeEditor();
})();
