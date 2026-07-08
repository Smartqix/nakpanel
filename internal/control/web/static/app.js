(function () {
  "use strict";

  var root = document.documentElement;
  root.classList.add("nakpanel-js");

  function each(selector, scope, fn) {
    Array.prototype.forEach.call((scope || document).querySelectorAll(selector), fn);
  }

  function setView(name) {
    if (!name) {
      return;
    }
    var nextTitle = "";
    each("[data-np-view]", document, function (button) {
      var active = button.getAttribute("data-np-view") === name;
      button.classList.toggle("is-active", active);
      if (!button.disabled) {
        button.setAttribute("aria-current", active ? "page" : "false");
      }
      if (active && button.getAttribute("data-np-view-title")) {
        nextTitle = button.getAttribute("data-np-view-title");
      }
    });
    each("[data-np-panel]", document, function (panel) {
      panel.classList.toggle("is-active", panel.getAttribute("data-np-panel") === name);
    });
    var title = document.querySelector("[data-np-section-title]");
    if (title && nextTitle) {
      title.textContent = nextTitle;
    }
    document.body.classList.remove("np-sidebar-open");
  }

  function openCreateModal() {
    var modal = document.getElementById("create-site-modal");
    if (!modal) {
      return;
    }
    modal.hidden = false;
    document.body.classList.add("np-modal-open");
    updateCreateGate(modal);
    var focusTarget = modal.querySelector("input, select, button");
    if (focusTarget) {
      focusTarget.focus();
    }
  }

  function closeCreateModal() {
    var modal = document.getElementById("create-site-modal");
    if (!modal) {
      return;
    }
    modal.hidden = true;
    document.body.classList.remove("np-modal-open");
  }

  function selectedCustomer(form) {
    var select = form && (form.querySelector('select[name="subscription_id"]') || form.querySelector('select[name="owner_user_id"]'));
    if (!select || !select.selectedOptions || select.selectedOptions.length === 0) {
      return null;
    }
    return select.selectedOptions[0].dataset;
  }

  function gateMessage(data) {
    if (!data || data.hasQuota !== "true") {
      return { blocked: true, text: "This customer has no active subscription." };
    }
    var maxSites = parseInt(data.maxSites || "-1", 10);
    var sitesUsed = parseInt(data.sitesUsed || "0", 10);
    if (maxSites >= 0 && sitesUsed >= maxSites) {
      return {
        blocked: true,
        text: (data.email || "Customer") + " is at the site limit for " + (data.planName || "the selected plan") + "."
      };
    }
    return {
      blocked: false,
      text: (data.email || "Customer") + " can create another site on " + (data.planName || "the selected plan") + "."
    };
  }

  function updateCreateGate(scope) {
    each("[data-np-create-site-form]", scope || document, function (form) {
      var gate = form.querySelector("[data-np-customer-gate]");
      var submit = form.querySelector("[data-np-create-submit]");
      var result = gateMessage(selectedCustomer(form));
      if (gate) {
        gate.textContent = result.text;
        gate.classList.toggle("is-blocked", result.blocked);
      }
      if (submit) {
        submit.disabled = result.blocked;
      }
      form.dataset.npGateBlocked = result.blocked ? "true" : "false";
    });
  }

  function subscriptionRows() {
    return Array.prototype.slice.call(document.querySelectorAll("[data-np-subscription-row]"));
  }

  function selectedSubscriptionRows() {
    return subscriptionRows().filter(function (row) {
      var checkbox = row.querySelector("[data-np-subscription-check]");
      return checkbox && checkbox.checked;
    });
  }

  function updateSubscriptionSelection() {
    var selected = selectedSubscriptionRows();
    subscriptionRows().forEach(function (row) {
      var checkbox = row.querySelector("[data-np-subscription-check]");
      row.classList.toggle("is-selected", !!checkbox && checkbox.checked);
    });
    each("[data-np-change-plan]", document, function (button) {
      button.disabled = selected.length !== 1;
    });
  }

  function filterSubscriptions() {
    var input = document.querySelector("[data-np-subscription-filter]");
    if (!input) {
      return;
    }
    var query = input.value.trim().toLowerCase();
    subscriptionRows().forEach(function (row) {
      var haystack = [
        row.getAttribute("data-subscriber-email") || "",
        row.getAttribute("data-plan-name") || "",
        row.textContent || ""
      ].join(" ").toLowerCase();
      row.classList.toggle("is-filtered", query !== "" && haystack.indexOf(query) === -1);
    });
  }

  function openSubscriptionAdmin(customerUserID, customerID) {
    var target = document.getElementById("subscription-admin-forms");
    if (!target) {
      return;
    }
    target.classList.add("is-open");
    var select = target.querySelector('[data-np-subscription-assign-form] select[name="customer_user_id"], [data-np-subscription-assign-form] select[name="customer_id"]');
    if (select) {
      select.value = select.name === "customer_id" ? customerID || "" : customerUserID || "";
    }
    if (target.scrollIntoView) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  async function submitSPAForm(form) {
    var payload = new FormData(form);
    var response = await fetch(form.action, {
      method: "POST",
      body: payload,
      credentials: "same-origin",
      headers: { "X-Nakpanel-SPA": "true" }
    });
    var data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Request failed");
    }
    return data;
  }

  document.addEventListener("click", function (event) {
    var viewButton = event.target.closest("[data-np-view]");
    if (viewButton && !viewButton.disabled) {
      setView(viewButton.getAttribute("data-np-view"));
    }
    if (event.target.closest("[data-np-open-create]")) {
      openCreateModal();
    }
    if (event.target.closest("[data-np-close-modal]")) {
      closeCreateModal();
    }
    if (event.target.closest("[data-np-menu]")) {
      document.body.classList.toggle("np-sidebar-open");
    }
    if (event.target.closest("[data-np-add-subscription]")) {
      openSubscriptionAdmin("", "");
    }
    if (event.target.closest("[data-np-change-plan]")) {
      var selected = selectedSubscriptionRows();
      if (selected.length === 1) {
        openSubscriptionAdmin(
          selected[0].getAttribute("data-customer-user-id"),
          selected[0].getAttribute("data-customer-id")
        );
      }
    }
    var scrollButton = event.target.closest("[data-np-scroll-target]");
    if (scrollButton) {
      var target = document.querySelector(scrollButton.getAttribute("data-np-scroll-target"));
      if (target && target.scrollIntoView) {
        target.classList.add("is-open");
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  });

  document.addEventListener("change", function (event) {
    if (event.target.matches('[data-np-create-site-form] select[name="subscription_id"], [data-np-create-site-form] select[name="owner_user_id"]')) {
      updateCreateGate(document);
    }
    if (event.target.matches("[data-np-subscription-check]")) {
      updateSubscriptionSelection();
    }
  });

  document.addEventListener("input", function (event) {
    if (event.target.matches("[data-np-subscription-filter]")) {
      filterSubscriptions();
    }
  });

  document.addEventListener("submit", function (event) {
    var form = event.target.closest("[data-np-create-site-form]");
    if (!form) {
      return;
    }
    updateCreateGate(form);
    if (form.dataset.npGateBlocked === "true") {
      event.preventDefault();
      return;
    }
    if (!window.fetch) {
      return;
    }
    event.preventDefault();
    var submit = form.querySelector("[data-np-create-submit]");
    var gate = form.querySelector("[data-np-customer-gate]");
    if (submit) {
      submit.disabled = true;
    }
    submitSPAForm(form).then(function (data) {
      if (gate) {
        gate.textContent = data.notice || "Site provisioning queued.";
        gate.classList.remove("is-blocked");
      }
      window.location.assign(data.redirect || "/");
    }).catch(function (error) {
      if (gate) {
        gate.textContent = error.message;
        gate.classList.add("is-blocked");
      }
      if (submit) {
        submit.disabled = false;
      }
    });
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeCreateModal();
      document.body.classList.remove("np-sidebar-open");
    }
  });

  updateCreateGate(document);
  updateSubscriptionSelection();
  filterSubscriptions();
})();
