(function () {
  'use strict';
  function removalReady(form) {
    if (!form || form.getAttribute('aria-busy') === 'true' || form.dataset.npRemovalUncertain === 'true' || form.dataset.npRemovalStale === 'true') return false;
    var name = form.querySelector('[name="confirm_domain"]');
    var children = form.querySelector('[name="include_children"]');
    var permanent = form.querySelector('[name="acknowledge_permanent"]');
    return !!(name && name.value.trim() === form.dataset.npConfirmDomain && permanent && permanent.checked && (!children || children.checked));
  }
  function normalizeSubdomainLabel(value, parent) {
    var original = String(value || '').trim(), normalized = original.toLowerCase().replace(/\.$/, '');
    var suffix = '.' + String(parent || '').toLowerCase();
    var label = normalized.endsWith(suffix) ? normalized.slice(0, -suffix.length) : normalized;
    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) ? label : original;
  }
  function subdomainError(value, parent) {
    if (!String(value || '').trim()) return '';
    var label = normalizeSubdomainLabel(value, parent);
    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) ? '' : 'Enter 1–63 letters, numbers or hyphens, starting and ending with a letter or number.';
  }
  function menuOpensUp(rect, viewportHeight) {
    return rect.bottom > viewportHeight - 12 && rect.top - rect.height > 12;
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {removalReady:removalReady, normalizeSubdomainLabel:normalizeSubdomainLabel, menuOpensUp:menuOpensUp, subdomainError:subdomainError};
  if (typeof window === 'undefined') return;
  var document = window.document;
  function updateRemovalGate(root) {
    root.querySelectorAll('[data-np-removal-form]').forEach(function (form) {
      var button = form.querySelector('button[type="submit"]');
      if (button) button.disabled = !removalReady(form);
    });
  }
  function updateSubdomainField(form) {
    if (form.dataset.npSubmitting === 'true') return;
    var field = form.querySelector('[name="label"]');
    if (!field) return;
    var error = subdomainError(field.value, form.dataset.npParentDomain);
    var message = form.querySelector('[data-np-subdomain-field-error]');
    field.setAttribute('aria-invalid', error ? 'true' : 'false');
    field.setCustomValidity(error);
    if (message) { message.textContent = error; message.hidden = !error; }
    var suffix = form.querySelector('[data-np-subdomain-suffix]');
    if (suffix) suffix.hidden = field.value.trim().toLowerCase().replace(/\.$/, '').endsWith('.' + form.dataset.npParentDomain.toLowerCase());
  }
  window.NakpanelDomains = {updateRemovalGate:updateRemovalGate, subdomainError:subdomainError};
  function closeMenu(menu, restoreFocus) {
    menu.open = false;
    menu.classList.remove('np-domain-menu-up');
    if (restoreFocus) menu.querySelector('summary').focus();
  }
  document.addEventListener('toggle', function (event) {
    var menu = event.target;
    if (!menu.matches || !menu.matches('details[data-np-domain-menu]') || !menu.open) return;
    document.querySelectorAll('details[data-np-domain-menu][open]').forEach(function (other) { if (other !== menu) closeMenu(other, false); });
    menu.classList.remove('np-domain-menu-up');
    var content = menu.querySelector('.np-domain-actions-menu,.np-domain-more-menu');
    if (content && menuOpensUp(content.getBoundingClientRect(), window.innerHeight)) menu.classList.add('np-domain-menu-up');
  }, true);
  document.addEventListener('click', function (event) {
    document.querySelectorAll('details[data-np-domain-menu][open]').forEach(function (menu) { if (!menu.contains(event.target)) closeMenu(menu, false); });
    var refresh = event.target.closest('[data-np-domain-refresh]');
    if (refresh) window.location.reload();
  });
  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape' || document.querySelector('dialog[open]')) return;
    var menu = document.querySelector('details[data-np-domain-menu][open]');
    if (menu) { event.preventDefault(); closeMenu(menu, true); }
  });
  function changed(event) {
    var form = event.target.closest('form');
    if (!form) return;
    if (form.matches('[data-np-removal-form]')) updateRemovalGate(form.parentElement);
    if (form.matches('[data-np-create-subdomain-form]')) updateSubdomainField(form);
  }
  document.addEventListener('input', changed);
  document.addEventListener('change', changed);
  document.addEventListener('focusout', function (event) {
    var input = event.target, form = input.closest('[data-np-create-subdomain-form]');
    if (!form || input.name !== 'label' || form.dataset.npSubmitting === 'true') return;
    var normalized = normalizeSubdomainLabel(input.value, form.dataset.npParentDomain);
    if (normalized !== input.value) { input.value = normalized; input.dispatchEvent(new Event('input', {bubbles:true})); }
  });
  updateRemovalGate(document);
})();
