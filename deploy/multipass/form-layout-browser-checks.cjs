// Pass to page.evaluate (or the CUA read-only DOM evaluator) on a rendered form.
// Checks geometry, not CSS source, so wrapped labels and helper text are covered.
module.exports = function checkFormLayout() {
  const problems = [];
  let fields = 0;
  let rows = 0;
  const grids = [...document.querySelectorAll('.np-plan-general-grid, .np-plan-field-grid, .np-settings-fields')]
    .filter(grid => grid.getClientRects().length);
  for (const grid of grids) {
    const groups = [];
    for (const field of grid.children) {
      const control = field.querySelector('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]), select, textarea');
      if (!control) continue;
      fields++;
      const rect = field.getBoundingClientRect();
      const input = control.getBoundingClientRect();
      let row = groups.find(row => Math.abs(row.top - rect.top) < 2);
      if (!row) groups.push(row = { top: rect.top, controls: [] });
      row.controls.push({ name: control.name, top: input.top, width: rect.width });
      if (input.left < rect.left - 1 || input.right > rect.right + 1) {
        problems.push(`${control.name}: control overflows its field`);
      }
      let previousBottom = input.bottom;
      for (const help of field.querySelectorAll(':scope > small')) {
        const helpRect = help.getBoundingClientRect();
        if (help.getClientRects().length && helpRect.top < previousBottom - 1) {
          problems.push(`${control.name}: help or validation text overlaps the preceding content`);
        }
        previousBottom = helpRect.bottom;
      }
      const limitControls = field.querySelector('.np-limit-controls');
      if (limitControls) {
        const parts = [...limitControls.children].filter(part => part.getClientRects().length)
          .map(part => part.getBoundingClientRect());
        for (let index = 0; index < parts.length; index++) {
          if (parts[index].right > rect.right + 1 || (index && parts[index - 1].right > parts[index].left + 1)) {
            problems.push(`${control.name}: limit controls overlap or overflow`);
          }
        }
      }
    }
    for (const row of groups) {
      rows++;
      const tops = row.controls.map(control => control.top);
      if (Math.max(...tops) - Math.min(...tops) > 2) {
        problems.push(`Misaligned controls: ${row.controls.map(control => `${control.name}=${control.top.toFixed(1)}`).join(', ')}`);
      }
    }
    if (grid.matches('.np-plan-general-grid')) {
      if (getComputedStyle(grid).gridTemplateColumns.split(' ').length > 1) {
        for (const pair of [['name', 'price_cents'], ['lifecycle_status', 'change_reason']]) {
          const controls = pair.map(name => grid.querySelector(`[name="${name}"]`));
          if (controls.every(Boolean) && Math.abs(controls[0].getBoundingClientRect().top - controls[1].getBoundingClientRect().top) > 2) {
            problems.push(`${pair.join(' and ')} do not share a control baseline`);
          }
        }
      }
      const name = grid.querySelector('[name="name"]')?.closest('label');
      const price = grid.querySelector('[name="price_cents"]')?.closest('label');
      if (name && price && Math.abs(name.getBoundingClientRect().width - price.getBoundingClientRect().width) > 2) {
        problems.push('Plan name and price columns have unequal widths');
      }
      const description = grid.querySelector('[name="description"]')?.closest('label');
      if (description && Math.abs(description.getBoundingClientRect().width - grid.getBoundingClientRect().width) > 2) {
        problems.push('Plan description does not span the form');
      }
    }
  }
  if (!fields) problems.push('No visible form fields were checked');
  if (document.documentElement.scrollWidth > document.documentElement.clientWidth + 1) {
    problems.push('Document has horizontal overflow');
  }
  if (problems.length) throw new Error(problems.join('\n'));
  return { grids: grids.length, fields, rows, problems };
};
