# Service plan deletion

An administrator can delete a hosting plan when it has no subscriptions. A
reseller can delete an unused hosting plan owned by that reseller. This applies
to draft, active and retired plans, including the initial hosting plans.

Use **Delete** on the hosting-plan list or the plan detail page, then confirm.
The plan, its service presets and its revision history are removed together.
A successful deletion is recorded in the audit log.
During submission the Delete button is disabled. If the request fails, it is
enabled again so the operator can review the error before retrying.

Any linked subscription blocks deletion, including suspended or cancelled
subscriptions and subscriptions with locked or custom settings. The interface
shows **Has subscriptions**. Move those subscriptions to another plan or remove
them before deleting the plan. Retirement remains available when a plan should
stop accepting new subscriptions while existing subscriptions keep using it.

The server rechecks ownership and relies on the subscription foreign key during
deletion, so a stale page or concurrent subscription assignment cannot bypass
the restriction. Individual revision edits and deletions remain forbidden while
their plan exists. No hosted files, mailboxes or databases are deleted by this
action.

The feature uses migration `20261028000062_unused_plan_deletion.sql`. It does not
change the supported Ubuntu 26.04 or PHP 8.3/8.4/8.5 runtime contract.
