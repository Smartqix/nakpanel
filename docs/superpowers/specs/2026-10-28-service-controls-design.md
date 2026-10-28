# Reliable service controls

The owner approved implementing the Services audit recommendations on 28 October 2026. Repair valid browser submissions and recent-password authorization; expose progress and failures beside the service and in Tasks; close action dropdowns on selection, cancellation, outside click, Escape and navigation.

Reuse the existing River system queue, server_operations and Operations recorder. Every accepted action has one durable task, a readable service/action title, a per-service failure identity and a task link. Keep recent successful manual service actions in quick Tasks for ten minutes. Recover ongoing actions after refresh/navigation, prevent conflicting requests for one service and never automatically replay uncertain commands. Display queued, actual execution, verification and terminal results without invented percentages. Verify Running for start/restart/reload and Stopped for stop.

Keep the existing grouped list and design system. Make feedback visible, remove empty notices, label startup state accurately, distinguish optional missing services, and show only supported PHP 8.3/8.4/8.5. Preserve Ubuntu 26.04, administrator/CSRF/recent-password authorization, isolated PHP execution and readiness.

Alternatives: menu-only CSS repair leaves broken submissions and lost progress; a separate task engine duplicates durable state. Repairing the current integration is selected by the owner's instruction to implement the recommendation.

Implement and verify locally only. No hosted tests, production service actions, PR, merge or deployment are authorized by this implementation request.
