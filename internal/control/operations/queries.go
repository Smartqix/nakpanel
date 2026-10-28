package operations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"time"
)

type Filter struct {
	// ActiveFirst is for the bounded quick view; full pages use keyset order.
	ActiveFirst              bool
	Resource                 Resource
	Before                   int64
	Limit                    int
	Search, Status, Severity string
}
type Counts struct {
	OpenIssues  int `json:"open_issues"`
	ActiveTasks int `json:"active_tasks"`
	Unread      int `json:"unread"`
}
type Notification struct {
	ID          int64      `json:"id"`
	Kind        string     `json:"kind"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Summary     string     `json:"summary"`
	Target      string     `json:"target"`
	IssueID     int64      `json:"issue_id,omitempty"`
	OperationID int64      `json:"operation_id,omitempty"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
type Page struct {
	Counts        Counts         `json:"counts"`
	Cursor        int64          `json:"cursor"`
	NextBefore    int64          `json:"next_before,omitempty"`
	Issues        []Issue        `json:"issues,omitempty"`
	Tasks         []Operation    `json:"tasks,omitempty"`
	History       []Event        `json:"history,omitempty"`
	Notifications []Notification `json:"notifications,omitempty"`
	CheckedAt     time.Time      `json:"checked_at"`
}
type OperationDetail struct {
	Operation Operation `json:"operation"`
	Attempts  []Attempt `json:"attempts"`
}
type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (f Filter) validate() error {
	if f.Before < 0 || f.Limit < 0 || f.Limit > 200 || len(f.Search) > 200 || (f.Resource.Kind != "" && !f.Resource.Valid()) || (f.ActiveFirst && f.Before > 0) {
		return ErrInvalid
	}
	switch f.Status {
	case "", "open", "acknowledged", "resolved", "active", "finished", "unread", "all":
	default:
		return ErrInvalid
	}
	switch f.Severity {
	case "", "info", "warning", "critical":
	default:
		return ErrInvalid
	}
	return nil
}
func (f Filter) limit() int {
	if f.Limit == 0 {
		return 50
	}
	return f.Limit
}
func bind(args *[]any, value any) string {
	*args = append(*args, value)
	return fmt.Sprintf("$%d", len(*args))
}
func resourceFilter(alias string, f Filter, args *[]any) string {
	if f.Resource.Kind == "" {
		return ""
	}
	kind := bind(args, string(f.Resource.Kind))
	id := bind(args, f.Resource.ID)
	if f.Resource.Kind == ResourceSubscription {
		return ` AND ((` + alias + `.resource_kind=` + kind + ` AND ` + alias + `.resource_id=` + id + `) OR (` + alias + `.resource_kind='site' AND EXISTS(SELECT 1 FROM sites filter_site WHERE filter_site.id=` + alias + `.resource_id AND filter_site.subscription_id=` + id + `)))`
	}
	if f.Resource.Kind == ResourceCustomer {
		return ` AND ((` + alias + `.resource_kind=` + kind + ` AND ` + alias + `.resource_id=` + id + `) OR (` + alias + `.resource_kind='subscription' AND EXISTS(SELECT 1 FROM subscriptions filter_sub WHERE filter_sub.id=` + alias + `.resource_id AND filter_sub.customer_id=` + id + `)) OR (` + alias + `.resource_kind='site' AND EXISTS(SELECT 1 FROM sites filter_site JOIN subscriptions filter_sub ON filter_sub.id=filter_site.subscription_id WHERE filter_site.id=` + alias + `.resource_id AND filter_sub.customer_id=` + id + `)))`
	}
	return ` AND ` + alias + `.resource_kind=` + kind + ` AND ` + alias + `.resource_id=` + id
}
func rowFilter(alias string, f Filter, args *[]any) string {
	clause := resourceFilter(alias, f, args)
	if f.Before > 0 {
		clause += ` AND ` + alias + `.id<` + bind(args, f.Before)
	}
	if f.Search != "" {
		clause += ` AND (` + alias + `.title ILIKE ` + bind(args, "%"+f.Search+"%") + ` OR ` + targetSQL(alias) + ` ILIKE ` + bind(args, "%"+f.Search+"%") + `)`
	}
	return clause
}
func targetSQL(a string) string {
	return `COALESCE(CASE ` + a + `.resource_kind WHEN 'server' THEN 'Server' WHEN 'site' THEN (SELECT domain FROM sites WHERE id=` + a + `.resource_id) WHEN 'subscription' THEN (SELECT name FROM subscriptions WHERE id=` + a + `.resource_id) WHEN 'customer' THEN (SELECT display_name FROM customers WHERE id=` + a + `.resource_id) WHEN 'user' THEN 'Your account' END,'Removed resource')`
}

// Detail destinations require a current resource, even when an administrator
// can still inspect its retained incident after removal.
func resourceAvailableSQL(a string) string {
	return `CASE ` + a + `.resource_kind WHEN 'server' THEN true WHEN 'site' THEN EXISTS(SELECT 1 FROM sites WHERE id=` + a + `.resource_id) WHEN 'subscription' THEN EXISTS(SELECT 1 FROM subscriptions WHERE id=` + a + `.resource_id) WHEN 'customer' THEN EXISTS(SELECT 1 FROM customers WHERE id=` + a + `.resource_id) WHEN 'user' THEN EXISTS(SELECT 1 FROM users WHERE id=` + a + `.resource_id) ELSE false END`
}
func (s *Store) Page(ctx context.Context, actor auth.SessionUser, view string, f Filter) (Page, error) {
	result := Page{CheckedAt: time.Now().UTC()}
	if err := f.validate(); err != nil {
		return result, err
	}
	if !actor.Role.Valid() || actor.ID <= 0 {
		return result, ErrNotFound
	}
	switch view {
	case "issues", "tasks", "history", "inbox":
	default:
		return result, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT cursor FROM operation_feed_clock WHERE singleton`).Scan(&result.Cursor); err != nil {
		return result, err
	}
	result.Counts, err = counts(ctx, tx, actor, f)
	if err != nil {
		return result, err
	}
	switch view {
	case "issues":
		result.Issues, err = listIssues(ctx, tx, actor, f)
		if len(result.Issues) > f.limit() {
			result.Issues = result.Issues[:f.limit()]
			result.NextBefore = result.Issues[len(result.Issues)-1].ID
		}
	case "tasks":
		result.Tasks, err = listOperations(ctx, tx, actor, f)
		if len(result.Tasks) > f.limit() {
			result.Tasks = result.Tasks[:f.limit()]
			if !f.ActiveFirst {
				result.NextBefore = result.Tasks[len(result.Tasks)-1].ID
			}
		}
	case "history":
		result.History, err = listHistory(ctx, tx, actor, f)
		if len(result.History) > f.limit() {
			result.History = result.History[:f.limit()]
			result.NextBefore = result.History[len(result.History)-1].ID
		}
	case "inbox":
		result.Notifications, err = listNotifications(ctx, tx, actor, f)
		if len(result.Notifications) > f.limit() {
			result.Notifications = result.Notifications[:f.limit()]
			result.NextBefore = result.Notifications[len(result.Notifications)-1].ID
		}
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}
func counts(ctx context.Context, q queryer, actor auth.SessionUser, f Filter) (Counts, error) {
	var c Counts
	args := []any{actor.ID, string(actor.Role)}
	where := resourcePredicate("i", 1, 2) + resourceFilter("i", f, &args)
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM issues i WHERE resolved_at IS NULL AND `+where, args...).Scan(&c.OpenIssues); err != nil {
		return c, err
	}
	args = []any{actor.ID, string(actor.Role)}
	where = resourcePredicate("o", 1, 2) + resourceFilter("o", f, &args)
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM operations o WHERE state IN ('queued','running','waiting_retry') AND `+where, args...).Scan(&c.ActiveTasks); err != nil {
		return c, err
	}
	args = []any{actor.ID, string(actor.Role)}
	where = NotificationVisibilitySQL("n", 1, 2) + resourceFilter("scope", f, &args)
	err := q.QueryRowContext(ctx, `SELECT count(*) `+notificationFrom+` WHERE receipt.read_at IS NULL AND receipt.archived_at IS NULL AND `+where, args...).Scan(&c.Unread)
	return c, err
}
func listIssues(ctx context.Context, q queryer, actor auth.SessionUser, f Filter) ([]Issue, error) {
	out := []Issue{}
	args := []any{actor.ID, string(actor.Role)}
	where := resourcePredicate("i", 1, 2) + rowFilter("i", f, &args)
	if f.Status == "resolved" {
		where += ` AND resolved_at IS NOT NULL`
	} else if f.Status != "all" {
		where += ` AND resolved_at IS NULL`
	}
	if f.Status == "acknowledged" {
		where += ` AND acknowledged_at IS NOT NULL`
	} else if f.Status == "open" {
		where += ` AND acknowledged_at IS NULL`
	}
	if f.Severity != "" {
		where += ` AND severity=` + bind(&args, f.Severity)
	}
	rows, err := q.QueryContext(ctx, `SELECT `+issueColumns+`,`+targetSQL("i")+`,`+resourceAvailableSQL("i")+` FROM issues i WHERE `+where+` ORDER BY id DESC LIMIT `+bind(&args, f.limit()+1), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		var available bool
		i, err := scanIssue(rows, &target, &available)
		if err != nil {
			return out, err
		}
		i.Target = target
		i.ResourceAvailable = available
		out = append(out, i)
	}
	return out, rows.Err()
}
func listOperations(ctx context.Context, q queryer, actor auth.SessionUser, f Filter) ([]Operation, error) {
	out := []Operation{}
	args := []any{actor.ID, string(actor.Role)}
	where := resourcePredicate("o", 1, 2) + rowFilter("o", f, &args)
	if f.Status == "active" {
		where += ` AND state IN ('queued','running','waiting_retry')`
	} else if f.Status == "finished" {
		where += ` AND state IN ('succeeded','failed','cancelled')`
	}
	order := `id DESC`
	if f.ActiveFirst {
		where += ` AND state IN ('queued','running','waiting_retry','failed')`
		order = `CASE WHEN state IN ('queued','running','waiting_retry') THEN 0 ELSE 1 END,id DESC`
	}
	rows, err := q.QueryContext(ctx, `SELECT `+operationColumns+`,`+targetSQL("o")+` FROM operations o WHERE `+where+` ORDER BY `+order+` LIMIT `+bind(&args, f.limit()+1), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var target string
		o, err := scanOperation(rows, &target)
		if err != nil {
			return out, err
		}
		o.Target = target
		out = append(out, o)
	}
	return out, rows.Err()
}

const notificationFrom = `FROM notifications n LEFT JOIN issues ni ON ni.id=n.issue_id LEFT JOIN notification_receipts receipt ON receipt.notification_id=n.id AND receipt.user_id=$1
 CROSS JOIN LATERAL (SELECT COALESCE(ni.resource_kind,CASE WHEN n.subscription_id IS NOT NULL THEN 'subscription' WHEN n.customer_id IS NOT NULL THEN 'customer' WHEN n.recipient_user_id IS NOT NULL THEN 'user' ELSE 'server' END) AS resource_kind,COALESCE(ni.resource_id,n.subscription_id,n.customer_id,n.recipient_user_id,0) AS resource_id) scope`

const notificationSummarySQL = `CASE WHEN n.kind IN ('threshold','over_limit','suspended','certificate_expiring','login_new_device','login_failed_burst','operation_failed','issue_recovered') THEN left(n.body,2000) ELSE 'Open the affected resource to review its current status.' END`

func notificationColumns() string {
	return `n.id,n.kind,n.severity,n.title,` + notificationSummarySQL + `,` + targetSQL("scope") + `,COALESCE(n.issue_id,0),COALESCE(n.operation_id,0),receipt.read_at,n.created_at`
}

func scanNotification(row scanner) (Notification, error) {
	var n Notification
	err := row.Scan(&n.ID, &n.Kind, &n.Severity, &n.Title, &n.Summary, &n.Target, &n.IssueID, &n.OperationID, &n.ReadAt, &n.CreatedAt)
	return n, err
}

// Notification is a safe, fresh authorized read. Receipt state changes only via
// the explicit personal receipt operations, never by loading a detail.
func (s *Store) Notification(ctx context.Context, actor auth.SessionUser, id int64, scope Resource) (Notification, error) {
	if id <= 0 || scope.Kind == "" && scope.ID != 0 || scope.Kind != "" && !scope.Valid() {
		return Notification{}, ErrInvalid
	}
	if actor.ID <= 0 || !actor.Role.Valid() {
		return Notification{}, ErrNotFound
	}
	args := []any{actor.ID, string(actor.Role), id}
	where := `n.id=$3 AND ` + NotificationVisibilitySQL("n", 1, 2) + resourceFilter("scope", Filter{Resource: scope}, &args)
	n, err := scanNotification(s.db.QueryRowContext(ctx, `SELECT `+notificationColumns()+` `+notificationFrom+` WHERE `+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return n, err
}

func listNotifications(ctx context.Context, q queryer, actor auth.SessionUser, f Filter) ([]Notification, error) {
	out := []Notification{}
	args := []any{actor.ID, string(actor.Role)}
	where := NotificationVisibilitySQL("n", 1, 2) + resourceFilter("scope", f, &args) + ` AND receipt.archived_at IS NULL`
	if f.Before > 0 {
		where += ` AND n.id<` + bind(&args, f.Before)
	}
	if f.Status == "unread" {
		where += ` AND receipt.read_at IS NULL`
	}
	if f.Search != "" {
		pattern := bind(&args, "%"+f.Search+"%")
		where += ` AND (n.title ILIKE ` + pattern + ` OR (` + notificationSummarySQL + `) ILIKE ` + pattern + ` OR ` + targetSQL("scope") + ` ILIKE ` + pattern + `)`
	}
	rows, err := q.QueryContext(ctx, `SELECT `+notificationColumns()+` `+notificationFrom+` WHERE `+where+` ORDER BY n.id DESC LIMIT `+bind(&args, f.limit()+1), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		n, scanErr := scanNotification(rows)
		if scanErr != nil {
			return out, scanErr
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) Issue(ctx context.Context, actor auth.SessionUser, id int64) (Issue, error) {
	var target string
	var available bool
	i, err := scanIssue(s.db.QueryRowContext(ctx, `SELECT `+issueColumns+`,`+targetSQL("i")+`,`+resourceAvailableSQL("i")+` FROM issues i WHERE i.id=$3 AND `+resourcePredicate("i", 1, 2), actor.ID, string(actor.Role), id), &target, &available)
	i.Target = target
	i.ResourceAvailable = available
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return i, err
}
func (s *Store) Operation(ctx context.Context, actor auth.SessionUser, id int64) (OperationDetail, error) {
	d := OperationDetail{Attempts: []Attempt{}}
	var target string
	o, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+`,`+targetSQL("o")+` FROM operations o WHERE o.id=$3 AND `+resourcePredicate("o", 1, 2), actor.ID, string(actor.Role), id), &target)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	o.Target = target
	d.Operation = o
	rows, err := s.db.QueryContext(ctx, `SELECT id,operation_id,number,state,error_code,started_at,finished_at FROM operation_attempts WHERE operation_id=$1 ORDER BY number DESC`, id)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Attempt
		if err = rows.Scan(&a.ID, &a.OperationID, &a.Number, &a.State, &a.ErrorCode, &a.StartedAt, &a.FinishedAt); err != nil {
			return d, err
		}
		d.Attempts = append(d.Attempts, a)
	}
	return d, rows.Err()
}
func (s *Store) MarkAllNotificationsRead(ctx context.Context, actor auth.SessionUser, f Filter) error {
	if err := f.validate(); err != nil {
		return err
	}
	if !actor.Role.Valid() || actor.ID <= 0 {
		return ErrNotFound
	}
	args := []any{actor.ID, string(actor.Role)}
	where := NotificationVisibilitySQL("n", 1, 2) + resourceFilter("scope", f, &args)
	_, err := s.db.ExecContext(ctx, `INSERT INTO notification_receipts(notification_id,user_id) SELECT n.id,$1 `+notificationFrom+` WHERE `+where+` ON CONFLICT(notification_id,user_id) DO NOTHING`, args...)
	return err
}
func (s *Store) ArchiveNotification(ctx context.Context, actor auth.SessionUser, id int64) error {
	if !actor.Role.Valid() || actor.ID <= 0 {
		return ErrNotFound
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO notification_receipts(notification_id,user_id,archived_at) SELECT n.id,$1,now() FROM notifications n WHERE n.id=$3 AND `+NotificationVisibilitySQL("n", 1, 2)+` ON CONFLICT(notification_id,user_id) DO UPDATE SET archived_at=COALESCE(notification_receipts.archived_at,now())`, actor.ID, string(actor.Role), id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}
