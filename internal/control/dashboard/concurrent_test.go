package dashboard

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/servertiming"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
)

type sleepingReader struct {
	fakeQuotaReader
	delay                    time.Duration
	siteErr, dbErr, phaseErr error
	mu                       sync.Mutex
	running, maximum         int
	scopeID                  int64
}

func (r *sleepingReader) wait() {
	r.mu.Lock()
	r.running++
	if r.running > r.maximum {
		r.maximum = r.running
	}
	r.mu.Unlock()
	time.Sleep(r.delay)
	r.mu.Lock()
	r.running--
	r.mu.Unlock()
}
func (r *sleepingReader) ListSites(context.Context) ([]store.Site, error) {
	r.wait()
	return []store.Site{{ID: 7, SubscriptionID: 22, Domain: "owned.test"}}, r.siteErr
}
func (r *sleepingReader) ListDatabases(context.Context) ([]store.Database, error) {
	r.wait()
	return []store.Database{{ID: 8, SubscriptionID: 22, DbName: "db"}}, r.dbErr
}
func (r *sleepingReader) ListSitesForUser(context.Context, int64) ([]Site, error) {
	r.wait()
	return []Site{{ID: 7, SubscriptionID: 22, Domain: "owned.test"}}, r.siteErr
}
func (r *sleepingReader) ListDatabasesForUser(context.Context, int64) ([]Database, error) {
	r.wait()
	return []Database{{ID: 8, SubscriptionID: 22, Name: "db"}}, r.dbErr
}
func (r *sleepingReader) GetPhase6(context.Context) (Phase6Data, error) {
	r.wait()
	return Phase6Data{Backups: []Backup{{ID: 9}}}, r.phaseErr
}
func (r *sleepingReader) GetPhase6ForUser(ctx context.Context, _ int64) (Phase6Data, error) {
	return r.GetPhase6(ctx)
}
func (r *sleepingReader) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	r.wait()
	return types.RuntimeCapabilities{}, nil
}
func (r *sleepingReader) ListSubscriptionServices(context.Context, auth.SessionUser) (SubscriptionServicesData, error) {
	r.wait()
	return SubscriptionServicesData{Tasks: []ScheduledTask{{ID: 10, SubscriptionID: 22}}}, nil
}
func (r *sleepingReader) ListSubscriptionServicesFor(_ context.Context, _ auth.SessionUser, id int64) (SubscriptionServicesData, error) {
	r.scopeID = id
	return SubscriptionServicesData{}, nil
}

func TestConcurrentDashboardMatchesSequential(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			newReader := func() *sleepingReader {
				return &sleepingReader{delay: 40 * time.Millisecond, fakeQuotaReader: fakeQuotaReader{subscriptions: []types.SubscriptionSummary{{ID: 22}}, customers: []types.Customer{{ID: 11}}}}
			}
			run := func(r *sleepingReader, limit int) (Data, time.Duration, string) {
				s := NewStore(r, WithScopedReader(r), WithPhase6Reader(r), WithQuotaReader(r), WithCapabilityReader(r))
				ctx := servertiming.WithRecorder(context.Background())
				start := time.Now()
				data, err := s.getDashboard(ctx, auth.SessionUser{ID: 1, Role: role}, limit)
				if err != nil {
					t.Fatal(err)
				}
				return data, time.Since(start), servertiming.Header(ctx)
			}
			sequential, serialTime, _ := run(newReader(), 1)
			reader := newReader()
			concurrent, parallelTime, header := run(reader, 4)
			if !reflect.DeepEqual(concurrent, sequential) {
				t.Fatalf("concurrent data differs:\n%#v\n%#v", concurrent, sequential)
			}
			if parallelTime >= serialTime*3/4 {
				t.Fatalf("concurrent %v vs sequential %v", parallelTime, serialTime)
			}
			if reader.maximum < 2 || reader.maximum > 4 {
				t.Fatalf("maximum concurrency %d", reader.maximum)
			}
			for _, name := range []string{"sites", "databases", "phase6", "services", "quotas", "subscriptions", "caps"} {
				if !strings.Contains(header, name+";dur=") {
					t.Errorf("missing timing %s: %s", name, header)
				}
			}
		})
	}
}
func TestConcurrentDashboardErrorSemantics(t *testing.T) {
	siteErr, dbErr := errors.New("sites failed"), errors.New("databases failed")
	reader := &sleepingReader{siteErr: siteErr, dbErr: dbErr, phaseErr: errors.New("phase6 failed")}
	s := NewStore(reader, WithPhase6Reader(reader))
	data, err := s.GetDashboard(context.Background(), auth.SessionUser{Role: auth.RoleAdmin})
	if err != siteErr || !reflect.DeepEqual(data, Data{}) {
		t.Fatalf("fatal: %#v %v", data, err)
	}
	reader.siteErr = nil
	_, err = s.GetDashboard(context.Background(), auth.SessionUser{Role: auth.RoleAdmin})
	if err != dbErr {
		t.Fatalf("database error: %v", err)
	}
	reader.dbErr = nil
	data, err = s.GetDashboard(context.Background(), auth.SessionUser{Role: auth.RoleAdmin})
	if err != nil || data.Phase6Error != "phase6 operations unavailable" || !reflect.DeepEqual(data.Phase6, Phase6Data{}) {
		t.Fatalf("nonfatal: %#v %v", data, err)
	}
}
func TestServiceScopeResolvesLoadedSitesAndNeverFallsBack(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		for _, tc := range []struct{ sub, site, want int64 }{{22, 0, 22}, {0, 7, 22}, {0, 999, 0}} {
			reader := &sleepingReader{}
			s := NewStore(reader, WithScopedReader(reader))
			_, err := s.GetDashboard(WithServiceScope(context.Background(), tc.sub, tc.site), auth.SessionUser{ID: 1, Role: role})
			if err != nil || reader.scopeID != tc.want {
				t.Fatalf("%s scope %+v: %d %v", role, tc, reader.scopeID, err)
			}
		}
	}
}
