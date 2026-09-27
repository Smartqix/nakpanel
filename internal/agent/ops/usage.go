package ops

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	usageUsernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	usageDatabaseRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,47}$`)
	usageDomainRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	nginxTrafficRE  = regexp.MustCompile(`\[([^]]+)\].*"\s+([0-9]{3})\s+([0-9]+)\s+`)
)

type UsageCollector struct {
	homeRoot      string
	logRoot       string
	mariaDSN      string
	containerRoot string
	runtimeProbe  RuntimeCapabilityProbe
}

type UsageCollectorOption func(*UsageCollector)

func WithRuntimeCapabilityProbe(probe RuntimeCapabilityProbe) UsageCollectorOption {
	return func(collector *UsageCollector) {
		if probe != nil {
			collector.runtimeProbe = probe
		}
	}
}

func NewUsageCollector(homeRoot, logRoot, mariaDSN string, options ...UsageCollectorOption) *UsageCollector {
	if homeRoot == "" {
		homeRoot = "/home"
	}
	if logRoot == "" {
		logRoot = "/var/log/nginx"
	}
	if mariaDSN == "" {
		mariaDSN = DefaultMariaDBDSN()
	}
	collector := &UsageCollector{
		homeRoot: filepath.Clean(homeRoot), logRoot: filepath.Clean(logRoot), mariaDSN: mariaDSN,
		containerRoot: "/var/lib/nakpanel/containers", runtimeProbe: systemRuntimeCapabilityProbe{},
	}
	for _, option := range options {
		option(collector)
	}
	return collector
}

func (c *UsageCollector) CollectUsage(ctx context.Context, req types.CollectUsageReq) (types.CollectUsageResult, error) {
	if c == nil {
		return types.CollectUsageResult{}, errors.New("usage collector is not configured")
	}
	result := types.CollectUsageResult{Sites: make([]types.SiteUsageResult, 0, len(req.Sites))}
	accountUsers := make(map[string]struct{}, len(req.AccountUsernames)+len(req.Sites))
	for _, username := range req.AccountUsernames {
		if !usageUsernameRE.MatchString(username) {
			return types.CollectUsageResult{}, errors.New("invalid subscription account username")
		}
		accountUsers[username] = struct{}{}
	}
	for _, site := range req.Sites {
		if site.SiteID <= 0 || !usageUsernameRE.MatchString(site.Username) {
			return types.CollectUsageResult{}, errors.New("invalid site usage request")
		}
		accountUsers[site.Username] = struct{}{}
		logPath, err := c.safeLogPath(site.AccessLog)
		if err != nil {
			return types.CollectUsageResult{}, err
		}
		documentRoot := filepath.Join(c.homeRoot, site.Username)
		if strings.TrimSpace(site.Domain) != "" {
			domain := strings.ToLower(strings.TrimSpace(site.Domain))
			if !usageDomainRE.MatchString(domain) {
				return types.CollectUsageResult{}, errors.New("invalid site usage domain")
			}
			documentRoot = filepath.Join(c.homeRoot, site.Username, "domains", domain, "public_html")
		}
		homeBytes, err := directoryBytes(ctx, documentRoot)
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure site %d document root: %w", site.SiteID, err)
		}
		traffic, cursor, err := readNginxTraffic(logPath, site.Cursor, req.PeriodStart)
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure site %d traffic: %w", site.SiteID, err)
		}
		result.Sites = append(result.Sites, types.SiteUsageResult{
			SiteID: site.SiteID, HomeBytes: homeBytes, TrafficBytes: traffic.Bytes,
			RequestCount: traffic.Requests, ErrorCount: traffic.Errors, Cursor: cursor,
		})
	}
	for username := range accountUsers {
		bytes, err := directoryBytes(ctx, filepath.Join(c.homeRoot, username))
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure subscription account %q: %w", username, err)
		}
		result.AccountBytes += bytes
	}
	if req.SubscriptionID > 0 {
		containerBytes, err := directoryBytes(ctx, filepath.Join(c.containerRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "apps"))
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure subscription container storage: %w", err)
		}
		result.ContainerBytes = containerBytes
	}
	databaseBytes, err := c.databaseBytes(ctx, req.Databases)
	if err != nil {
		return types.CollectUsageResult{}, err
	}
	result.DatabaseBytes = databaseBytes
	return result, nil
}

func (c *UsageCollector) RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error) {
	probe := c.runtimeProbe
	if probe == nil {
		probe = systemRuntimeCapabilityProbe{}
	}
	runtimes, versions := probePHPRuntimes(ctx, probe)
	_, quotaErr := probe.LookPath("setquota")
	capabilities := types.RuntimeCapabilities{
		PHPVersions: versions, PHPRuntimes: runtimes, DiskQuota: quotaErr == nil,
		ApplicationHealth:   []string{types.ApplicationHealthHTTP, types.ApplicationHealthTCP},
		ApplicationPortFrom: 20000, ApplicationPortTo: 29999,
	}
	capabilities.ComposerAvailable, capabilities.ComposerVersion = probeToolVersion(ctx, probe, "composer", []string{"--no-plugins", "--no-scripts", "--version", "--no-ansi"}, composerVersionRE)
	capabilities.WPCLIAvailable, capabilities.WPCLIVersion = probeToolVersion(ctx, probe, "wp", []string{"--version", "--allow-root"}, wpCLIVersionRE)
	capabilities.GoAccessAvailable, capabilities.GoAccessVersion = probeToolVersion(ctx, probe, "goaccess", []string{"--version"}, goAccessVersionRE)
	if podman, err := probe.LookPath("podman"); err == nil {
		output, versionErr := probe.Run(ctx, podman, "--version")
		if versionErr == nil {
			capabilities.PodmanVersion = strings.TrimSpace(string(output))
		}
		_, newUIDErr := probe.LookPath("newuidmap")
		_, newGIDErr := probe.LookPath("newgidmap")
		_, subUIDErr := os.Stat("/etc/subuid")
		_, subGIDErr := os.Stat("/etc/subgid")
		capabilities.SubordinateIDSupport = newUIDErr == nil && newGIDErr == nil && subUIDErr == nil && subGIDErr == nil
		capabilities.RootlessPodman = capabilities.PodmanVersion != "" && capabilities.SubordinateIDSupport
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		capabilities.CgroupVersion = 2
	} else if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		capabilities.CgroupVersion = 1
	}
	return capabilities, nil
}

func (c *UsageCollector) safeLogPath(raw string) (string, error) {
	path := filepath.Clean(raw)
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.logRoot, path)
	}
	rel, err := filepath.Rel(c.logRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("access log must be inside the nginx log directory")
	}
	return path, nil
}

func directoryBytes(ctx context.Context, root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return total, err
}

type nginxUsageMeasurement struct {
	Bytes    int64
	Requests int64
	Errors   int64
}

func (m *nginxUsageMeasurement) add(other nginxUsageMeasurement) {
	m.Bytes += other.Bytes
	m.Requests += other.Requests
	m.Errors += other.Errors
}

func readNginxTraffic(path string, cursor types.UsageCursor, periodStart time.Time) (nginxUsageMeasurement, types.UsageCursor, error) {
	currentInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		if cursor.Inode != 0 {
			return nginxUsageMeasurement{}, types.UsageCursor{}, errors.New("managed access log disappeared after collection started")
		}
		return nginxUsageMeasurement{}, types.UsageCursor{}, nil
	}
	if err != nil {
		return nginxUsageMeasurement{}, types.UsageCursor{}, err
	}
	device, inode := fileIdentity(currentInfo)
	var total nginxUsageMeasurement
	if cursor.Inode != 0 && (cursor.Inode != inode || cursor.DeviceID != device) {
		rotated := path + ".1"
		info, statErr := os.Stat(rotated)
		if statErr != nil {
			return nginxUsageMeasurement{}, types.UsageCursor{}, fmt.Errorf("traffic cursor gap: rotated access log is unavailable: %w", statErr)
		}
		rotatedDevice, rotatedInode := fileIdentity(info)
		if rotatedDevice != cursor.DeviceID || rotatedInode != cursor.Inode {
			return nginxUsageMeasurement{}, types.UsageCursor{}, errors.New("traffic cursor gap: previous access log is no longer retained")
		}
		bytes, _, readErr := readNginxBytes(rotated, cursor.Offset, periodStart)
		if readErr != nil {
			return nginxUsageMeasurement{}, types.UsageCursor{}, readErr
		}
		total.add(bytes)
		cursor.Offset = 0
	}
	if cursor.Offset > currentInfo.Size() {
		rotated := path + ".1"
		info, statErr := os.Stat(rotated)
		if statErr != nil || info.Size() < cursor.Offset {
			return nginxUsageMeasurement{}, types.UsageCursor{}, errors.New("traffic cursor gap: truncated access log cannot be recovered")
		}
		bytes, _, readErr := readNginxBytes(rotated, cursor.Offset, periodStart)
		if readErr != nil {
			return nginxUsageMeasurement{}, types.UsageCursor{}, readErr
		}
		total.add(bytes)
		cursor.Offset = 0
	}
	bytes, offset, err := readNginxBytes(path, cursor.Offset, periodStart)
	if err != nil {
		return nginxUsageMeasurement{}, types.UsageCursor{}, err
	}
	total.add(bytes)
	return total, types.UsageCursor{DeviceID: device, Inode: inode, Offset: offset}, nil
}

func readNginxBytes(path string, offset int64, periodStart time.Time) (nginxUsageMeasurement, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nginxUsageMeasurement{}, offset, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nginxUsageMeasurement{}, offset, err
	}
	var total nginxUsageMeasurement
	position := offset
	reader := bufio.NewReaderSize(file, 64*1024)
	for {
		line, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nginxUsageMeasurement{}, position, readErr
		}
		position += int64(len(line))
		match := nginxTrafficRE.FindSubmatch(line)
		if len(match) != 4 {
			continue
		}
		if !periodStart.IsZero() {
			loggedAt, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(match[1]))
			if err != nil || loggedAt.Before(periodStart) {
				continue
			}
		}
		status, statusErr := strconv.Atoi(string(match[2]))
		value, err := strconv.ParseInt(string(match[3]), 10, 64)
		if err == nil && value > 0 {
			total.Bytes += value
		}
		if statusErr == nil {
			total.Requests++
			if status >= 400 {
				total.Errors++
			}
		}
	}
	return total, position, nil
}

func fileIdentity(info os.FileInfo) (int64, int64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return int64(stat.Dev), int64(stat.Ino)
}

func (c *UsageCollector) databaseBytes(ctx context.Context, names []string) (int64, error) {
	if len(names) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(names))
	marks := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !usageDatabaseRE.MatchString(name) {
			return 0, fmt.Errorf("invalid database name %q", name)
		}
		args = append(args, name)
		marks = append(marks, "?")
	}
	db, err := sql.Open("mysql", c.mariaDSN)
	if err != nil {
		return 0, fmt.Errorf("open mariadb usage connection: %w", err)
	}
	defer db.Close()
	var total sql.NullInt64
	query := `SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema IN (` + strings.Join(marks, ",") + `)`
	if err := db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("measure mariadb usage: %w", err)
	}
	return total.Int64, nil
}
