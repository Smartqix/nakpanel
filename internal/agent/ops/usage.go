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
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	nginxTrafficRE  = regexp.MustCompile(`\[([^]]+)\].*"\s+[0-9]{3}\s+([0-9]+)\s+`)
)

type UsageCollector struct {
	homeRoot string
	logRoot  string
	mariaDSN string
}

func NewUsageCollector(homeRoot, logRoot, mariaDSN string) *UsageCollector {
	if homeRoot == "" {
		homeRoot = "/home"
	}
	if logRoot == "" {
		logRoot = "/var/log/nginx"
	}
	if mariaDSN == "" {
		mariaDSN = DefaultMariaDBDSN()
	}
	return &UsageCollector{homeRoot: filepath.Clean(homeRoot), logRoot: filepath.Clean(logRoot), mariaDSN: mariaDSN}
}

func (c *UsageCollector) CollectUsage(ctx context.Context, req types.CollectUsageReq) (types.CollectUsageResult, error) {
	if c == nil {
		return types.CollectUsageResult{}, errors.New("usage collector is not configured")
	}
	result := types.CollectUsageResult{Sites: make([]types.SiteUsageResult, 0, len(req.Sites))}
	for _, site := range req.Sites {
		if site.SiteID <= 0 || !usageUsernameRE.MatchString(site.Username) {
			return types.CollectUsageResult{}, errors.New("invalid site usage request")
		}
		logPath, err := c.safeLogPath(site.AccessLog)
		if err != nil {
			return types.CollectUsageResult{}, err
		}
		homeBytes, err := directoryBytes(ctx, filepath.Join(c.homeRoot, site.Username))
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure site %d home: %w", site.SiteID, err)
		}
		trafficBytes, cursor, err := readNginxTraffic(logPath, site.Cursor, req.PeriodStart)
		if err != nil {
			return types.CollectUsageResult{}, fmt.Errorf("measure site %d traffic: %w", site.SiteID, err)
		}
		result.Sites = append(result.Sites, types.SiteUsageResult{SiteID: site.SiteID, HomeBytes: homeBytes, TrafficBytes: trafficBytes, Cursor: cursor})
	}
	databaseBytes, err := c.databaseBytes(ctx, req.Databases)
	if err != nil {
		return types.CollectUsageResult{}, err
	}
	result.DatabaseBytes = databaseBytes
	return result, nil
}

func (c *UsageCollector) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	matches, err := filepath.Glob("/etc/php/*/fpm/pool.d")
	if err != nil {
		return types.RuntimeCapabilities{}, err
	}
	versions := make([]string, 0, len(matches))
	for _, match := range matches {
		version := filepath.Base(filepath.Dir(filepath.Dir(match)))
		if regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
			versions = append(versions, version)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	_, quotaErr := exec.LookPath("setquota")
	return types.RuntimeCapabilities{PHPVersions: versions, DiskQuota: quotaErr == nil}, nil
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

func readNginxTraffic(path string, cursor types.UsageCursor, periodStart time.Time) (int64, types.UsageCursor, error) {
	currentInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		if cursor.Inode != 0 {
			return 0, types.UsageCursor{}, errors.New("managed access log disappeared after collection started")
		}
		return 0, types.UsageCursor{}, nil
	}
	if err != nil {
		return 0, types.UsageCursor{}, err
	}
	device, inode := fileIdentity(currentInfo)
	var total int64
	if cursor.Inode != 0 && (cursor.Inode != inode || cursor.DeviceID != device) {
		rotated := path + ".1"
		info, statErr := os.Stat(rotated)
		if statErr != nil {
			return 0, types.UsageCursor{}, fmt.Errorf("traffic cursor gap: rotated access log is unavailable: %w", statErr)
		}
		rotatedDevice, rotatedInode := fileIdentity(info)
		if rotatedDevice != cursor.DeviceID || rotatedInode != cursor.Inode {
			return 0, types.UsageCursor{}, errors.New("traffic cursor gap: previous access log is no longer retained")
		}
		bytes, _, readErr := readNginxBytes(rotated, cursor.Offset, periodStart)
		if readErr != nil {
			return 0, types.UsageCursor{}, readErr
		}
		total += bytes
		cursor.Offset = 0
	}
	if cursor.Offset > currentInfo.Size() {
		rotated := path + ".1"
		info, statErr := os.Stat(rotated)
		if statErr != nil || info.Size() < cursor.Offset {
			return 0, types.UsageCursor{}, errors.New("traffic cursor gap: truncated access log cannot be recovered")
		}
		bytes, _, readErr := readNginxBytes(rotated, cursor.Offset, periodStart)
		if readErr != nil {
			return 0, types.UsageCursor{}, readErr
		}
		total += bytes
		cursor.Offset = 0
	}
	bytes, offset, err := readNginxBytes(path, cursor.Offset, periodStart)
	if err != nil {
		return 0, types.UsageCursor{}, err
	}
	total += bytes
	return total, types.UsageCursor{DeviceID: device, Inode: inode, Offset: offset}, nil
}

func readNginxBytes(path string, offset int64, periodStart time.Time) (int64, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, offset, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return 0, offset, err
	}
	var total int64
	position := offset
	reader := bufio.NewReaderSize(file, 64*1024)
	for {
		line, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, position, readErr
		}
		position += int64(len(line))
		match := nginxTrafficRE.FindSubmatch(line)
		if len(match) != 3 {
			continue
		}
		if !periodStart.IsZero() {
			loggedAt, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(match[1]))
			if err != nil || loggedAt.Before(periodStart) {
				continue
			}
		}
		value, err := strconv.ParseInt(string(match[2]), 10, 64)
		if err == nil && value > 0 {
			total += value
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
