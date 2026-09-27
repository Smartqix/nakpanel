package ops

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const statisticsMaxHTML = 2 << 20
const statisticsMaxInput = 128 << 20

var statisticsCombinedRE = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^]]+)\] "([^"\r\n]*)" ([0-9]{3}) ([0-9]+|-) "([^"\r\n]*)" "([^"\r\n]*)"$`)

type WebStatisticsGenerator struct {
	logRoot, reportRoot string
	mu                  sync.Mutex
	run                 func(context.Context, string, ...string) error
	now                 func() time.Time
}

func NewWebStatisticsGenerator() *WebStatisticsGenerator {
	return &WebStatisticsGenerator{logRoot: "/var/log/nginx", reportRoot: "/var/lib/nakpanel/web-statistics", now: time.Now,
		run: func(ctx context.Context, inputPath string, args ...string) error {
			input, err := os.Open(inputPath)
			if err != nil {
				return err
			}
			defer input.Close()
			bounded := []string{"--quiet", "--pipe", "--wait", "--collect", "--service-type=exec", "--property=MemoryMax=256M", "--property=CPUQuota=50%", "--property=TasksMax=16", "--property=RuntimeMaxSec=110", "--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict", "--property=ReadWritePaths=" + filepath.Dir(inputPath), "--setenv=LC_ALL=C", "--setenv=TZ=UTC", "/usr/bin/goaccess"}
			cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", append(bounded, args...)...)
			cmd.Stdin = input
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "TZ=UTC", "HOME=/nonexistent"}
			return cmd.Run()
		}}
}

func (g *WebStatisticsGenerator) WebStatisticsStatus(ctx context.Context) (types.WebStatisticsStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path, err := exec.LookPath("goaccess")
	if err != nil {
		return types.WebStatisticsStatus{}, nil
	}
	output, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return types.WebStatisticsStatus{}, nil
	}
	version := strings.SplitN(string(output), "\n", 2)[0]
	if len(version) > 128 {
		version = version[:128]
	}
	return types.WebStatisticsStatus{Available: true, Version: version}, nil
}

func validateStatisticsRequest(req types.WebStatisticsRequest) error {
	if req.SiteID <= 0 || req.Generation <= 0 || req.RetainGeneration < 0 || req.RetainGeneration >= req.Generation || !usageUsernameRE.MatchString(req.Username) || !usageDomainRE.MatchString(req.Domain) || req.RetentionDays < 1 || req.RetentionDays > 90 {
		return errors.New("invalid web statistics request")
	}
	return nil
}

func (g *WebStatisticsGenerator) GenerateWebStatistics(ctx context.Context, req types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	if err := validateStatisticsRequest(req); err != nil {
		return types.WebStatisticsResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return types.WebStatisticsResult{}, err
	}
	if _, err := os.Lstat(g.reportPath(req)); err == nil {
		result, err := g.ReadWebStatistics(ctx, req)
		result.HTML = nil
		return result, err
	}
	if err := os.MkdirAll(g.reportRoot, 0700); err != nil {
		return types.WebStatisticsResult{}, err
	}
	rootInfo, err := os.Lstat(g.reportRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return types.WebStatisticsResult{}, errors.New("unsafe statistics storage")
	}
	stage, err := os.MkdirTemp(g.reportRoot, ".generation-")
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	defer os.RemoveAll(stage)
	input, err := os.OpenFile(filepath.Join(stage, "access.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	now := g.now().UTC()
	start := now.AddDate(0, 0, -req.RetentionDays)
	summary := types.WebStatisticsSummary{GeneratedAt: now, PeriodStart: start, PeriodEnd: now}
	err = g.sanitizedInput(ctx, req, input, start, now, &summary)
	closeErr := input.Close()
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	if closeErr != nil {
		return types.WebStatisticsResult{}, closeErr
	}
	htmlPath, jsonPath := filepath.Join(stage, "report.html"), filepath.Join(stage, "report.json")
	if summary.Requests == 0 {
		if err = os.WriteFile(htmlPath, []byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Web statistics</title></head><body><h1>No requests in this period</h1></body></html>"), 0600); err != nil {
			return types.WebStatisticsResult{}, err
		}
	} else {
		args := []string{"--no-global-config", "--log-format=COMBINED", "--date-format=%d/%b/%Y", "--time-format=%T", "--no-query-string", "--no-ip-validation", "--no-progress", "--no-parsing-spinner", "--max-items=100", "--html-report-title=Web Statistics", "-o", htmlPath, "-o", jsonPath, "-"}
		if err = g.run(ctx, filepath.Join(stage, "access.log"), args...); err != nil {
			return types.WebStatisticsResult{}, errors.New("GoAccess generation failed")
		}
		data, readErr := readStatisticsFile(jsonPath, statisticsMaxHTML)
		if readErr != nil {
			return types.WebStatisticsResult{}, readErr
		}
		var report struct {
			General struct {
				UniqueVisitors int64 `json:"unique_visitors"`
			} `json:"general"`
		}
		if err = json.Unmarshal(data, &report); err != nil {
			return types.WebStatisticsResult{}, errors.New("invalid GoAccess summary")
		}
		summary.Visitors = report.General.UniqueVisitors
	}
	if _, err = readStatisticsFile(htmlPath, statisticsMaxHTML); err != nil {
		return types.WebStatisticsResult{}, err
	}
	data, _ := json.Marshal(summary)
	if err = os.WriteFile(filepath.Join(stage, "summary.json"), data, 0600); err != nil {
		return types.WebStatisticsResult{}, err
	}
	manifest, _ := json.Marshal(req)
	if err = os.WriteFile(filepath.Join(stage, "manifest.json"), manifest, 0600); err != nil {
		return types.WebStatisticsResult{}, err
	}
	_ = os.Remove(filepath.Join(stage, "access.log"))
	_ = os.Remove(jsonPath)
	final := g.reportPath(req)
	if _, err = os.Lstat(final); err == nil {
		return types.WebStatisticsResult{}, errors.New("statistics generation already exists")
	}
	if err = os.Rename(stage, final); err != nil {
		return types.WebStatisticsResult{}, err
	}
	// Preserve the immediately previous generation for last-good database reads.
	entries, _ := os.ReadDir(g.reportRoot)
	prefix := fmt.Sprintf("site-%d-generation-", req.SiteID)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		generation, parseErr := strconv.ParseInt(strings.TrimPrefix(entry.Name(), prefix), 10, 64)
		if parseErr == nil && generation < req.Generation && generation != req.RetainGeneration {
			_ = os.RemoveAll(filepath.Join(g.reportRoot, entry.Name()))
		}
	}
	return types.WebStatisticsResult{Summary: summary}, nil
}

func (g *WebStatisticsGenerator) reportPath(req types.WebStatisticsRequest) string {
	return filepath.Join(g.reportRoot, fmt.Sprintf("site-%d-generation-%d", req.SiteID, req.Generation))
}

func (g *WebStatisticsGenerator) ReadWebStatistics(ctx context.Context, req types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	if err := validateStatisticsRequest(req); err != nil {
		return types.WebStatisticsResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return types.WebStatisticsResult{}, err
	}
	root := g.reportPath(req)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return types.WebStatisticsResult{}, errors.New("report unavailable")
	}
	manifest, err := readStatisticsFile(filepath.Join(root, "manifest.json"), 4096)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	var saved types.WebStatisticsRequest
	if json.Unmarshal(manifest, &saved) != nil {
		return types.WebStatisticsResult{}, errors.New("invalid report identity")
	}
	saved.RetainGeneration = 0
	req.RetainGeneration = 0
	if saved != req {
		return types.WebStatisticsResult{}, errors.New("report identity or privacy settings changed")
	}
	data, err := readStatisticsFile(filepath.Join(root, "summary.json"), 4096)
	if err != nil {
		return types.WebStatisticsResult{}, err
	}
	var result types.WebStatisticsResult
	if err = json.Unmarshal(data, &result.Summary); err != nil {
		return result, err
	}
	result.HTML, err = readStatisticsFile(filepath.Join(root, "report.html"), statisticsMaxHTML)
	return result, err
}

func readStatisticsFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("report unavailable or exceeds size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("report exceeds size limit")
	}
	return data, err
}

func (g *WebStatisticsGenerator) sanitizedInput(ctx context.Context, req types.WebStatisticsRequest, out io.Writer, start, end time.Time, summary *types.WebStatisticsSummary) error {
	base := filepath.Join(g.logRoot, req.Username+"-"+strings.ReplaceAll(req.Domain, ".", "-")+".access.log")
	paths := []string{base}
	for i := 1; i <= 90; i++ {
		paths = append(paths, base+"."+strconv.Itoa(i), base+"."+strconv.Itoa(i)+".gz")
	}
	var total int64
	var parsed int64
	seen := map[string]bool{}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("unsafe access log")
		}
		dev, ino := fileIdentity(info)
		identity := fmt.Sprintf("%d:%d", dev, ino)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		var source io.Reader = io.LimitReader(f, info.Size())
		var gz *gzip.Reader
		if strings.HasSuffix(path, ".gz") {
			gz, err = gzip.NewReader(source)
			if err != nil {
				f.Close()
				return errors.New("invalid compressed access log")
			}
			source = gz
		}
		scanner := bufio.NewScanner(io.LimitReader(source, statisticsMaxInput-total+1))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			if err = ctx.Err(); err != nil {
				break
			}
			line := scanner.Text()
			total += int64(len(line) + 1)
			if total > statisticsMaxInput {
				err = errors.New("statistics input exceeds size limit")
				break
			}
			match := statisticsCombinedRE.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			date, parseErr := time.Parse("02/Jan/2006:15:04:05 -0700", match[2])
			if parseErr == nil {
				parsed++
			}
			if parseErr != nil || date.Before(start) || date.After(end) {
				continue
			}
			ip := net.ParseIP(match[1])
			if ip == nil {
				continue
			}
			if req.AnonymizeIP {
				if v4 := ip.To4(); v4 != nil {
					ip = v4.Mask(net.CIDRMask(24, 32))
				} else {
					ip = ip.Mask(net.CIDRMask(48, 128))
				}
			}
			request := strings.Fields(match[3])
			if len(request) != 3 {
				continue
			}
			request[1] = statisticsSafeURL(request[1], true)
			referrer := statisticsSafeURL(match[6], false)
			agent := match[7]
			if len(agent) > 1024 {
				agent = agent[:1024]
			}
			if _, err = fmt.Fprintf(out, "%s - - [%s] \"%s %s %s\" %s %s \"%s\" \"%s\"\n", ip.String(), date.UTC().Format("02/Jan/2006:15:04:05 -0700"), request[0], request[1], request[2], match[4], match[5], referrer, agent); err != nil {
				break
			}
			summary.Requests++
			n, _ := strconv.ParseInt(match[5], 10, 64)
			summary.Bandwidth += n
			status, _ := strconv.Atoi(match[4])
			if status >= 400 {
				summary.Errors++
			}
		}
		if err == nil {
			err = scanner.Err()
		}
		if gz != nil {
			gz.Close()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	if total > 0 && parsed == 0 {
		return errors.New("access log format is not supported")
	}
	return nil
}

func statisticsSafeURL(raw string, relative bool) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "-"
	}
	if u.Scheme != "http" && u.Scheme != "https" && !(relative && u.Scheme == "" && strings.HasPrefix(u.Path, "/")) {
		return "-"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	value := u.String()
	if len(value) > 4096 {
		return "-"
	}
	return value
}
