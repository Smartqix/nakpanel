package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	defaultServerAdminCommandTimeout   = 5 * time.Second
	defaultServerAdminInventoryTimeout = 30 * time.Second
	defaultServerAdminOutputLimit      = 256 * 1024
	maxServerAdminOutputLimit          = 1024 * 1024
	serverAdminFileLimit               = 256 * 1024
)

var (
	ErrServerAdminRegistryID  = errors.New("unknown server administration registry id")
	ErrServerAdminOutputLimit = errors.New("server administration command output exceeded the limit")
)

// ServerAdminFileReader exists to make fixed, bounded host file reads
// independently testable. Caller-controlled paths never reach this interface.
type ServerAdminFileReader interface {
	ReadFile(path string, maxBytes int64) ([]byte, error)
}

type boundedServerAdminFileReader struct{}

func (boundedServerAdminFileReader) ReadFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrServerAdminOutputLimit
	}
	return data, nil
}

type ServerAdminInspectorOptions struct {
	Runner           CommandRunner
	FileReader       ServerAdminFileReader
	Now              func() time.Time
	CommandTimeout   time.Duration
	InventoryTimeout time.Duration
	MaxCommandOutput int
}

// ServerAdminInspector performs read-only operations from fixed registries.
// It intentionally has no generic command, path, unit, PHP version, or
// journal-expression entry point.
type ServerAdminInspector struct {
	runner           CommandRunner
	files            ServerAdminFileReader
	now              func() time.Time
	commandTimeout   time.Duration
	inventoryTimeout time.Duration
	maxOutput        int
}

type managedServiceDescriptor struct {
	id             string
	displayName    string
	unit           string
	componentID    string
	allowedActions []string
}

type phpHandlerDescriptor struct {
	id        string
	version   string
	cliBinary string
	fpmBinary string
	serviceID string
	unit      string
}

type hostInspection struct {
	hostname         string
	operatingSystem  string
	kernel           string
	architecture     string
	uptimeSeconds    int64
	loadAverage      []float64
	cpuCount         int
	memory           types.MemoryInventory
	errorDescription string
}

var managedServiceDescriptors = []managedServiceDescriptor{
	{id: "panel", displayName: "Nakpanel", unit: "nakpanel.service", componentID: "panel", allowedActions: []string{"restart"}},
	{id: "agent", displayName: "Nakpanel agent", unit: "nakpanel-agent.service", componentID: "agent", allowedActions: []string{"restart"}},
	{id: "web", displayName: "nginx", unit: "nginx.service", componentID: "nginx", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "dns", displayName: "BIND", unit: "bind9.service", componentID: "bind", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "mariadb", displayName: "MariaDB", unit: "mariadb.service", componentID: "mariadb", allowedActions: []string{"restart", "start", "stop"}},
	{id: "postgresql", displayName: "PostgreSQL", unit: "postgresql.service", componentID: "postgresql", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "mail", displayName: "Stalwart Mail", unit: "stalwart-mail.service", componentID: "stalwart", allowedActions: []string{"restart", "start", "stop"}},
	{id: "podman", displayName: "Podman", unit: "podman.service", componentID: "podman", allowedActions: []string{"restart", "start", "stop"}},
	{id: "time_sync", displayName: "systemd-timesyncd", unit: "systemd-timesyncd.service", componentID: "time", allowedActions: []string{"restart", "start", "stop"}},
	{id: "php-8.1", displayName: "PHP 8.1 FPM", unit: "php8.1-fpm.service", componentID: "php_81", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "php-8.2", displayName: "PHP 8.2 FPM", unit: "php8.2-fpm.service", componentID: "php_82", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "php-8.3", displayName: "PHP 8.3 FPM", unit: "php8.3-fpm.service", componentID: "php_83", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "php-8.4", displayName: "PHP 8.4 FPM", unit: "php8.4-fpm.service", componentID: "php_84", allowedActions: []string{"reload", "restart", "start", "stop"}},
	{id: "php-8.5", displayName: "PHP 8.5 FPM", unit: "php8.5-fpm.service", componentID: "php_85", allowedActions: []string{"reload", "restart", "start", "stop"}},
}

var phpHandlerDescriptors = []phpHandlerDescriptor{
	{id: "php81", version: "8.1", cliBinary: "/usr/bin/php8.1", fpmBinary: "/usr/sbin/php-fpm8.1", serviceID: "php-8.1", unit: "php8.1-fpm.service"},
	{id: "php82", version: "8.2", cliBinary: "/usr/bin/php8.2", fpmBinary: "/usr/sbin/php-fpm8.2", serviceID: "php-8.2", unit: "php8.2-fpm.service"},
	{id: "php83", version: "8.3", cliBinary: "/usr/bin/php8.3", fpmBinary: "/usr/sbin/php-fpm8.3", serviceID: "php-8.3", unit: "php8.3-fpm.service"},
	{id: "php84", version: "8.4", cliBinary: "/usr/bin/php8.4", fpmBinary: "/usr/sbin/php-fpm8.4", serviceID: "php-8.4", unit: "php8.4-fpm.service"},
	{id: "php85", version: "8.5", cliBinary: "/usr/bin/php8.5", fpmBinary: "/usr/sbin/php-fpm8.5", serviceID: "php-8.5", unit: "php8.5-fpm.service"},
}

var filesystemDescriptors = []struct {
	path string
}{
	{path: "/"},
	{path: "/home"},
	{path: "/var/lib/nakpanel"},
}

var protectedPHPExtensions = map[string]struct{}{
	"date": {}, "filter": {}, "hash": {}, "json": {}, "openssl": {},
	"pcre": {}, "session": {}, "spl": {}, "standard": {},
}

var listenerServicePorts = map[int]string{
	22: "ssh", 25: "mail", 53: "dns", 80: "web", 110: "mail",
	143: "mail", 443: "web", 465: "mail", 587: "mail", 993: "mail",
	995: "mail", 3306: "mariadb", 5432: "postgresql", 7443: "panel",
}

func NewServerAdminInspector(opts ServerAdminInspectorOptions) *ServerAdminInspector {
	maxOutput := opts.MaxCommandOutput
	if maxOutput <= 0 {
		maxOutput = defaultServerAdminOutputLimit
	}
	if maxOutput > maxServerAdminOutputLimit {
		maxOutput = maxServerAdminOutputLimit
	}
	commandTimeout := opts.CommandTimeout
	if commandTimeout <= 0 || commandTimeout > 30*time.Second {
		commandTimeout = defaultServerAdminCommandTimeout
	}
	inventoryTimeout := opts.InventoryTimeout
	if inventoryTimeout <= 0 || inventoryTimeout > 2*time.Minute {
		inventoryTimeout = defaultServerAdminInventoryTimeout
	}
	runner := opts.Runner
	if runner == nil {
		runner = boundedServerAdminExecRunner{maxOutput: maxOutput}
	}
	files := opts.FileReader
	if files == nil {
		files = boundedServerAdminFileReader{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &ServerAdminInspector{
		runner: runner, files: files, now: now, commandTimeout: commandTimeout,
		inventoryTimeout: inventoryTimeout, maxOutput: maxOutput,
	}
}

func (i *ServerAdminInspector) InspectServer(ctx context.Context) (types.ServerInventory, error) {
	if i == nil {
		return types.ServerInventory{}, errors.New("server administration inspector is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, i.inventoryTimeout)
	defer cancel()

	checkedAt := i.now().UTC()
	host := i.inspectHost(ctx)
	result := types.ServerInventory{
		Hostname: host.hostname, OperatingSystem: host.operatingSystem,
		Kernel: host.kernel, Architecture: host.architecture,
		UptimeSeconds: host.uptimeSeconds, LoadAverage: host.loadAverage,
		CPUCount: host.cpuCount, Memory: host.memory,
		Status: types.ServerStateHealthy, CheckedAt: checkedAt,
	}
	var problems []string
	if host.errorDescription != "" {
		problems = append(problems, host.errorDescription)
	}

	result.Filesystems = i.inspectFilesystems(ctx)
	if len(result.Filesystems) == 0 {
		problems = append(problems, "filesystem inventory unavailable")
	}
	listeners, err := i.inspectListeners(ctx)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		result.Listeners = listeners
	}
	timeState, err := i.InspectTime(ctx)
	if err != nil {
		problems = append(problems, err.Error())
	} else if timeState.LastError != "" {
		problems = append(problems, timeState.LastError)
	}
	result.Time = timeState

	services, err := i.InspectManagedServices(ctx, types.InspectManagedServicesReq{})
	if err != nil {
		problems = append(problems, err.Error())
	}
	result.Services = services
	result.Components = componentsFromServices(services)
	for _, service := range services {
		if service.LastError != "" {
			problems = append(problems, service.DisplayName+": "+service.LastError)
		} else if service.Available && service.ActiveState == "failed" {
			problems = append(problems, service.DisplayName+": service failed")
		}
	}

	phpHandlers, err := i.InspectPHP(ctx)
	if err != nil {
		problems = append(problems, err.Error())
	}
	result.PHPHandlers = phpHandlers
	for _, handler := range phpHandlers {
		if handler.LastError != "" && handler.State != "not_installed" {
			problems = append(problems, "PHP "+handler.Version+": "+handler.LastError)
		}
		result.Components = append(result.Components, types.ComponentState{
			ID:   "php_" + strings.ReplaceAll(handler.Version, ".", ""),
			Name: "PHP " + handler.Version + " FPM", Version: handler.FullVersion,
			Installed: handler.State != "not_installed",
			State:     handler.State,
		})
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(problems) > 0 {
		result.Status = types.ServerStateWarning
		result.LastError = strings.Join(problems, "; ")
	}
	return result, nil
}

func (i *ServerAdminInspector) InspectManagedServices(ctx context.Context, req types.InspectManagedServicesReq) ([]types.ManagedService, error) {
	if i == nil {
		return nil, errors.New("server administration inspector is not configured")
	}
	descriptors, err := selectManagedServiceDescriptors(req.ServiceIDs)
	if err != nil {
		return nil, err
	}
	result := make([]types.ManagedService, 0, len(descriptors))
	for _, descriptor := range descriptors {
		service, inspectErr := i.inspectSystemdUnit(ctx, descriptor)
		if inspectErr != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			service.LastError = inspectErr.Error()
		}
		result = append(result, service)
	}
	return result, nil
}

func (i *ServerAdminInspector) InspectTime(ctx context.Context) (types.TimeState, error) {
	if i == nil {
		return types.TimeState{}, errors.New("server administration inspector is not configured")
	}
	checkedAt := i.now()
	result := types.TimeState{
		LocalTime: checkedAt, UniversalTime: checkedAt.UTC(), CheckedAt: checkedAt.UTC(),
	}
	output, err := i.run(ctx, "timedatectl", "show", "--no-pager",
		"--property=Timezone", "--property=LocalRTC", "--property=NTP",
		"--property=NTPSynchronized", "--property=CanNTP",
		"--property=RuntimeNTPServers", "--property=SystemNTPServers")
	if err != nil {
		result.LastError = "system time inspection unavailable"
		return result, fmt.Errorf("inspect system time: %w", err)
	}
	values := parseServerAdminProperties(output)
	result.Timezone = values["Timezone"]
	if location, locationErr := time.LoadLocation(result.Timezone); locationErr == nil {
		result.LocalTime = checkedAt.In(location)
	}
	result.RTCLocal = parseServerAdminBool(values["LocalRTC"])
	result.SyncEnabled = parseServerAdminBool(values["NTP"])
	result.Synchronized = parseServerAdminBool(values["NTPSynchronized"])
	result.Available = result.Timezone != ""
	result.Source = firstNonempty(values["RuntimeNTPServers"], values["SystemNTPServers"])
	if parseServerAdminBool(values["CanNTP"]) {
		result.Backend = "systemd-timesyncd"
	}
	if !result.Available {
		result.LastError = "timedatectl did not return a timezone"
	}
	return result, nil
}

func (i *ServerAdminInspector) InspectPHP(ctx context.Context) ([]types.PHPHandlerState, error) {
	if i == nil {
		return nil, errors.New("server administration inspector is not configured")
	}
	checkedAt := i.now().UTC()
	defaultVersion := i.inspectDefaultPHPVersion(ctx)
	result := make([]types.PHPHandlerState, 0, len(phpHandlerDescriptors))
	for _, descriptor := range phpHandlerDescriptors {
		handler, err := i.inspectPHPHandler(ctx, descriptor, checkedAt)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			handler.LastError = err.Error()
			if handler.State != "not_installed" {
				handler.State = types.ServerStateUnknown
			}
		}
		handler.Default = handler.Version == defaultVersion
		result = append(result, handler)
	}
	return result, nil
}

func selectManagedServiceDescriptors(ids []string) ([]managedServiceDescriptor, error) {
	if len(ids) == 0 {
		return append([]managedServiceDescriptor(nil), managedServiceDescriptors...), nil
	}
	if len(ids) > len(managedServiceDescriptors) {
		return nil, errors.New("too many managed service ids")
	}
	registry := make(map[string]managedServiceDescriptor, len(managedServiceDescriptors))
	for _, descriptor := range managedServiceDescriptors {
		registry[descriptor.id] = descriptor
	}
	seen := make(map[string]bool, len(ids))
	result := make([]managedServiceDescriptor, 0, len(ids))
	for _, id := range ids {
		descriptor, ok := registry[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrServerAdminRegistryID, id)
		}
		if !seen[id] {
			seen[id] = true
			result = append(result, descriptor)
		}
	}
	return result, nil
}

func (i *ServerAdminInspector) inspectHost(ctx context.Context) hostInspection {
	result := hostInspection{architecture: runtime.GOARCH, cpuCount: runtime.NumCPU()}
	var problems []string
	if data, err := i.files.ReadFile("/etc/hostname", 4096); err == nil {
		result.hostname = strings.TrimSpace(string(data))
	} else if output, runErr := i.run(ctx, "hostname"); runErr == nil {
		result.hostname = strings.TrimSpace(string(output))
	} else {
		problems = append(problems, "hostname unavailable")
	}
	if data, err := i.files.ReadFile("/etc/os-release", serverAdminFileLimit); err == nil {
		values := parseServerAdminOSRelease(data)
		result.operatingSystem = firstNonempty(values["PRETTY_NAME"], values["NAME"])
	} else {
		problems = append(problems, "operating system release unavailable")
	}
	if output, err := i.run(ctx, "uname", "-r"); err == nil {
		result.kernel = strings.TrimSpace(string(output))
	} else {
		problems = append(problems, "kernel release unavailable")
	}
	if data, err := i.files.ReadFile("/proc/uptime", 4096); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptime, _ := strconv.ParseFloat(fields[0], 64)
			if uptime >= 0 {
				result.uptimeSeconds = int64(uptime)
			}
		}
	} else {
		problems = append(problems, "uptime unavailable")
	}
	if data, err := i.files.ReadFile("/proc/loadavg", 4096); err == nil {
		fields := strings.Fields(string(data))
		for index := 0; index < 3 && index < len(fields); index++ {
			if value, parseErr := strconv.ParseFloat(fields[index], 64); parseErr == nil {
				result.loadAverage = append(result.loadAverage, value)
			}
		}
	} else {
		problems = append(problems, "load average unavailable")
	}
	if data, err := i.files.ReadFile("/proc/meminfo", serverAdminFileLimit); err == nil {
		values := parseServerAdminMemory(data)
		result.memory = types.MemoryInventory{
			TotalBytes: values["MemTotal"], AvailableBytes: values["MemAvailable"],
			SwapTotalBytes: values["SwapTotal"], SwapFreeBytes: values["SwapFree"],
		}
		if result.memory.TotalBytes <= 0 {
			problems = append(problems, "memory total unavailable")
		}
	} else {
		problems = append(problems, "memory details unavailable")
	}
	result.errorDescription = strings.Join(problems, "; ")
	return result
}

func (i *ServerAdminInspector) inspectFilesystems(ctx context.Context) []types.FilesystemState {
	result := make([]types.FilesystemState, 0, len(filesystemDescriptors))
	seen := make(map[string]bool)
	for _, descriptor := range filesystemDescriptors {
		output, err := i.run(ctx, "df", "--block-size=1",
			"--output=source,size,avail,itotal,iavail,target", descriptor.path)
		if err != nil {
			continue
		}
		lines := nonemptyServerAdminLines(output)
		if len(lines) < 2 {
			continue
		}
		fields := strings.Fields(lines[len(lines)-1])
		if len(fields) < 6 {
			continue
		}
		entry := types.FilesystemState{Filesystem: fields[0], Mountpoint: strings.Join(fields[5:], " ")}
		entry.TotalBytes, _ = strconv.ParseInt(fields[1], 10, 64)
		entry.AvailableBytes, _ = strconv.ParseInt(fields[2], 10, 64)
		entry.TotalInodes, _ = strconv.ParseInt(fields[3], 10, 64)
		entry.AvailableInodes, _ = strconv.ParseInt(fields[4], 10, 64)
		if entry.Mountpoint == "" || entry.TotalBytes <= 0 || entry.AvailableBytes < 0 ||
			entry.TotalInodes < 0 || entry.AvailableInodes < 0 || seen[entry.Mountpoint] {
			continue
		}
		seen[entry.Mountpoint] = true
		result = append(result, entry)
	}
	return result
}

func (i *ServerAdminInspector) inspectListeners(ctx context.Context) ([]types.ListenerState, error) {
	output, err := i.run(ctx, "ss", "-H", "-lntu")
	if err != nil {
		return nil, fmt.Errorf("listening socket inspection unavailable")
	}
	seen := make(map[string]types.ListenerState)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		address, port, ok := splitServerAdminListenerAddress(fields[4])
		if !ok {
			continue
		}
		key := protocol + "\x00" + address + "\x00" + strconv.Itoa(port)
		seen[key] = types.ListenerState{
			ServiceID: listenerServicePorts[port], Protocol: protocol,
			Address: address, Port: port,
		}
		if len(seen) >= 512 {
			break
		}
	}
	result := make([]types.ListenerState, 0, len(seen))
	for _, listener := range seen {
		result = append(result, listener)
	}
	sort.Slice(result, func(a, b int) bool {
		if result[a].Port != result[b].Port {
			return result[a].Port < result[b].Port
		}
		if result[a].Protocol != result[b].Protocol {
			return result[a].Protocol < result[b].Protocol
		}
		return result[a].Address < result[b].Address
	})
	return result, nil
}

func (i *ServerAdminInspector) inspectSystemdUnit(ctx context.Context, descriptor managedServiceDescriptor) (types.ManagedService, error) {
	checkedAt := i.now().UTC()
	result := types.ManagedService{
		ID: descriptor.id, DisplayName: descriptor.displayName,
		AllowedActions: append([]string(nil), descriptor.allowedActions...), CheckedAt: checkedAt,
	}
	output, err := i.run(ctx, "systemctl", "show", "--no-pager",
		"--property=LoadState", "--property=ActiveState", "--property=SubState",
		"--property=UnitFileState", "--property=Result", "--property=MainPID",
		"--property=NRestarts", "--property=MemoryCurrent", "--property=CPUUsageNSec",
		"--property=ActiveEnterTimestampUSec", descriptor.unit)
	if err != nil {
		return result, fmt.Errorf("managed service %q inspection unavailable", descriptor.id)
	}
	values := parseServerAdminProperties(output)
	result.LoadState = values["LoadState"]
	result.ActiveState = values["ActiveState"]
	result.SubState = values["SubState"]
	result.UnitFileState = values["UnitFileState"]
	result.Result = values["Result"]
	result.MainPID = parseServerAdminInt(values["MainPID"])
	result.RestartCount = parseServerAdminInt(values["NRestarts"])
	result.MemoryBytes = parseServerAdminInt64(values["MemoryCurrent"])
	result.CPUUsageNSec = parseServerAdminInt64(values["CPUUsageNSec"])
	result.ActiveSince = parseSystemdTimestamp(values["ActiveEnterTimestampUSec"])
	result.Available = result.LoadState != "" && result.LoadState != "not-found"
	if !result.Available {
		result.AllowedActions = nil
	}
	return result, nil
}

func (i *ServerAdminInspector) inspectPHPHandler(ctx context.Context, descriptor phpHandlerDescriptor, checkedAt time.Time) (types.PHPHandlerState, error) {
	handler := types.PHPHandlerState{
		ID: descriptor.id, Version: descriptor.version, SAPI: "fpm-fcgi",
		ServiceID: descriptor.serviceID, State: "not_installed", CheckedAt: checkedAt,
	}
	versionOutput, versionErr := i.run(ctx, descriptor.cliBinary, "--version")
	service, serviceErr := i.inspectSystemdUnit(ctx, managedServiceDescriptor{
		id: descriptor.serviceID, displayName: "PHP " + descriptor.version + " FPM",
		unit: descriptor.unit, allowedActions: []string{"reload", "restart", "start", "stop"},
	})
	if versionErr != nil {
		if serviceErr != nil {
			handler.State = types.ServerStateUnknown
			handler.LastError = "PHP binary and FPM service are unavailable"
		} else if service.Available {
			handler.State = types.ServerStateUnknown
			handler.LastError = "PHP binary inspection is unavailable"
		}
		return handler, nil
	}
	handler.PackageSource = "system"
	handler.FullVersion = parseServerAdminPHPVersion(versionOutput)
	if handler.FullVersion == "" {
		handler.FullVersion = descriptor.version
	}
	if serviceErr == nil && !service.Available {
		// A CLI package can exist without the FPM SAPI. Nakpanel is FPM-only,
		// so do not present CLI modules or a missing FPM binary as a broken
		// hosting handler.
		handler.State = "not_installed"
		return handler, nil
	}
	switch {
	case serviceErr != nil:
		handler.State = types.ServerStateUnknown
	case service.ActiveState == "active":
		handler.State = "active"
	case service.ActiveState == "failed":
		handler.State = "failed"
	default:
		handler.State = "inactive"
	}
	moduleOutput, err := i.run(ctx, descriptor.cliBinary, "-m")
	if err != nil {
		return handler, fmt.Errorf("PHP %s extension inspection unavailable", descriptor.version)
	}
	for _, extension := range parseServerAdminPHPExtensions(moduleOutput) {
		_, protected := protectedPHPExtensions[strings.ToLower(extension)]
		handler.Extensions = append(handler.Extensions, types.PHPExtensionState{
			Name: extension, Installed: true, Enabled: true, Protected: protected,
		})
	}
	if _, err := i.run(ctx, descriptor.fpmBinary, "-tt"); err != nil {
		handler.ConfigValid = false
		return handler, fmt.Errorf("PHP %s FPM configuration validation failed", descriptor.version)
	}
	handler.ConfigValid = true
	return handler, nil
}

func (i *ServerAdminInspector) inspectDefaultPHPVersion(ctx context.Context) string {
	output, err := i.run(ctx, "/usr/bin/php", "--version")
	if err != nil {
		return ""
	}
	fullVersion := parseServerAdminPHPVersion(output)
	parts := strings.Split(fullVersion, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func (i *ServerAdminInspector) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if i == nil || i.runner == nil {
		return nil, errors.New("server administration command runner is not configured")
	}
	commandCtx, cancel := context.WithTimeout(ctx, i.commandTimeout)
	defer cancel()
	output, err := i.runner.Run(commandCtx, name, args...)
	if len(output) > i.maxOutput {
		return nil, ErrServerAdminOutputLimit
	}
	if commandCtx.Err() != nil {
		return nil, commandCtx.Err()
	}
	if err != nil {
		detail := cleanServerAdminDiagnostic(output)
		if detail != "" {
			return nil, fmt.Errorf("%w: %s", err, detail)
		}
		return nil, err
	}
	return output, nil
}

type boundedServerAdminExecRunner struct {
	maxOutput int
}

func (r boundedServerAdminExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	output := &boundedServerAdminBuffer{limit: r.maxOutput}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.truncated {
		return output.Bytes(), ErrServerAdminOutputLimit
	}
	return output.Bytes(), err
}

type boundedServerAdminBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedServerAdminBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = b.buffer.Write(data[:remaining])
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return len(data), nil
}

func (b *boundedServerAdminBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func componentsFromServices(services []types.ManagedService) []types.ComponentState {
	descriptorByID := make(map[string]managedServiceDescriptor, len(managedServiceDescriptors))
	for _, descriptor := range managedServiceDescriptors {
		descriptorByID[descriptor.id] = descriptor
	}
	result := make([]types.ComponentState, 0, len(services))
	for _, service := range services {
		descriptor := descriptorByID[service.ID]
		state := service.ActiveState
		if service.LastError != "" {
			state = types.ServerStateUnknown
		} else if !service.Available {
			state = "not_installed"
		}
		result = append(result, types.ComponentState{
			ID: descriptor.componentID, Name: service.DisplayName,
			Installed: service.Available, State: state,
		})
	}
	return result
}

func parseServerAdminProperties(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "" {
			result[key] = strings.TrimSpace(value)
		}
	}
	return result
}

func parseServerAdminBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "yes" || value == "true" || value == "1"
}

func parseServerAdminOSRelease(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func parseServerAdminMemory(data []byte) map[string]int64 {
	result := make(map[string]int64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && value >= 0 && value <= int64(^uint64(0)>>1)/1024 {
			result[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	return result
}

func parseServerAdminPHPVersion(data []byte) string {
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if !strings.HasPrefix(line, "PHP ") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	for _, r := range fields[1] {
		if (r < '0' || r > '9') && r != '.' && r != '-' && r != '+' {
			return ""
		}
	}
	return fields[1]
}

func parseServerAdminPHPExtensions(data []byte) []string {
	seen := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || (strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]")) ||
			len(name) > 128 || strings.ContainsAny(name, "\x00\r\t") {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; !exists {
			seen[key] = name
		}
		if len(seen) >= 512 {
			break
		}
	}
	result := make([]string, 0, len(seen))
	for _, name := range seen {
		result = append(result, name)
	}
	sort.Slice(result, func(a, b int) bool {
		return strings.ToLower(result[a]) < strings.ToLower(result[b])
	})
	return result
}

func splitServerAdminListenerAddress(value string) (string, int, bool) {
	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	address := strings.TrimSpace(value[:index])
	address = strings.TrimPrefix(address, "[")
	address = strings.TrimSuffix(address, "]")
	if address == "" {
		address = "*"
	}
	return address, port, true
}

func parseServerAdminInt(value string) int {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil || parsed < 0 {
		return 0
	}
	return int(parsed)
}

func parseServerAdminInt64(value string) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func parseSystemdTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return time.Time{}
	}
	if numeric, err := strconv.ParseInt(value, 10, 64); err == nil && numeric > 0 {
		return time.UnixMicro(numeric).UTC()
	}
	for _, layout := range []string{
		"Mon 2006-01-02 15:04:05 MST", "Mon 2006-01-02 15:04:05.999999 MST",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func nonemptyServerAdminLines(data []byte) []string {
	result := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func cleanServerAdminDiagnostic(data []byte) string {
	value := strings.Join(strings.Fields(string(data)), " ")
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
