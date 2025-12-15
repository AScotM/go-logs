package main

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxDays      = 30
	defaultTruncate     = 80
	defaultLinesPerSvc  = 5
	defaultMaxFileSize  = 100
	defaultMaxEntries   = 100000
)

var (
	defaultLogPaths = []string{
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/system.log",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
		"/var/log/dmesg",
		"/var/log/debug",
	}

	monthMap = map[string]int{
		"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
		"May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
		"Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
	}

	errorIndicators = []string{
		"error", "failed", "failure", "exception",
		"critical", "panic", "fatal", "segfault",
	}
)

type LogLevel string

const (
	LevelEmergency LogLevel = "emerg"
	LevelAlert     LogLevel = "alert"
	LevelCritical  LogLevel = "crit"
	LevelError     LogLevel = "err"
	LevelWarning   LogLevel = "warn"
	LevelNotice    LogLevel = "notice"
	LevelInfo      LogLevel = "info"
	LevelDebug     LogLevel = "debug"
)

func (l LogLevel) IsError() bool {
	switch l {
	case LevelEmergency, LevelAlert, LevelCritical, LevelError:
		return true
	default:
		return false
	}
}

func (l LogLevel) Color() string {
	switch l {
	case LevelEmergency, LevelAlert, LevelCritical:
		return "\033[1;31m"
	case LevelError:
		return "\033[31m"
	case LevelWarning:
		return "\033[33m"
	case LevelInfo:
		return "\033[32m"
	case LevelNotice:
		return "\033[36m"
	case LevelDebug:
		return "\033[34m"
	default:
		return "\033[0m"
	}
}

func ParseLogLevel(s string) (LogLevel, bool) {
	s = strings.ToLower(s)
	switch s {
	case "emerg", "emergency":
		return LevelEmergency, true
	case "alert":
		return LevelAlert, true
	case "crit", "critical":
		return LevelCritical, true
	case "err", "error":
		return LevelError, true
	case "warn", "warning":
		return LevelWarning, true
	case "notice":
		return LevelNotice, true
	case "info":
		return LevelInfo, true
	case "debug":
		return LevelDebug, true
	default:
		return "", false
	}
}

type Config struct {
	MaxDays         int
	TruncateLength  int
	ShowFullLines   bool
	WrapLines       bool
	MaxLinesPerSvc  int
	ColorOutput     bool
	Verbose         bool
	EnableAnalysis  bool
	MaxFileSizeMB   int
	DetectRsyslog   bool
	MaxMemoryEntries int
}

func DefaultConfig() Config {
	return Config{
		MaxDays:         defaultMaxDays,
		TruncateLength:  defaultTruncate,
		ShowFullLines:   false,
		WrapLines:       false,
		MaxLinesPerSvc:  defaultLinesPerSvc,
		ColorOutput:     true,
		Verbose:         false,
		EnableAnalysis:  false,
		MaxFileSizeMB:   defaultMaxFileSize,
		DetectRsyslog:   true,
		MaxMemoryEntries: defaultMaxEntries,
	}
}

type LogEntry struct {
	Timestamp time.Time
	Service   string
	Message   string
	Level     *LogLevel
	Host      *string
	PID       *string
	RawLine   string
}

func (e *LogEntry) IsError() bool {
	if e.Level != nil && (*e.Level).IsError() {
		return true
	}
	
	msgLower := strings.ToLower(e.Message)
	for _, indicator := range errorIndicators {
		if strings.Contains(msgLower, indicator) {
			return true
		}
	}
	return false
}

type LogParser struct {
	CurrentYear int
	LastMonth   *int
	LastYear    int
	Patterns    []LogPattern
	Verbose     bool
}

type LogPattern struct {
	Regex       *regexp.Regexp
	Name        string
	Description string
}

func NewLogParser(currentYear int, verbose bool, detectRsyslog bool) *LogParser {
	parser := &LogParser{
		CurrentYear: currentYear,
		LastYear:    currentYear,
		Verbose:     verbose,
	}
	
	parser.compilePatterns(detectRsyslog)
	return parser
}

func (p *LogParser) compilePatterns(detectRsyslog bool) {
	patterns := []LogPattern{
		{
			Name:        "traditional",
			Description: "Traditional syslog format",
			Regex: regexp.MustCompile(`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$`),
		},
		{
			Name:        "simple",
			Description: "Simple syslog format",
			Regex: regexp.MustCompile(`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*(?P<message>.+)$`),
		},
		{
			Name:        "iso8601",
			Description: "ISO 8601 timestamp format",
			Regex: regexp.MustCompile(`^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$`),
		},
	}
	
	if detectRsyslog && p.detectRsyslogVersion() >= 8 {
		patterns = append(patterns, LogPattern{
			Name:        "enhanced",
			Description: "Enhanced syslog format",
			Regex: regexp.MustCompile(`^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\d+-:]+)\s+(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:?\s+(?:\[(?P<level>\w+)\]\s+)?(?P<message>.+)$`),
		})
	}
	
	p.Patterns = patterns
}

func (p *LogParser) detectRsyslogVersion() int {
	cmd := exec.Command("rsyslogd", "-v")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "rsyslogd") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, ".") {
					versionParts := strings.Split(part, ".")
					if len(versionParts) > 0 {
						major, err := strconv.Atoi(versionParts[0])
						if err == nil {
							return major
						}
					}
				}
			}
		}
	}
	return 0
}

func (p *LogParser) ParseLine(line string, now time.Time, cutoff time.Time) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if len(line) < 20 {
		return nil, nil
	}
	
	for _, pattern := range p.getLikelyPatterns(line) {
		matches := pattern.Regex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		
		timestamp, err := p.extractTimestamp(matches, pattern.Regex.SubexpNames(), pattern.Name)
		if err != nil {
			if p.Verbose {
				log.Printf("Failed to extract timestamp: %v", err)
			}
			continue
		}
		
		if timestamp.Before(cutoff) || timestamp.After(now.Add(24*time.Hour)) {
			return nil, nil
		}
		
		entry := &LogEntry{
			Timestamp: timestamp,
			RawLine:   line,
		}
		
		for i, name := range pattern.Regex.SubexpNames() {
			if i == 0 || name == "" {
				continue
			}
			value := matches[i]
			
			switch name {
			case "service":
				entry.Service = value
			case "message":
				entry.Message = value
			case "level":
				if level, ok := ParseLogLevel(value); ok {
					entry.Level = &level
				}
			case "host":
				host := value
				entry.Host = &host
			case "pid":
				pid := value
				entry.PID = &pid
			}
		}
		
		if entry.Service == "" {
			entry.Service = "unknown"
		}
		
		return entry, nil
	}
	
	return nil, nil
}

func (p *LogParser) getLikelyPatterns(line string) []LogPattern {
	if len(line) >= 3 {
		month := line[0:3]
		if _, ok := monthMap[month]; ok {
			return p.Patterns[0:2]
		}
	}
	
	if len(line) >= 10 && line[4] == '-' && line[7] == '-' {
		return p.Patterns[2:]
	}
	
	return p.Patterns
}

func (p *LogParser) extractTimestamp(matches []string, names []string, patternName string) (time.Time, error) {
	values := make(map[string]string)
	for i, name := range names {
		if i > 0 && name != "" {
			values[name] = matches[i]
		}
	}
	
	if strings.HasPrefix(patternName, "iso") || patternName == "enhanced" {
		tsStr, ok := values["timestamp"]
		if !ok {
			return time.Time{}, errors.New("no timestamp in match")
		}
		return p.parseISOTimestamp(tsStr)
	}
	
	monthStr, ok := values["month"]
	if !ok {
		return time.Time{}, errors.New("no month in match")
	}
	
	dayStr, ok := values["day"]
	if !ok {
		return time.Time{}, errors.New("no day in match")
	}
	
	timeStr, ok := values["time"]
	if !ok {
		return time.Time{}, errors.New("no time in match")
	}
	
	month, ok := monthMap[monthStr]
	if !ok {
		return time.Time{}, fmt.Errorf("invalid month: %s", monthStr)
	}
	
	day, err := strconv.Atoi(dayStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid day: %s", dayStr)
	}
	
	year := p.adjustYear(month)
	
	timeParts := strings.Split(timeStr, ".")
	baseTime := timeParts[0]
	var microsec int64
	if len(timeParts) > 1 {
		micro, _ := strconv.ParseInt(timeParts[1], 10, 64)
		microsec = micro
	}
	
	timeComponents := strings.Split(baseTime, ":")
	if len(timeComponents) != 3 {
		return time.Time{}, fmt.Errorf("invalid time format: %s", baseTime)
	}
	
	hour, _ := strconv.Atoi(timeComponents[0])
	minute, _ := strconv.Atoi(timeComponents[1])
	second, _ := strconv.Atoi(timeComponents[2])
	
	loc := time.Local
	timestamp := time.Date(year, time.Month(month), day, hour, minute, second, int(microsec*1000), loc)
	return timestamp, nil
}

func (p *LogParser) parseISOTimestamp(tsStr string) (time.Time, error) {
	tsStr = strings.Replace(tsStr, " ", "T", 1)
	
	formats := []string{
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05.999999-07:00",
	}
	
	for _, format := range formats {
		t, err := time.Parse(format, tsStr)
		if err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, errors.New("unsupported ISO timestamp format")
}

func (p *LogParser) adjustYear(month int) int {
	if p.LastMonth == nil {
		p.LastMonth = &month
		return p.LastYear
	}
	
	if *p.LastMonth == 12 && month == 1 {
		p.LastYear++
	} else if *p.LastMonth == 1 && month == 12 {
		p.LastYear--
	}
	
	p.LastMonth = &month
	return p.LastYear
}

type LogStore struct {
	Entries      []*LogEntry
	ByDate       map[string]map[string][]*LogEntry
	Stats        *Statistics
	MemoryWarned bool
}

type Statistics struct {
	TotalEntries   int
	UniqueServices map[string]bool
	ServiceCounts  map[string]int
	LevelCounts    map[LogLevel]int
	ErrorCount     int
	HourlyCounts   [24]int
}

func NewLogStore() *LogStore {
	return &LogStore{
		ByDate: make(map[string]map[string][]*LogEntry),
		Stats: &Statistics{
			UniqueServices: make(map[string]bool),
			ServiceCounts:  make(map[string]int),
			LevelCounts:    make(map[LogLevel]int),
		},
	}
}

func (s *LogStore) AddEntry(entry *LogEntry) {
	s.Entries = append(s.Entries, entry)
	
	dateKey := entry.Timestamp.Format("2006-01-02")
	dateMap, exists := s.ByDate[dateKey]
	if !exists {
		dateMap = make(map[string][]*LogEntry)
		s.ByDate[dateKey] = dateMap
	}
	
	dateMap[entry.Service] = append(dateMap[entry.Service], entry)
	
	s.updateStats(entry)
}

func (s *LogStore) updateStats(entry *LogEntry) {
	s.Stats.TotalEntries++
	s.Stats.UniqueServices[entry.Service] = true
	s.Stats.ServiceCounts[entry.Service]++
	
	if entry.Level != nil {
		s.Stats.LevelCounts[*entry.Level]++
	}
	
	if entry.IsError() {
		s.Stats.ErrorCount++
	}
	
	hour := entry.Timestamp.Hour()
	s.Stats.HourlyCounts[hour]++
}

func (s *LogStore) SortAll() {
	sort.Slice(s.Entries, func(i, j int) bool {
		return s.Entries[i].Timestamp.Before(s.Entries[j].Timestamp)
	})
	
	for _, dateMap := range s.ByDate {
		for _, entries := range dateMap {
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Timestamp.Before(entries[j].Timestamp)
			})
		}
	}
}

type SyslogAnalyzer struct {
	Config      Config
	LogFile     string
	Parser      *LogParser
	Store       *LogStore
	LinesRead   int
	EntriesRead int
}

func NewSyslogAnalyzer(logFile string, config Config) (*SyslogAnalyzer, error) {
	if logFile != "" {
		if !isSafePath(logFile) {
			return nil, errors.New("unsafe log file path")
		}
	} else {
		found, err := findLogFile()
		if err != nil {
			return nil, err
		}
		logFile = found
	}
	
	now := time.Now()
	parser := NewLogParser(now.Year(), config.Verbose, config.DetectRsyslog)
	
	return &SyslogAnalyzer{
		Config:  config,
		LogFile: logFile,
		Parser:  parser,
		Store:   NewLogStore(),
	}, nil
}

func isSafePath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	
	safePrefixes := []string{
		"/var/log",
		"/var/log/rsyslog",
		"/var/log/syslog.d",
		"/var/log/journal",
	}
	
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(absPath, prefix) {
			return true
		}
	}
	return false
}

func findLogFile() (string, error) {
	for _, basePath := range defaultLogPaths {
		if fileExists(basePath) && isReadable(basePath) {
			return basePath, nil
		}
		
		extensions := []string{".1", ".2", ".3", ".0", ".gz", ".bz2", ".xz"}
		for _, ext := range extensions {
			path := basePath + ext
			if fileExists(path) && isReadable(path) {
				return path, nil
			}
		}
		
		dir := filepath.Dir(basePath)
		base := filepath.Base(basePath)
		
		files, err := filepath.Glob(filepath.Join(dir, base+".*"))
		if err != nil {
			continue
		}
		
		for _, file := range files {
			if isReadable(file) {
				return file, nil
			}
		}
	}
	
	return "", errors.New("no readable log file found")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isReadable(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func (a *SyslogAnalyzer) LoadLogs() error {
	if a.LogFile == "" {
		return errors.New("no log file specified")
	}
	
	if !fileExists(a.LogFile) {
		return fmt.Errorf("log file does not exist: %s", a.LogFile)
	}
	
	fileInfo, err := os.Stat(a.LogFile)
	if err != nil {
		return err
	}
	
	if fileInfo.Size() > int64(a.Config.MaxFileSizeMB)*1024*1024 {
		return errors.New("file too large")
	}
	
	now := time.Now()
	cutoff := now.AddDate(0, 0, -a.Config.MaxDays)
	
	file, err := os.Open(a.LogFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	var reader io.Reader = file
	
	switch {
	case strings.HasSuffix(a.LogFile, ".gz"):
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzReader.Close()
		reader = gzReader
		
	case strings.HasSuffix(a.LogFile, ".bz2"):
		reader = bzip2.NewReader(file)
	}
	
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	
	a.LinesRead = 0
	a.EntriesRead = 0
	
	for scanner.Scan() {
		if a.LinesRead >= a.Config.MaxMemoryEntries*10 {
			log.Printf("Warning: Reached line limit (%d)", a.Config.MaxMemoryEntries*10)
			break
		}
		
		a.LinesRead++
		line := scanner.Text()
		
		entry, err := a.Parser.ParseLine(line, now, cutoff)
		if err != nil && a.Config.Verbose {
			log.Printf("Parse error: %v", err)
		}
		
		if entry != nil {
			if a.EntriesRead >= a.Config.MaxMemoryEntries {
				if !a.Store.MemoryWarned {
					log.Printf("Warning: Memory limit reached (%d entries)", a.Config.MaxMemoryEntries)
					a.Store.MemoryWarned = true
				}
				break
			}
			
			a.Store.AddEntry(entry)
			a.EntriesRead++
		}
	}
	
	if err := scanner.Err(); err != nil {
		return err
	}
	
	a.Store.SortAll()
	return nil
}

func (a *SyslogAnalyzer) DisplayTree() {
	if len(a.Store.ByDate) == 0 {
		fmt.Println("No logs to display")
		return
	}
	
	if a.Config.ColorOutput {
		fmt.Println("\033[1;34mSyslog Analysis Tree\033[0m")
		fmt.Println("\033[90m" + strings.Repeat("=", 50) + "\033[0m")
	} else {
		fmt.Println("Syslog Analysis Tree")
		fmt.Println(strings.Repeat("=", 50))
	}
	
	var dates []string
	for date := range a.Store.ByDate {
		dates = append(dates, date)
	}
	sort.Strings(dates)
	
	for _, date := range dates {
		if a.Config.ColorOutput {
			fmt.Printf("\n\033[1;33m%s\033[0m\n", date)
		} else {
			fmt.Printf("\n%s\n", date)
		}
		
		servicesMap := a.Store.ByDate[date]
		var services []string
		for service := range servicesMap {
			services = append(services, service)
		}
		sort.Strings(services)
		
		for i, service := range services {
			entries := servicesMap[service]
			errorCount := 0
			for _, entry := range entries {
				if entry.IsError() {
					errorCount++
				}
			}
			
			prefix := "├── "
			if i == len(services)-1 {
				prefix = "└── "
			}
			
			if a.Config.ColorOutput {
				if errorCount > 0 {
					fmt.Printf("%s\033[1;36m%s\033[0m \033[91m[errors: %d]\033[0m\n", 
						prefix, service, errorCount)
				} else {
					fmt.Printf("%s\033[1;36m%s\033[0m\n", prefix, service)
				}
			} else {
				if errorCount > 0 {
					fmt.Printf("%s%s [errors: %d]\n", prefix, service, errorCount)
				} else {
					fmt.Printf("%s%s\n", prefix, service)
				}
			}
			
			a.displayServiceEntries(entries, i == len(services)-1)
		}
	}
}

func (a *SyslogAnalyzer) displayServiceEntries(entries []*LogEntry, lastService bool) {
	displayCount := len(entries)
	if displayCount > a.Config.MaxLinesPerSvc {
		displayCount = a.Config.MaxLinesPerSvc
	}
	
	for i := 0; i < displayCount; i++ {
		isLast := i == displayCount-1
		prefix := "│   ├── "
		if isLast {
			prefix = "│   └── "
		}
		
		a.displayLogEntry(entries[i], prefix, isLast, lastService)
	}
	
	if len(entries) > displayCount {
		overflow := len(entries) - displayCount
		errorCount := 0
		for i := displayCount; i < len(entries); i++ {
			if entries[i].IsError() {
				errorCount++
			}
		}
		
		connector := "│   └── "
		if lastService {
			connector = "    └── "
		}
		
		if a.Config.ColorOutput {
			if errorCount > 0 {
				fmt.Printf("%s\033[90m... (%d more logs, %d errors)\033[0m\n", 
					connector, overflow, errorCount)
			} else {
				fmt.Printf("%s\033[90m... (%d more logs)\033[0m\n", connector, overflow)
			}
		} else {
			if errorCount > 0 {
				fmt.Printf("%s... (%d more logs, %d errors)\n", connector, overflow, errorCount)
			} else {
				fmt.Printf("%s... (%d more logs)\n", connector, overflow)
			}
		}
	}
}

func (a *SyslogAnalyzer) displayLogEntry(entry *LogEntry, prefix string, isLast bool, lastService bool) {
	timeStr := entry.Timestamp.Format("15:04:05")
	
	var levelIndicator string
	if entry.Level != nil {
		levelIndicator = fmt.Sprintf("[%s] ", *entry.Level)
	}
	
	var colorStart, colorEnd string
	if a.Config.ColorOutput {
		colorEnd = "\033[0m"
		if entry.Level != nil {
			colorStart = (*entry.Level).Color()
		} else if entry.IsError() {
			colorStart = "\033[31m"
		}
	}
	
	if a.Config.ShowFullLines {
		fmt.Printf("%s\033[90m[%s]\033[0m %s%s%s%s\n", 
			prefix, timeStr, colorStart, levelIndicator, entry.Message, colorEnd)
	} else if a.Config.WrapLines {
		wrapWidth := 40
		if a.Config.TruncateLength-len(prefix)-len(timeStr)-len(levelIndicator)-4 > wrapWidth {
			wrapWidth = a.Config.TruncateLength - len(prefix) - len(timeStr) - len(levelIndicator) - 4
		}
		
		lines := wrapText(entry.Message, wrapWidth)
		for i, line := range lines {
			if i == 0 {
				fmt.Printf("%s\033[90m[%s]\033[0m %s%s%s%s\n", 
					prefix, timeStr, colorStart, levelIndicator, line, colorEnd)
			} else {
				connector := "│      "
				if lastService && isLast {
					connector = "       "
				}
				fmt.Printf("%s%s%s%s%s\n", prefix[:1], connector, colorStart, line, colorEnd)
			}
		}
	} else {
		message := entry.Message
		truncation := ""
		if len(message) > a.Config.TruncateLength {
			message = message[:a.Config.TruncateLength]
			truncation = "..."
		}
		
		fmt.Printf("%s\033[90m[%s]\033[0m %s%s%s%s%s\n", 
			prefix, timeStr, colorStart, levelIndicator, message, truncation, colorEnd)
	}
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}
	
	var lines []string
	for len(text) > 0 {
		if len(text) <= width {
			lines = append(lines, text)
			break
		}
		
		line := text[:width]
		text = text[width:]
		lines = append(lines, line)
	}
	
	return lines
}

func (a *SyslogAnalyzer) DisplaySummary() {
	if len(a.Store.ByDate) == 0 {
		fmt.Println("No logs found")
		return
	}
	
	fmt.Println("\nSummary:")
	fmt.Printf("  Total entries: %d\n", a.Store.Stats.TotalEntries)
	fmt.Printf("  Unique services: %d\n", len(a.Store.Stats.UniqueServices))
	fmt.Printf("  Error count: %d\n", a.Store.Stats.ErrorCount)
	
	type serviceCount struct {
		name  string
		count int
	}
	
	var topServices []serviceCount
	for service, count := range a.Store.Stats.ServiceCounts {
		topServices = append(topServices, serviceCount{service, count})
	}
	
	sort.Slice(topServices, func(i, j int) bool {
		return topServices[i].count > topServices[j].count
	})
	
	limit := 5
	if len(topServices) < limit {
		limit = len(topServices)
	}
	
	if limit > 0 {
		fmt.Printf("  Top services: ")
		for i := 0; i < limit; i++ {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s (%d)", topServices[i].name, topServices[i].count)
		}
		fmt.Println()
	}
	
	if len(a.Store.Stats.LevelCounts) > 0 {
		fmt.Println("  Level distribution:")
		for level, count := range a.Store.Stats.LevelCounts {
			fmt.Printf("    %s: %d\n", level, count)
		}
	}
}

func (a *SyslogAnalyzer) FindErrors(serviceFilter string) []*LogEntry {
	var errors []*LogEntry
	
	for _, entries := range a.Store.ByDate {
		for _, serviceEntries := range entries {
			for _, entry := range serviceEntries {
				if serviceFilter != "" && entry.Service != serviceFilter {
					continue
				}
				if entry.IsError() {
					errors = append(errors, entry)
				}
			}
		}
	}
	
	sort.Slice(errors, func(i, j int) bool {
		return errors[i].Timestamp.Before(errors[j].Timestamp)
	})
	
	return errors
}

func (a *SyslogAnalyzer) ExportJSON(filename string) error {
	exportData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"exported_at":   time.Now().Format(time.RFC3339),
			"log_file":      a.LogFile,
			"analysis_days": a.Config.MaxDays,
		},
		"summary": map[string]interface{}{
			"total_entries":    a.Store.Stats.TotalEntries,
			"unique_services":  len(a.Store.Stats.UniqueServices),
			"error_count":      a.Store.Stats.ErrorCount,
			"service_counts":   a.Store.Stats.ServiceCounts,
			"level_counts":     a.Store.Stats.LevelCounts,
		},
	}
	
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, jsonData, 0644)
}

func (a *SyslogAnalyzer) ExportCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	header := []string{"Timestamp", "Service", "Level", "Host", "PID", "Message"}
	if err := writer.Write(header); err != nil {
		return err
	}
	
	for _, entry := range a.Store.Entries {
		level := ""
		if entry.Level != nil {
			level = string(*entry.Level)
		}
		
		host := ""
		if entry.Host != nil {
			host = *entry.Host
		}
		
		pid := ""
		if entry.PID != nil {
			pid = *entry.PID
		}
		
		record := []string{
			entry.Timestamp.Format(time.RFC3339),
			entry.Service,
			level,
			host,
			pid,
			strings.ReplaceAll(entry.Message, "\"", "\"\""),
		}
		
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	
	return nil
}

func main() {
	var (
		logFile        = flag.String("file", "", "Log file path")
		maxDays        = flag.Int("days", defaultMaxDays, "Days to analyze")
		truncate       = flag.Int("truncate", defaultTruncate, "Truncate length")
		fullLines      = flag.Bool("full", false, "Show full lines")
		wrapLines      = flag.Bool("wrap", false, "Wrap long lines")
		linesPerSvc    = flag.Int("per-service", defaultLinesPerSvc, "Lines per service")
		noColor        = flag.Bool("no-color", false, "Disable color output")
		verbose        = flag.Bool("verbose", false, "Verbose output")
		summary        = flag.Bool("summary", false, "Show summary")
		systemInfo     = flag.Bool("info", false, "Show system info")
		enableAnalysis = flag.Bool("analyze", false, "Enable analysis")
		exportJSON     = flag.String("export-json", "", "Export to JSON file")
		exportCSV      = flag.String("export-csv", "", "Export to CSV file")
		findErrors     = flag.Bool("find-errors", false, "Find error logs")
		serviceFilter  = flag.String("service", "", "Filter by service")
		filterService  = flag.String("filter-service", "", "Filter by service regex")
		filterLevel    = flag.String("filter-level", "", "Filter by level")
		filterMessage  = flag.String("filter-message", "", "Filter by message content")
		maxFileSize    = flag.Int("max-size", defaultMaxFileSize, "Max file size in MB")
		maxEntries     = flag.Int("max-entries", defaultMaxEntries, "Max log entries")
		noDetect       = flag.Bool("no-detect", false, "Disable rsyslog detection")
		configFile     = flag.String("config", "", "Config file")
	)
	
	flag.Parse()
	
	config := DefaultConfig()
	if *configFile != "" {
		config = loadConfig(*configFile)
	} else {
		config.MaxDays = *maxDays
		config.TruncateLength = *truncate
		config.ShowFullLines = *fullLines
		config.WrapLines = *wrapLines
		config.MaxLinesPerSvc = *linesPerSvc
		config.ColorOutput = !*noColor
		config.Verbose = *verbose
		config.EnableAnalysis = *enableAnalysis || *summary || *exportJSON != ""
		config.MaxFileSizeMB = *maxFileSize
		config.DetectRsyslog = !*noDetect
		config.MaxMemoryEntries = *maxEntries
	}
	
	if *systemInfo {
		fmt.Println("System Information:")
		fmt.Println("  Log parser ready")
		fmt.Println("  Default paths:", strings.Join(defaultLogPaths, ", "))
		return
	}
	
	analyzer, err := NewSyslogAnalyzer(*logFile, config)
	if err != nil {
		log.Fatal(err)
	}
	
	if err := analyzer.LoadLogs(); err != nil {
		log.Fatal(err)
	}
	
	if *findErrors {
		errors := analyzer.FindErrors(*serviceFilter)
		if len(errors) > 0 {
			fmt.Printf("\nFound %d error logs:\n", len(errors))
			showCount := 10
			if len(errors) < showCount {
				showCount = len(errors)
			}
			for i := len(errors) - showCount; i < len(errors); i++ {
				entry := errors[i]
				preview := entry.Message
				if len(preview) > 100 {
					preview = preview[:100] + "..."
				}
				fmt.Printf("  %s [%s] %s\n", 
					entry.Timestamp.Format("15:04:05"), entry.Service, preview)
			}
		} else {
			fmt.Println("No error logs found")
		}
	} else if *filterService != "" || *filterLevel != "" || *filterMessage != "" {
		fmt.Println("Filtering not implemented in this version")
	} else if *summary {
		analyzer.DisplaySummary()
	} else {
		analyzer.DisplayTree()
	}
	
	if *exportJSON != "" {
		if err := analyzer.ExportJSON(*exportJSON); err != nil {
			log.Printf("Failed to export JSON: %v", err)
		} else {
			log.Printf("Exported to %s", *exportJSON)
		}
	}
	
	if *exportCSV != "" {
		if err := analyzer.ExportCSV(*exportCSV); err != nil {
			log.Printf("Failed to export CSV: %v", err)
		} else {
			log.Printf("Exported to %s", *exportCSV)
		}
	}
}

func loadConfig(filename string) Config {
	config := DefaultConfig()
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return config
	}
	
	var configMap map[string]interface{}
	if err := json.Unmarshal(data, &configMap); err != nil {
		return config
	}
	
	if val, ok := configMap["max_days"].(float64); ok {
		config.MaxDays = int(val)
	}
	if val, ok := configMap["truncate_length"].(float64); ok {
		config.TruncateLength = int(val)
	}
	if val, ok := configMap["max_lines_per_service"].(float64); ok {
		config.MaxLinesPerSvc = int(val)
	}
	if val, ok := configMap["max_file_size_mb"].(float64); ok {
		config.MaxFileSizeMB = int(val)
	}
	if val, ok := configMap["max_memory_entries"].(float64); ok {
		config.MaxMemoryEntries = int(val)
	}
	
	if val, ok := configMap["show_full_lines"].(bool); ok {
		config.ShowFullLines = val
	}
	if val, ok := configMap["wrap_lines"].(bool); ok {
		config.WrapLines = val
	}
	if val, ok := configMap["color_output"].(bool); ok {
		config.ColorOutput = val
	}
	if val, ok := configMap["verbose"].(bool); ok {
		config.Verbose = val
	}
	if val, ok := configMap["enable_analysis"].(bool); ok {
		config.EnableAnalysis = val
	}
	if val, ok := configMap["use_rsyslog_detection"].(bool); ok {
		config.DetectRsyslog = val
	}
	
	return config
}
