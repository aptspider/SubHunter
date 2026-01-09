package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	version = "1.0.0"
	banner  = `
   _____       _     _    _             _            
  / ____|     | |   | |  | |           | |           
 | (___  _   _| |__ | |__| |_   _ _ __ | |_ ___ _ __ 
  \___ \| | | | '_ \|  __  | | | | '_ \| __/ _ \ '__|
  ____) | |_| | |_) | |  | | |_| | | | | ||  __/ |   
 |_____/ \__,_|_.__/|_|  |_|\__,_|_| |_|\__\___|_|   
                                                      
  Certificate Transparency Subdomain Enumerator
  Powered by crt.sh | By SpiderSec | v%s
`
)

var (
	pink    = "\033[95m"
	magenta = "\033[35m"
	dim     = "\033[2m"
	bold    = "\033[1m"
	reset   = "\033[0m"
)

type CRTResponse struct {
	NameValue string `json:"name_value"`
}

type SubHunter struct {
	timeout     time.Duration
	concurrency int
	silent      bool
	client      *http.Client
	totalFound  int
	mu          sync.Mutex
}

func NewSubHunter(timeout int, concurrency int, silent bool) *SubHunter {
	return &SubHunter{
		timeout:     time.Duration(timeout) * time.Second,
		concurrency: concurrency,
		silent:      silent,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (s *SubHunter) log(level, message, data string) {
	if s.silent {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	icon := ""

	switch level {
	case "info":
		icon = pink + "[INF]" + reset
	case "success":
		icon = pink + "[SUC]" + reset
	case "error":
		icon = pink + "[ERR]" + reset
	case "warn":
		icon = pink + "[WAR]" + reset
	case "found":
		icon = pink + "[*]" + reset
	case "run":
		icon = pink + "[>]" + reset
	}

	if data != "" {
		fmt.Printf("%s%s%s %s %s %s%s%s%s\n", dim, timestamp, reset, icon, message, pink, bold, data, reset)
	} else {
		fmt.Printf("%s%s%s %s %s\n", dim, timestamp, reset, icon, message)
	}
}

func (s *SubHunter) printResult(subdomain string) {
	if !s.silent {
		fmt.Printf("%s[R]%s %s\n", pink, reset, subdomain)
	} else {
		fmt.Println(subdomain)
	}
}

func (s *SubHunter) isValidSubdomain(subdomain string) bool {
	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}

	subdomain = strings.TrimPrefix(subdomain, "*.")
	parts := strings.Split(subdomain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}

	return true
}

func (s *SubHunter) extractSubdomains(domain string, nameValues []string) []string {
	subdomainSet := make(map[string]bool)
	pattern := regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*` + regexp.QuoteMeta(domain) + `\b`)

	for _, nameValue := range nameValues {
		entries := strings.Split(nameValue, "\n")
		for _, entry := range entries {
			matches := pattern.FindAllString(entry, -1)
			for _, match := range matches {
				subdomain := strings.ToLower(strings.TrimSpace(match))
				subdomain = strings.TrimPrefix(subdomain, "*.")

				if s.isValidSubdomain(subdomain) && strings.Contains(subdomain, domain) {
					subdomainSet[subdomain] = true
				}
			}
		}
	}

	subdomains := make([]string, 0, len(subdomainSet))
	for sub := range subdomainSet {
		subdomains = append(subdomains, sub)
	}
	sort.Strings(subdomains)

	return subdomains
}

func (s *SubHunter) queryAPI(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	s.log("run", "Querying crt.sh API", domain)

	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []CRTResponse
	if err := json.Unmarshal(body, &results); err != nil {
		s.log("warn", "JSON decode failed", "")
		return nil, err
	}

	nameValues := make([]string, len(results))
	for i, result := range results {
		nameValues[i] = result.NameValue
	}

	return s.extractSubdomains(domain, nameValues), nil
}

func (s *SubHunter) processDomain(domain string, showResults bool) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	subdomains, err := s.queryAPI(domain)
	if err != nil {
		s.log("error", fmt.Sprintf("Failed to query %s", domain), err.Error())
		return nil
	}

	count := len(subdomains)
	s.mu.Lock()
	s.totalFound += count
	s.mu.Unlock()

	if count > 0 {
		s.log("found", fmt.Sprintf("Discovered %d subdomains", count), "")
		if showResults {
			for _, sub := range subdomains {
				s.printResult(sub)
			}
		}
	} else {
		s.log("warn", "No subdomains found", "")
	}

	return subdomains
}

func (s *SubHunter) processDomainsFromFile(filename string, concurrent bool) []string {
	file, err := os.Open(filename)
	if err != nil {
		s.log("error", "Cannot read file", err.Error())
		return nil
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	s.log("info", fmt.Sprintf("Loaded %d domains from", len(domains)), filename)

	if concurrent {
		s.log("info", fmt.Sprintf("Using %d concurrent workers", s.concurrency), "")
	}

	allSubdomains := make(map[string]bool)
	var mu sync.Mutex

	if concurrent && len(domains) > 1 {
		semaphore := make(chan struct{}, s.concurrency)
		var wg sync.WaitGroup

		for i, domain := range domains {
			wg.Add(1)
			go func(idx int, d string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				subs := s.processDomain(d, false)

				mu.Lock()
				for _, sub := range subs {
					allSubdomains[sub] = true
				}
				mu.Unlock()

				s.log("success", fmt.Sprintf("[%d/%d] %s", idx+1, len(domains), d), fmt.Sprintf("%d found", len(subs)))
			}(i, domain)
		}

		wg.Wait()
	} else {
		for i, domain := range domains {
			s.log("run", fmt.Sprintf("[%d/%d] Processing", i+1, len(domains)), domain)
			subs := s.processDomain(domain, false)

			for _, sub := range subs {
				allSubdomains[sub] = true
			}
		}
	}

	result := make([]string, 0, len(allSubdomains))
	for sub := range allSubdomains {
		result = append(result, sub)
	}
	sort.Strings(result)

	s.totalFound = len(result)
	return result
}

func (s *SubHunter) saveToFile(subdomains []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, sub := range subdomains {
		fmt.Fprintln(writer, sub)
	}
	writer.Flush()

	s.log("success", "Saved output to", filename)
	return nil
}

func (s *SubHunter) printSummary(elapsed time.Duration) {
	if !s.silent {
		fmt.Printf("\n%s%s%s\n", pink, strings.Repeat("━", 60), reset)
		fmt.Printf("%s%s[SUMMARY]%s\n", pink, bold, reset)
		fmt.Printf("%s%s%s\n", pink, strings.Repeat("━", 60), reset)
		fmt.Printf("  Total Subdomains: %s%s%d%s\n", pink, bold, s.totalFound, reset)
		fmt.Printf("  Execution Time:   %s%s%.2fs%s\n", pink, bold, elapsed.Seconds(), reset)
		fmt.Printf("%s%s%s\n\n", pink, strings.Repeat("━", 60), reset)
	}
}

func main() {
	domain := flag.String("d", "", "target domain")
	domainList := flag.String("l", "", "file with domain list")
	output := flag.String("o", "", "output file path")
	timeout := flag.Int("t", 300, "timeout in seconds")
	concurrency := flag.Int("c", 5, "concurrent workers")
	concurrent := flag.Bool("concurrent", false, "enable concurrent mode")
	silent := flag.Bool("silent", false, "silent mode (only results)")
	showVersion := flag.Bool("version", false, "show version")

	flag.Parse()

	if *showVersion {
		fmt.Printf("SubHunter v%s\n", version)
		os.Exit(0)
	}

	if !*silent {
		fmt.Printf("%s%s%s%s", pink, bold, fmt.Sprintf(banner, version), reset)
	}

	if *domain == "" && *domainList == "" {
		fmt.Printf("%s[ERR]%s Specify -d/--domain or -l/--list\n\n", pink, reset)
		flag.Usage()
		os.Exit(1)
	}

	if *domain != "" && *domainList != "" {
		fmt.Printf("%s[ERR]%s Cannot use -d and -l together\n\n", pink, reset)
		os.Exit(1)
	}

	hunter := NewSubHunter(*timeout, *concurrency, *silent)

	if !*silent {
		fmt.Printf("%s%s%s\n", pink, strings.Repeat("━", 60), reset)
		fmt.Printf("%s%s[CONFIGURATION]%s\n", pink, bold, reset)
		fmt.Printf("%s%s%s\n", pink, strings.Repeat("━", 60), reset)

		target := *domain
		if target == "" {
			target = *domainList
		}
		outputStr := "stdout"
		if *output != "" {
			outputStr = *output
		}

		fmt.Printf("  Target:      %s%s%s\n", pink, target, reset)
		fmt.Printf("  Output:      %s%s%s\n", pink, outputStr, reset)
		fmt.Printf("  Timeout:     %s%ds%s\n", pink, *timeout, reset)

		if *domainList != "" && *concurrent {
			fmt.Printf("  Workers:     %s%d%s\n", pink, *concurrency, reset)
		}

		fmt.Printf("%s%s%s\n\n", pink, strings.Repeat("━", 60), reset)
	}

	start := time.Now()
	var subdomains []string

	if *domainList != "" {
		subdomains = hunter.processDomainsFromFile(*domainList, *concurrent)
	} else {
		if !*silent {
			hunter.log("info", "Target domain", *domain)
		}
		subdomains = hunter.processDomain(*domain, true)
	}

	if *output != "" && len(subdomains) > 0 {
		if err := hunter.saveToFile(subdomains, *output); err != nil {
			hunter.log("error", "Failed to save file", err.Error())
		}
	}

	elapsed := time.Since(start)
	hunter.printSummary(elapsed)
}
