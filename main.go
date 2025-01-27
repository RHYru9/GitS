package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"net/url"
	"github.com/fatih/color"
	"time"
)

var paths = []string{
	"/.git/",
	"/.git/index",
	"/.git/logs/",
	"/.git/HEAD",
	"/.git/logs/HEAD",
	"/.git/logs/refs",
	"/.git/logs/refs/remotes/origin/master",
	"/.git/config",
	"/.git/description",
	"/.git/hooks/",
	"/.git/info/",
	"/.git/objects/",
	"/.git/refs/",
}

var vulnerabilitySigns = []string{
	"ref:", 
	"index of", 
	"initial commit",
	"update by push",
	"[core]",
	"repository",
	"bare = false",
	"filemode",
	"[remote",
	"[branch",
	"master",
	"origin",
	"HEAD branch:",
	"refs/heads/",
	"autopull",
	"repositoryformatversion",
}

func isHTML(responseText string) bool {
	return strings.Contains(strings.ToLower(responseText), "<html") || 
		   strings.Contains(strings.ToLower(responseText), "<!doctype html")
}

func getStatusText(code int) string {
	switch code {
	case 200:
		return "ok"
	case 301, 302, 307, 308:
		return "redirect"
	case 401:
		return "unauthenticated"
	case 403:
		return "forbidden"
	case 404:
		return "not found"
	case 500:
		return "server error"
	default:
		return fmt.Sprintf("status: %d", code)
	}
}

func checkVulnerability(content string) bool {
	for _, sign := range vulnerabilitySigns {
		if strings.Contains(strings.ToLower(content), strings.ToLower(sign)) {
			return true
		}
	}
	return false
}

func checkPath(domain string) bool {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	parsedDomain, err := url.Parse(domain)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	firstPath := paths[0]
	targetURL := parsedDomain.Scheme + "://" + parsedDomain.Host + firstPath
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		color.Red("[+] %-60s|\terror\t\t | %v", targetURL, err)
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0")
	resp, err := client.Do(req)
	
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			color.Yellow("[+] %-60s|\ttimeout\t\t | skipping entire domain", targetURL)
			return false
		}
		color.Red("[+] %-60s|\terror\t\t | %v", targetURL, err)
		return false
	}
	
	defer resp.Body.Close()
	
	vulnerable := processPathResponse(targetURL, resp)
	
	for _, path := range paths[1:] {
		targetURL := parsedDomain.Scheme + "://" + parsedDomain.Host + path
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			color.Red("[+] %-60s|\terror\t\t | %v", targetURL, err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GitSD/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				color.Yellow("[+] %-60s|\ttimeout\t\t | skipping", targetURL)
			} else {
				color.Red("[+] %-60s|\terror\t\t | %v", targetURL, err)
			}
			continue
		}
		
		defer resp.Body.Close()
		if processPathResponse(targetURL, resp) {
			vulnerable = true
		}
	}
	
	return vulnerable
}

func processPathResponse(targetURL string, resp *http.Response) bool {
	statusText := getStatusText(resp.StatusCode)
	
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		color.Yellow("[+] %-60s|\t%-15s\t | Status code: %d", targetURL, statusText, resp.StatusCode)
		return false
	}

	if resp.StatusCode == 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			color.Red("[+] %-60s|\terror reading\t | %v", targetURL, err)
			return false
		}
		
		content := string(bodyBytes)
		
		if isHTML(content) {
			color.Yellow("[+] %-60s|\tHTML content\t | Status code: %d", targetURL, resp.StatusCode)
			return false
		}

		if checkVulnerability(content) {
			color.Green("[+] %-60s|\tvulnerable\t | Status code: %d", targetURL, resp.StatusCode)
			return true
		} else {
			color.Yellow("[+] %-60s|\tnot vulnerable\t | Status code: %d", targetURL, resp.StatusCode)
		}
	} else {
		color.Yellow("[+] %-60s|\t%-15s\t | Status code: %d", targetURL, statusText, resp.StatusCode)
	}
	return false
}

func processDomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vulnerableDomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if checkPath(domain) {
			vulnerableDomains = append(vulnerableDomains, domain)
		}
	}
	return vulnerableDomains, scanner.Err()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gitsd <file containing list of domains>")
		return
	}

	filePath := os.Args[1]
	vulnerableDomains, err := processDomains(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	if len(vulnerableDomains) > 0 {
		color.Green("\n[+] Found %d vulnerable domains:", len(vulnerableDomains))
		for _, domain := range vulnerableDomains {
			color.Green("[+] %s", domain)
		}
	} else {
		color.Yellow("\n[+] No vulnerable domains found.")
	}
}
