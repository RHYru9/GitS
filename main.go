package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"net/url"
	"github.com/fatih/color"
)

var paths = []string{
	"/.git/", "/.git/index", "/.git/logs/", "/.git/HEAD",
	"/.git/logs/HEAD", "/.git/logs/refs", "/.git/logs/refs/remotes/origin/master",
}

var vulnerabilitySigns = []string{"ref:", "index of", "initial commit", "update by push"}

func isHTML(responseText string) bool {
	return strings.Contains(strings.ToLower(responseText), "<html") || strings.Contains(strings.ToLower(responseText), "<!doctype html")
}

func checkPath(domain string) bool {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	parsedDomain, err := url.Parse(domain)
	if err != nil {
		fmt.Println("Error parsing domain:", err)
		return false
	}

	vulnerable := false

	for _, path := range paths {
		url := parsedDomain.Scheme + "://" + parsedDomain.Host + path
		resp, err := http.Get(url)

		if err != nil {
			color.Red("%s - Error: %s", url, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			color.Yellow("%s redirects - Not vulnerable", url)
			continue
		}

		if resp.StatusCode == 200 {
			body := make([]byte, 1024)
			resp.Body.Read(body)
			content := string(body)

			if isHTML(content) {
				color.Yellow("%s found [%s], but contains HTML - Not vulnerable", url, path)
				continue
			}

			for _, sign := range vulnerabilitySigns {
				if strings.Contains(content, sign) {
					color.Green("%s found [%s] - Vulnerable", url, path)
					vulnerable = true
					break
				}
			}

			if !vulnerable {
				color.Yellow("%s found [%s], but not vulnerable", url, path)
			}
		} else {
			color.Yellow("%s not found [%s] - Status code: %d", url, path, resp.StatusCode)
		}
	}

	return vulnerable
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
		color.Green("[+] vuln: %d", len(vulnerableDomains))
		for _, domain := range vulnerableDomains {
			color.Green("[+] [%s]", domain)
		}
	} else {
		color.Yellow("[+] No vulnerable domains found.")
	}
}
