package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

/* =========================
   User-Agent Pool
   ========================= */
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
}

/* =========================
   Regexes
   ========================= */
var secretsRegex = regexp.MustCompile(`(?i)['"]?\w*\s*(secret|token|password|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|aws_session_token|irc_pass|slack_bot_token|id_dsa|secret[_-]?(key|token)|api[_-]?(key|token|secret)|access[_-]?(key|token|secret)|auth[_-]?(key|token|secret)|session[_-]?(key|token|secret)|consumer[_-]?(key|token|secret)|public[_-]?(key|token|secret)|client[_-]?(id|token|key)|ssh[_-]?key|encrypt[_-]?(secret|key)|decrypt[_-]?(secret|key)|github[_-]?(key|token|secret)|gitlab[_-]?token|slack[_-]?token)\w*\s*['"]?\s*[:=]+\s*['"]?[\w\-/~!@#$%^&*+=]{8,}`)
var apiKeyUUID = regexp.MustCompile(`(?i)["']?apiKey["']?\s*:\s*["']?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}["']?`)
var hardTokens = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z]{20,}|CTF_CDA_ACCESS_TOKEN_PREVIEW_API`)

/* =========================
   Core Scanning
   ========================= */
func scanContent(name string, r io.Reader, out chan<- string) {
	body, err := io.ReadAll(r)
	if err != nil {
		return
	}
	content := string(body)
	var matches []string
	matches = append(matches, secretsRegex.FindAllString(content, -1)...)
	matches = append(matches, apiKeyUUID.FindAllString(content, -1)...)
	matches = append(matches, hardTokens.FindAllString(content, -1)...)

	if len(matches) > 0 {
		out <- name
		for _, m := range matches {
			out <- "    " + m
		}
	}
}

func scanFile(fname string, wg *sync.WaitGroup, out chan<- string) {
	defer wg.Done()
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()
	scanContent(fname, f, out)
}

func scanURL(u string, wg *sync.WaitGroup, sem chan struct{}, timeout int, out chan<- string) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	scanContent(u, resp.Body, out)
}

func scanURLList(r io.Reader, wg *sync.WaitGroup, sem chan struct{}, timeout int, out chan<- string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			wg.Add(1)
			go scanURL(u, wg, sem, timeout, out)
		}
	}
}

/* =========================
   Main
   ========================= */
func main() {
	rand.Seed(time.Now().UnixNano())

	f := flag.String("f", "", "URL list file")
	t := flag.Int("t", 20, "max concurrent threads")
	timeout := flag.Int("timeout", 20, "HTTP timeout in seconds")
	flag.Parse()

	out := make(chan string)
	var wg sync.WaitGroup
	sem := make(chan struct{}, *t)

	if *f != "" {
		file, err := os.Open(*f)
		if err == nil {
			scanURLList(file, &wg, sem, *timeout, out)
			file.Close()
		}
	} else if len(flag.Args()) == 1 && flag.Args()[0] == "-" {
		scanURLList(os.Stdin, &wg, sem, *timeout, out)
	} else if len(flag.Args()) > 0 {
		for _, a := range flag.Args() {
			wg.Add(1)
			go scanFile(a, &wg, out)
		}
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanContent("stdin", os.Stdin, out)
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	for l := range out {
		fmt.Println(l)
	}
}
