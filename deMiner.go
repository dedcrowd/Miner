package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

var re = regexp.MustCompile(`(?i)(api[-_]?key|apikey|secret|access[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?key|aws_access_key_id|aws_secret_access_key|aws_session_token|x-amz-security-token|slack[-_]?token|github[-_]?token|gitlab[-_]?token|firebase[-_]?key|stripe[-_]?secret|heroku[-_]?api[-_]?key|mailgun[-_]?api[-_]?key|twilio[-_]?api[-_]?key)[^[:alnum:]]{0,8}["'=:\s]{0,8}[A-Za-z0-9_\-\/+=]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9A-Za-z\-]{10,48}|gh[pousr]_[0-9A-Za-z]{36}`)

func scanContent(name string, r io.Reader, output chan<- string) {
	scanner := bufio.NewScanner(r)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindAllString(line, -1)
		if len(matches) > 0 {
			if !found {
				output <- name
				found = true
			}
			for _, m := range matches {
				output <- "  " + m
			}
		}
	}
}

func scanURL(url string, wg *sync.WaitGroup, output chan<- string) {
	defer wg.Done()
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	scanContent(url, resp.Body, output)
}

func scanFile(fname string, wg *sync.WaitGroup, output chan<- string) {
	defer wg.Done()
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()
	scanContent(fname, f, output)
}

func main() {
	output := make(chan string)
	var wg sync.WaitGroup

	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				wg.Add(1)
				go scanURL(arg, &wg, output)
			} else {
				wg.Add(1)
				go scanFile(arg, &wg, output)
			}
		}
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanContent("stdin", os.Stdin, output)
		}()
	}

	go func() {
		wg.Wait()
		close(output)
	}()
	for l := range output {
		fmt.Println(l)
	}
}
