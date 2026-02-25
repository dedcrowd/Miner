package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

var re = regexp.MustCompile(`(?i)(api[-_]?key|apikey|secret|access[-_]?token|auth[-_]?token|client[-_]?secret|private[-_]?key|aws_access_key_id|aws_secret_access_key|aws_session_token|slack[-_]?token|github[-_]?token|gitlab[-_]?token|firebase[-_]?key|stripe[-_]?secret|heroku[-_]?api[-_]?key|mailgun[-_]?api[-_]?key|twilio[-_]?api[-_]?key)[^[:alnum:]]{0,8}["'=:\s]{0,8}[A-Za-z0-9_\-\/+=]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9A-Za-z\-]{10,48}|gh[pousr]_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z]{20,}`)

func scanContent(name string, r io.Reader, out chan<- string) {
	sc := bufio.NewScanner(r)
	found := false
	for sc.Scan() {
		line := sc.Text()
		m := re.FindAllString(line, -1)
		if len(m) > 0 {
			if !found {
				out <- name
				found = true
			}
			for _, x := range m {
				out <- "    " + x
			}
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

func scanURL(u string, wg *sync.WaitGroup, out chan<- string) {
	defer wg.Done()
	resp, err := http.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	scanContent(u, resp.Body, out)
}

func scanURLList(r io.Reader, wg *sync.WaitGroup, out chan<- string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			wg.Add(1)
			go scanURL(u, wg, out)
		}
	}
}

func main() {
	f := flag.String("f", "", "")
	flag.Parse()

	out := make(chan string)
	var wg sync.WaitGroup

	// -f => URL listesi
	if *f != "" {
		file, err := os.Open(*f)
		if err == nil {
			scanURLList(file, &wg, out)
			file.Close()
		}

	// miner -  => stdin URL listesi
	} else if len(flag.Args()) == 1 && flag.Args()[0] == "-" {
		scanURLList(os.Stdin, &wg, out)

	// FLAG YOK => DOSYA TARAMA (hardcoded secrets)
	} else if len(flag.Args()) > 0 {
		for _, a := range flag.Args() {
			wg.Add(1)
			go scanFile(a, &wg, out)
		}

	// cat file | miner  => stdin dosya içeriği
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
