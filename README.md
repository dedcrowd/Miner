

---

# Miner – Ultra-fast API Key & Secret Scanner

**Miner** is a Go-based tool for scanning files, stdin, or URLs to find API keys, secrets, tokens, and sensitive credentials using regex. It works with local files, piped input, or URLs from tools like `gau`, `waybackurls`, or `subfinder`. Fully parallelized for maximum speed.

---

## **Installation**

1. Ensure Go is installed:

```bash
go version
```

2. Clone or download the repository, then build:

```bash
go build -o ~/go/bin/miner deMinerPlus.go
```

---

## **Usage**

### **Scan a file containing endpoints**

```bash
miner -f endpoints.txt
```

* Scans all URLs listed in `endpoints.txt`.
* Outputs the URL followed by any matching secrets.

### **Scan stdin (pipe from another tool)**

```bash
cat urls.txt | miner -
```

* Accepts input from any command (e.g., `gau`, `subfinder`, `waybackurls`).
* Each line is treated as a URL and scanned.

### **Scan individual URLs**

```bash
miner https://example.com/app.js https://test.com/main.js
```

* Can provide one or multiple URLs as arguments.

---

## **Output Format**

```
https://example.com/main/main.js
    apikey=apikeyhere
https://example.com/upload/index.html
    jwt=eyj+here
```

* URL first, then each matched key or token indented underneath.

---

## **Features**

* Fully parallelized for speed.
* Supports files, stdin, and URLs.
* Works with endpoint lists from popular reconnaissance tools.
* Regex covers common API keys, tokens, AWS keys, GitHub/GitLab keys, Stripe, Firebase, and more.

---

If you want, I can also **write a ready-to-paste GitHub `README.md`** including badges, commit-ready markdown, and usage examples. That way you can just commit it directly. Do you want me to do that?




# miner
Fastes Hard Coded Credentials Founder
deMiner - Ultra-Fast Secret & API Key Scanner

# INSTALL

```
cd miner
```

add to Go path and install code...
```
go build -o ~/go/bin/miner miner.go
```

```
go build -o ~/go/bin/deMiner deMiner.go
```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/0a3c392a-df83-45fe-918d-eb348f57f2a8" />



Overview:
deMiner is a high-performance, parallel secret scanner written in Go.
Detects API keys, tokens, and secrets in:
- Local files (.js, .json, .html, .php)
- Stdin streams (cat * | deMiner)
- URLs and multi-target lists (supports subfinder, gau, waybackurls)

Features:
- Parallel scanning for speed
- Detects GitHub, GitLab, Slack, AWS, Stripe, Firebase, Twilio, Heroku, Mailgun keys
- Supports stdin, files, or URLs
- Single Go binary, no dependencies

Usage:
Single file: deMiner file.js
Multiple files & URLs: deMiner file.js file.json https://example.com
Piped input: cat urls.txt | deMiner

Installation:
git clone https://github.com/dedcrowd/Miner.git
cd Miner
go build -o deMiner miner.go
sudo mv deMiner /usr/local/bin/

Disclaimer:
Use responsibly. Only scan files/URLs you own or have permission for. Unauthorized scanning may be illegal.

Keywords:
API key scanner, secret finder, bug bounty, Go security tool, AWS key, GitHub token, Slack token, parallel scanning, ultra-fast, recon tool, subdomain enumeration, waybackurls, gau, pentest
