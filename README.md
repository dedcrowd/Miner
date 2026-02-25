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
