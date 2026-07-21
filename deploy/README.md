# Deploy — persistence for native (non-Docker) aiScraper

These configs keep aiScraper running in the background on a local machine
(only Postgres stays containerized).  Fill in the placeholder paths before
installing.

---

## Linux (systemd user service)

```bash
# Copy and edit
mkdir -p ~/.config/systemd/user
cp deploy/systemd/ai-scraper.service ~/.config/systemd/user/
# Open ~/.config/systemd/user/ai-scraper.service and replace:
#   /path/to/aiScraper  → the actual repo path

# Enable and start
systemctl --user daemon-reload
systemctl --user enable --now ai-scraper.service

# View logs
journalctl --user -u ai-scraper.service -f

# Stop
systemctl --user stop ai-scraper.service
```

---

## macOS (launchd user agent)

```bash
# Copy and edit
cp deploy/launchd/com.aiscraper.local.plist ~/Library/LaunchAgents/
# Open ~/Library/LaunchAgents/com.aiscraper.local.plist and replace:
#   /path/to/aiScraper          → the actual repo path
#   REPLACE_WITH_YOUR_USERNAME  → your macOS username

# Load (starts immediately and on login)
launchctl load ~/Library/LaunchAgents/com.aiscraper.local.plist

# View logs
tail -f ~/Library/Logs/ai-scraper.log
tail -f ~/Library/Logs/ai-scraper-error.log

# Stop / unload
launchctl unload ~/Library/LaunchAgents/com.aiscraper.local.plist
```
