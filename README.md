# Cyber News Automation

Automated cybersecurity news aggregation and summarization system that delivers daily briefings and weekly digests to an Obsidian vault.

## Overview

This project fetches cybersecurity news from major security websites, ranks stories by severity and relevance, and generates markdown notes for consumption in Obsidian. It can optionally use Google Gemini AI for intelligent summarization or fall back to keyword-based ranking.

## Features

- **Daily News Briefs**: Automated daily aggregation from 6+ major cybersecurity news sources
- **Weekly Digests**: Curated weekly summaries of the most critical security issues
- **Smart Ranking**: AI-powered (Gemini) or keyword-based story prioritization
- **Obsidian Integration**: Automatic markdown note generation with proper frontmatter
- **LinkedIn Post Generation**: Pre-formatted posts for critical security alerts
- **Scheduled Execution**: Configured to run via macOS launchd

## News Sources

- The Hacker News
- Bleeping Computer
- Krebs on Security
- Dark Reading
- Threatpost
- SecurityWeek

## Project Structure

```
cyber-news-automation/
├── scripts/
│   ├── cyber_news_agent.py        # Daily news aggregator
│   └── weekly_cyber_news.py       # Weekly digest generator
├── logs/                           # Execution logs (created at runtime)
├── setup_cyber_news_api.sh        # API key configuration script
└── README.md
```

## Installation

### Prerequisites

- Python 3.8+
- Required packages:
  - `feedparser`
  - `requests`
  - `google-generativeai` (optional, for AI summarization)

### Setup

1. Install dependencies:
```bash
pip install feedparser requests google-generativeai
```

2. (Optional) Configure Gemini API key:
```bash
./setup_cyber_news_api.sh
```

Or manually set environment variable:
```bash
export GEMINI_API_KEY="your-api-key-here"
```

3. Configure Obsidian vault path in scripts:
```python
OBSIDIAN_VAULT = "/path/to/your/Cyber Vault"
```

## Usage

### Manual Execution

**Daily News:**
```bash
python3 scripts/cyber_news_agent.py
```

**Weekly Digest:**
```bash
python3 scripts/weekly_cyber_news.py
```

### Automated Scheduling (macOS)

The project includes launchd configuration for automated execution:

- **Daily News**: Runs at 10:00 AM daily
- **Weekly Digest**: Runs every Friday at 6:00 PM

Launch agent configuration files are located in `~/Library/LaunchAgents/`:
- `com.cybernews.agent.plist`
- `com.weeklycybernews.agent.plist`

## Output

### Daily Brief Format

- **Frontmatter**: Date, tags for categorization
- **Critical Alert Section**: LinkedIn-ready post (if critical stories detected)
- **Top 10 Stories**: Ranked by severity with summaries
- **All Source Articles**: Complete feed of all fetched articles

Output location: `[Obsidian Vault]/Daily News/Daily Brief - YYYY-MM-DD.md`

### Weekly Digest Format

- **Executive Summary**: Overview of the week's security landscape
- **Top 5 Critical Issues**: Most important security stories
- **Emerging Threats**: New threat vectors and campaigns
- **Notable Vulnerabilities**: CVEs and patches
- **Industry News**: Significant security industry developments

Output location: `[Obsidian Vault]/Weekly Digest/Weekly Digest - YYYY-MM-DD.md`

## Configuration

### Environment Variables

- `GEMINI_API_KEY`: Optional Google Gemini API key for AI summarization
- If not set, scripts fall back to keyword-based ranking

### Customization

Edit the following in scripts:

**News Sources** (`cyber_news_agent.py`):
```python
RSS_FEEDS = {
    "Source Name": "https://feed-url.com/rss",
    # Add or remove sources here
}
```

**Severity Keywords** (`cyber_news_agent.py`):
```python
critical_keywords = [
    'zero-day', 'ransomware', 'breach',
    # Customize keywords for ranking
]
```

## Troubleshooting

### No articles fetched
- Check internet connection
- Verify RSS feed URLs are still valid
- Check for rate limiting from news sources

### Obsidian notes not appearing
- Verify `OBSIDIAN_VAULT` path is correct
- Ensure write permissions to vault directory
- Check if vault is synced (iCloud, Dropbox, etc.)

### API errors
- Verify `GEMINI_API_KEY` is set correctly
- Check API quota limits
- Scripts will automatically fall back to keyword ranking if API fails

## Log Files

Execution logs are written to:
- Standard output: `~/cyber_news_agent.log` (daily)
- Standard error: `~/cyber_news_agent_error.log` (daily)
- Weekly logs: `~/weekly_cyber_news.log` and `~/weekly_cyber_news_error.log`

## Contributing

This is a personal project, but suggestions and improvements are welcome.

## License

Personal use project. Modify as needed for your own automation needs.

## Author

Jason Tilson - Cybersecurity professional and automation enthusiast

## Notes

- The system works without AI API keys by using keyword-based ranking
- RSS feeds may change over time; monitor and update as needed
- Consider adding your own trusted security news sources
