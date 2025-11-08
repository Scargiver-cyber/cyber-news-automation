#!/usr/bin/env python3
"""
Daily Cybersecurity News Agent
Fetches and summarizes cybersecurity news from multiple sources
"""

import os
import json
import requests
import feedparser
from datetime import datetime
from pathlib import Path
import google.generativeai as genai

# Configuration
OBSIDIAN_VAULT = "/Users/jasontilson/Library/Mobile Documents/com~apple~CloudDocs/Cyber Vault"
NEWS_FOLDER = "Daily News"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# News Sources - Major Cybersecurity News Sites Only
RSS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Threatpost": "https://threatpost.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
}


def fetch_rss_feed(url, source_name, limit=5):
    """Fetch and parse RSS feed"""
    try:
        feed = feedparser.parse(url)
        articles = []

        for entry in feed.entries[:limit]:
            articles.append({
                "title": entry.get("title", "No title"),
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
                "summary": entry.get("summary", "")[:300] + "..." if entry.get("summary") else "",
                "source": source_name
            })

        return articles
    except Exception as e:
        print(f"Error fetching {source_name}: {e}")
        return []


def fetch_all_news():
    """Fetch news from all sources"""
    all_articles = []

    print("Fetching from major security news sites...")
    for source, url in RSS_FEEDS.items():
        articles = fetch_rss_feed(url, source, limit=10)
        all_articles.extend(articles)

    return all_articles


def calculate_importance_score(article):
    """Calculate importance score based on keywords in title and summary"""
    text = (article['title'] + " " + article['summary']).lower()

    # High priority keywords
    critical_keywords = [
        'zero-day', 'zero day', 'ransomware', 'breach', 'hacked', 'exploit',
        'critical vulnerability', 'cve', 'data breach', 'supply chain',
        'nation-state', 'apt', 'malware', 'phishing', 'credential',
        'authentication', 'botnet', 'ddos', 'vulnerability', 'backdoor',
        'trojan', 'critical flaw', 'actively exploited', 'under attack',
        'threat actor', 'cyber attack', 'security flaw', 'remote code execution',
        'rce', 'sql injection', 'xss', 'patch', 'cisa', 'emergency',
        'millions impacted', 'data leak', 'stolen', 'compromised'
    ]

    score = 0
    for keyword in critical_keywords:
        if keyword in text:
            score += 2

    # Bonus for recent articles
    if 'today' in article.get('published', '').lower() or 'hours ago' in article.get('published', '').lower():
        score += 1

    return score


def summarize_with_gemini(articles):
    """Use Google Gemini to analyze and summarize the news articles"""
    if not GEMINI_API_KEY:
        print("⚠️  No Gemini API key found, falling back to keyword-based ranking...")
        return None

    try:
        # Configure Gemini
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')

        # Prepare article text for Gemini
        articles_text = ""
        for i, article in enumerate(articles, 1):
            articles_text += f"\n\n---\n**Article {i}: {article['source']}**\n"
            articles_text += f"Title: {article['title']}\n"
            articles_text += f"Link: {article['link']}\n"
            articles_text += f"Summary: {article['summary']}\n"

        prompt = f"""You are a cybersecurity analyst. Review the following cybersecurity news articles from today and identify the TOP 10 MOST IMPORTANT stories based on:
- Severity and impact of security threats
- Critical vulnerabilities or zero-days
- Significant threat actor campaigns
- Major security incidents or breaches
- Important security tool or technology releases
- Regulatory or policy changes affecting security

For each of the top 10 stories, provide:
1. **Story number and headline**
2. **Source and link**
3. **A detailed 3-4 sentence summary** explaining what happened, why it matters, and potential impact
4. **Severity rating** (Critical/High/Medium) if applicable

Format your response as:

## Top 10 Cybersecurity Stories

### 1. [Story Title]
**Source:** [Source Name]
**Link:** [URL]
**Summary:** [Your detailed 3-4 sentence summary here]
**Severity:** [Critical/High/Medium]

[Continue for all 10 stories]

Articles to analyze:
{articles_text}

Format your response in Markdown suitable for an Obsidian note. Only include the top 10 most important stories."""

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        print(f"⚠️  Gemini API error: {e}")
        print("Falling back to keyword-based ranking...")
        return None


def summarize_without_api(articles):
    """Rank and format top stories without using AI API"""
    # Score all articles
    scored_articles = []
    for article in articles:
        score = calculate_importance_score(article)
        if score > 0:  # Only include articles with some relevance
            scored_articles.append((score, article))

    # Sort by score and get top 10
    scored_articles.sort(reverse=True, key=lambda x: x[0])
    top_articles = [article for score, article in scored_articles[:10]]

    # Format the summary
    summary = "## Top 10 Cybersecurity Stories\n\n"
    summary += "*Stories ranked by severity and relevance based on keywords*\n\n"

    for i, article in enumerate(top_articles, 1):
        summary += f"### {i}. {article['title']}\n"
        summary += f"**Source:** {article['source']}\n"
        summary += f"**Link:** [{article['link']}]({article['link']})\n"

        # Determine severity based on keywords
        text = (article['title'] + " " + article['summary']).lower()
        if any(word in text for word in ['zero-day', 'critical', 'actively exploited', 'emergency', 'nation-state']):
            severity = "🔴 Critical"
        elif any(word in text for word in ['breach', 'ransomware', 'malware', 'vulnerability', 'exploit']):
            severity = "🟠 High"
        else:
            severity = "🟡 Medium"

        summary += f"**Severity:** {severity}\n"

        # Add summary if available
        if article['summary']:
            summary += f"\n{article['summary']}\n"

        summary += "\n---\n\n"

    return summary


def create_linkedin_post(articles):
    """Create a LinkedIn-ready post from top 5 articles"""
    # Score articles to get the top 5
    scored_articles = []
    for article in articles:
        score = calculate_importance_score(article)
        if score > 0:
            scored_articles.append((score, article))

    scored_articles.sort(reverse=True, key=lambda x: x[0])
    top_5 = [article for score, article in scored_articles[:5]]

    today = datetime.now()
    formatted_date = today.strftime("%B %d, %Y")

    # Create LinkedIn post
    linkedin_post = f"""📰 Cybersecurity News Update - {formatted_date}

Here are today's top 5 critical cybersecurity stories you need to know:

"""

    for i, article in enumerate(top_5, 1):
        # Determine emoji based on severity
        text = (article['title'] + " " + article['summary']).lower()
        if any(word in text for word in ['zero-day', 'critical', 'actively exploited', 'emergency', 'nation-state']):
            emoji = "🔴"
        elif any(word in text for word in ['breach', 'ransomware', 'malware', 'vulnerability', 'exploit']):
            emoji = "🟠"
        else:
            emoji = "🟡"

        linkedin_post += f"{i}. {emoji} {article['title']}\n"
        linkedin_post += f"   {article['link']}\n\n"

    linkedin_post += """Stay informed, stay secure! 🔒

#Cybersecurity #InfoSec #ThreatIntelligence #SecurityNews"""

    return linkedin_post


def create_obsidian_note(summary, articles):
    """Create markdown note in Obsidian vault"""
    today = datetime.now()
    date_str = today.strftime("%Y-%m-%d")
    formatted_date = today.strftime("%B %d, %Y")

    # Check if there are any critical stories (only include LinkedIn post if critical)
    has_critical = False
    scored_articles = []
    for article in articles:
        score = calculate_importance_score(article)
        if score > 0:
            scored_articles.append((score, article))

    # Check top 5 articles for critical stories
    scored_articles.sort(reverse=True, key=lambda x: x[0])
    top_5 = [article for score, article in scored_articles[:5]]

    for article in top_5:
        text = (article['title'] + " " + article['summary']).lower()
        if any(word in text for word in ['zero-day', 'critical', 'actively exploited', 'emergency', 'nation-state']):
            has_critical = True
            break

    # Create note content
    note_content = f"""---
date: {date_str}
tags: [cybersecurity, news, daily-brief, top-stories]
---

# Cybersecurity News Brief - {formatted_date}

"""

    # Only include LinkedIn post section if there are critical stories
    if has_critical:
        linkedin_post = create_linkedin_post(articles)
        note_content += f"""## ⚠️ CRITICAL ALERT - LinkedIn Post

```
{linkedin_post}
```

---

"""

    note_content += f"""{summary}

---

## All Source Articles

"""

    # Add all articles as references
    for article in articles:
        note_content += f"### [{article['title']}]({article['link']})\n"
        note_content += f"**Source:** {article['source']}\n"
        if article['published']:
            note_content += f"**Published:** {article['published']}\n"
        note_content += f"\n{article['summary']}\n\n---\n\n"

    note_content += f"\n\n*Generated on {formatted_date} at {today.strftime('%I:%M %p')}*\n"

    # Save to Obsidian vault
    vault_path = Path(OBSIDIAN_VAULT) / NEWS_FOLDER
    vault_path.mkdir(exist_ok=True)

    note_path = vault_path / f"Daily Brief - {date_str}.md"

    with open(note_path, 'w', encoding='utf-8') as f:
        f.write(note_content)

    print(f"\n✅ Note created: {note_path}")
    return note_path


def main():
    """Main execution function"""
    print("🔍 Starting Cybersecurity News Agent...")
    print(f"📅 Date: {datetime.now().strftime('%B %d, %Y')}\n")

    # Fetch news
    articles = fetch_all_news()
    print(f"\n📰 Fetched {len(articles)} articles from all sources")

    if not articles:
        print("❌ No articles fetched. Exiting.")
        return

    # Summarize with AI (Gemini) or fall back to keyword-based ranking
    print("\n🤖 Analyzing and ranking stories with AI...")
    summary = summarize_with_gemini(articles)

    if not summary:
        print("\n📊 Using keyword-based ranking...")
        summary = summarize_without_api(articles)

    # Create Obsidian note
    print("\n📝 Creating Obsidian note...")
    note_path = create_obsidian_note(summary, articles)

    print("\n✨ Daily brief complete!")


if __name__ == "__main__":
    main()
