#!/usr/bin/env python3
"""
Weekly Cybersecurity News Digest
Aggregates top stories from the week and creates a professional LinkedIn post
"""

import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Configuration
OBSIDIAN_VAULT = "/Users/jasontilson/Documents/Big Bad"
DAILY_NEWS_FOLDER = "Cyber News/Daily News"
WEEKLY_DIGEST_FOLDER = "Cyber News/Weekly News"


def get_week_date_range():
    """Get the date range for the current week (Monday-Friday)"""
    today = datetime.now()

    # Find the most recent Friday (including today if it's Friday)
    days_since_friday = (today.weekday() - 4) % 7
    if days_since_friday == 0 and today.hour < 18:  # If it's Friday but before 6 PM
        # Use previous week
        friday = today - timedelta(days=7)
    else:
        friday = today - timedelta(days=days_since_friday)

    # Monday is 4 days before Friday
    monday = friday - timedelta(days=4)

    return monday, friday


def parse_daily_brief(file_path):
    """Parse a daily brief file and extract top stories"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        stories = []

        # Extract stories from the "Top 10 Cybersecurity Stories" section
        # Look for pattern: ### N. Title
        story_pattern = r'### (\d+)\.\s+(.+?)\n\*\*Source:\*\*\s+(.+?)\n\*\*Link:\*\*\s+\[?(.+?)\]?\((.+?)\)\n\*\*Severity:\*\*\s+(.+?)(?:\n\n|\n(?![\s]))'

        matches = re.finditer(story_pattern, content, re.DOTALL)

        for match in matches:
            story = {
                'title': match.group(2).strip(),
                'source': match.group(3).strip(),
                'link': match.group(5).strip(),
                'severity': match.group(6).strip(),
                'date': file_path.stem.replace('Daily Brief - ', '')
            }
            stories.append(story)

        return stories
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return []


def aggregate_weekly_stories():
    """Aggregate stories from the week's daily briefs"""
    monday, friday = get_week_date_range()

    daily_news_path = Path(OBSIDIAN_VAULT) / DAILY_NEWS_FOLDER

    all_stories = []
    dates_checked = []

    # Check each day from Monday to Friday
    current_date = monday
    while current_date <= friday:
        date_str = current_date.strftime("%Y-%m-%d")
        brief_file = daily_news_path / f"Daily Brief - {date_str}.md"

        dates_checked.append(date_str)

        if brief_file.exists():
            print(f"📖 Reading brief from {date_str}...")
            stories = parse_daily_brief(brief_file)
            all_stories.extend(stories)
        else:
            print(f"⚠️  No brief found for {date_str}")

        current_date += timedelta(days=1)

    return all_stories, monday, friday, dates_checked


def rank_weekly_stories(stories):
    """Rank stories by severity and deduplicate"""
    # Severity weights
    severity_weights = {
        '🔴 Critical': 3,
        '🟠 High': 2,
        '🟡 Medium': 1
    }

    # Track unique stories by title (case-insensitive)
    unique_stories = {}

    for story in stories:
        title_key = story['title'].lower().strip()

        # If we've seen this story, keep the one with higher severity
        if title_key in unique_stories:
            existing_weight = severity_weights.get(unique_stories[title_key]['severity'], 0)
            new_weight = severity_weights.get(story['severity'], 0)

            if new_weight > existing_weight:
                unique_stories[title_key] = story
        else:
            unique_stories[title_key] = story

    # Sort by severity
    ranked_stories = sorted(
        unique_stories.values(),
        key=lambda x: severity_weights.get(x['severity'], 0),
        reverse=True
    )

    return ranked_stories[:5]  # Top 5


def create_linkedin_post(top_stories, monday, friday):
    """Create a professional LinkedIn post for the week"""
    week_range = f"{monday.strftime('%B %d')} - {friday.strftime('%B %d, %Y')}"

    post = f"""Weekly Cybersecurity Briefing | {week_range}

Team,

This week's threat landscape analysis highlights five critical developments requiring your attention. I've reviewed the most significant incidents and vulnerabilities that could impact our security posture and broader industry operations.

KEY ISSUES THIS WEEK:

"""

    for i, story in enumerate(top_stories, 1):
        # Get severity level without emoji for cleaner professional text
        severity_text = story['severity'].replace('🔴 ', '').replace('🟠 ', '').replace('🟡 ', '')
        severity_emoji = ''
        if '🔴' in story['severity']:
            severity_emoji = '🔴 '
        elif '🟠' in story['severity']:
            severity_emoji = '🟠 '
        elif '🟡' in story['severity']:
            severity_emoji = '🟡 '

        post += f"{i}. {severity_emoji}{story['title']}\n"
        post += f"   [{severity_text}] {story['source']}\n"
        post += f"   📎 {story['link']}\n\n"

    post += """RECOMMENDED ACTIONS:
• Review these developments with your security teams
• Assess potential impact on your infrastructure
• Update incident response plans as needed
• Brief stakeholders on emerging threat vectors

Our security posture depends on staying ahead of these evolving threats. Let's ensure we're proactive, not reactive.

Questions or need additional context? Feel free to reach out.

#Cybersecurity #InfoSec #ThreatIntelligence #SecurityLeadership #CISO #RiskManagement"""

    return post


def create_weekly_digest(top_stories, all_stories_count, monday, friday, dates_checked):
    """Create the weekly digest Obsidian note"""
    today = datetime.now()
    week_range = f"{monday.strftime('%B %d')} - {friday.strftime('%B %d, %Y')}"
    file_date = friday.strftime("%Y-%m-%d")

    # Create LinkedIn post
    linkedin_post = create_linkedin_post(top_stories, monday, friday)

    # Calculate severity breakdown
    critical_count = sum(1 for s in top_stories if '🔴' in s['severity'])
    high_count = sum(1 for s in top_stories if '🟠' in s['severity'])
    medium_count = sum(1 for s in top_stories if '🟡' in s['severity'])

    # Create note content
    note_content = f"""---
date: {file_date}
week_start: {monday.strftime("%Y-%m-%d")}
week_end: {friday.strftime("%Y-%m-%d")}
tags: [cybersecurity, news, weekly-digest, weekly-briefing, threat-intelligence]
---

# Weekly Cybersecurity Briefing | {week_range}

## Executive Summary

This briefing consolidates the five most critical cybersecurity developments from the week of {week_range}. These issues represent significant threats, vulnerabilities, and incidents that require awareness and potential action from security teams.

**Intelligence Summary:**
- 📊 **Total Stories Analyzed:** {all_stories_count} incidents and developments
- 🔴 **Critical Issues:** {critical_count}
- 🟠 **High Priority:** {high_count}
- 🟡 **Medium Priority:** {medium_count}
- 📅 **Coverage Period:** {len([d for d in dates_checked if (Path(OBSIDIAN_VAULT) / DAILY_NEWS_FOLDER / f"Daily Brief - {d}.md").exists()])} days of monitoring

---

## 🎯 LinkedIn Post - Ready to Share

```
{linkedin_post}
```

---

## 📰 Top 5 Critical Issues This Week

"""

    # Add detailed story breakdown with professional context
    for i, story in enumerate(top_stories, 1):
        # Get clean severity text
        severity_text = story['severity'].replace('🔴 ', '').replace('🟠 ', '').replace('🟡 ', '')

        note_content += f"### Issue #{i}: {story['title']}\n\n"
        note_content += f"**Severity Level:** {story['severity']}\n\n"
        note_content += f"**Source Intelligence:** {story['source']} | **First Detected:** {story['date']}\n\n"
        note_content += f"**Primary Reference:** [{story['link']}]({story['link']})\n\n"

        # Add context based on severity
        if '🔴' in story['severity']:
            note_content += "**Impact Assessment:** This represents a critical-level threat requiring immediate attention. "
            note_content += "Security teams should prioritize assessment and response planning.\n\n"
        elif '🟠' in story['severity']:
            note_content += "**Impact Assessment:** High-priority issue with significant potential impact. "
            note_content += "Recommend review within 24-48 hours and implementation of appropriate safeguards.\n\n"
        else:
            note_content += "**Impact Assessment:** Moderate-priority development warranting awareness and monitoring. "
            note_content += "Should be incorporated into ongoing security planning.\n\n"

        note_content += f"**Recommended Actions:**\n"
        note_content += f"- Review the full report: [Link to Source]({story['link']})\n"
        note_content += f"- Assess potential exposure within your infrastructure\n"
        note_content += f"- Document findings and mitigation steps\n"
        note_content += f"- Brief relevant stakeholders as appropriate\n\n"

        note_content += "---\n\n"

    note_content += f"""
## 📋 Weekly Intelligence Report

**Analysis Period:** {week_range}

**Monitoring Coverage:**
{chr(10).join([f'- {d} {"✅ Monitored" if (Path(OBSIDIAN_VAULT) / DAILY_NEWS_FOLDER / f"Daily Brief - {d}.md").exists() else "⚠️ No Data"}' for d in dates_checked])}

**Total Incidents Tracked:** {all_stories_count}

**Key Takeaways:**
- The cybersecurity landscape this week showed {'heightened' if critical_count > 0 else 'moderate'} threat activity
- Primary focus areas: Vulnerability management, threat actor campaigns, and security incidents
- Continuous monitoring and proactive defense remain essential

---

## 🔗 Related Resources

For additional context on this week's developments, refer to:
- Daily briefing notes in `[[Daily News]]` folder
- Individual source reports linked above
- Organization-specific threat intelligence feeds

---

*This briefing was generated on {today.strftime('%B %d, %Y')} at {today.strftime('%I:%M %p')}*

*Classification: Internal Use | Distribution: Security Team*
"""

    # Save to Obsidian vault
    vault_path = Path(OBSIDIAN_VAULT) / WEEKLY_DIGEST_FOLDER
    vault_path.mkdir(parents=True, exist_ok=True)

    note_path = vault_path / f"Weekly Digest - {file_date}.md"

    with open(note_path, 'w', encoding='utf-8') as f:
        f.write(note_content)

    print(f"\n✅ Weekly digest created: {note_path}")
    return note_path


def main():
    """Main execution function"""
    print("📊 Starting Weekly Cybersecurity Digest Generator...")
    print(f"📅 Date: {datetime.now().strftime('%B %d, %Y %I:%M %p')}\n")

    # Aggregate stories from the week
    print("🔍 Aggregating stories from this week's daily briefs...\n")
    all_stories, monday, friday, dates_checked = aggregate_weekly_stories()

    if not all_stories:
        print("❌ No stories found in daily briefs. Exiting.")
        return

    print(f"\n📊 Found {len(all_stories)} total stories from the week")

    # Rank and deduplicate
    print("🎯 Ranking and selecting top 5 critical issues...\n")
    top_stories = rank_weekly_stories(all_stories)

    print(f"✨ Selected {len(top_stories)} critical issues for briefing")

    # Create weekly digest
    print("\n📝 Creating weekly digest note...")
    note_path = create_weekly_digest(top_stories, len(all_stories), monday, friday, dates_checked)

    print("\n✨ Weekly briefing complete!")
    print(f"📅 Week: {monday.strftime('%B %d')} - {friday.strftime('%B %d, %Y')}")
    print(f"📰 Critical Issues: {len(top_stories)}")
    print(f"📍 Location: {note_path}")


if __name__ == "__main__":
    main()
