# MCP Audit - PR/FAQ

## Press Release

### APIsec Launches MCP Audit: Free Tool to Discover and Assess AI Plugin Security Risks

**San Francisco, CA** – APIsec today announced the launch of MCP Audit, a free security tool that helps organizations discover and assess Model Context Protocol (MCP) servers deployed across their development environments. As AI assistants like Claude, Cursor, and GitHub Copilot become integral to software development, MCP Audit addresses the growing security blind spot of unmonitored AI plugins.

MCP servers are plugins that extend AI assistants with powerful capabilities – from reading files and accessing databases to executing shell commands and connecting to cloud services. While these integrations boost developer productivity, they also introduce significant security risks that most organizations aren't tracking.

"Development teams are rapidly adopting AI assistants without realizing they're also deploying dozens of MCP plugins with varying levels of access to sensitive systems," said Rajaram Ramanathan, founder of APIsec. "MCP Audit gives security teams visibility into what's actually deployed, so they can make informed decisions about AI tool governance."

**Key Features:**

- **Web-based GitHub scanning** – Scan entire GitHub organizations for MCP configurations without installing anything
- **Local system auditing** – CLI tool scans developer machines for MCP configs in Claude Desktop, Cursor, VS Code, and more
- **Known MCP registry** – Database of 50+ verified MCP servers with risk assessments
- **Heuristic risk scoring** – Automatically assesses unknown MCPs based on capabilities and configuration
- **Privacy-first design** – All scanning happens client-side; credentials never leave your browser

MCP Audit is available immediately at https://apisec-inc.github.io/mcp-audit/

---

## Frequently Asked Questions

### General Questions

**Q: What is MCP Audit?**

A: MCP Audit is a free, open-source security tool that discovers and assesses MCP (Model Context Protocol) servers across your organization. It scans GitHub repositories and local developer machines to find MCP configurations, then assesses their security risk based on a curated registry and heuristic analysis.

**Q: What is MCP (Model Context Protocol)?**

A: MCP is a standard protocol that allows AI assistants (like Claude, Cursor, GitHub Copilot) to connect with external tools and data sources. MCP servers are plugins that give AI assistants capabilities like reading files, querying databases, sending messages, or executing commands. Think of them as "extensions" for AI tools.

**Q: Why should I care about MCP security?**

A: MCP servers can have significant access to sensitive systems:
- **Filesystem access** – Read/write any files on a developer's machine
- **Database access** – Query and modify production databases
- **Shell access** – Execute arbitrary commands
- **API access** – Connect to Slack, GitHub, cloud providers with stored credentials

Without visibility into what MCPs are deployed, you have a security blind spot in your development environment.

**Q: Who is this tool for?**

A: MCP Audit is designed for:
- **Security teams** – Get visibility into AI tool deployments across the organization
- **IT administrators** – Audit developer machines for unauthorized plugins
- **Engineering managers** – Understand what AI capabilities teams are using
- **Individual developers** – Check your own setup for risky configurations

**Q: Is MCP Audit free?**

A: Yes, MCP Audit is completely free and open-source. There are no premium tiers, usage limits, or hidden costs.

---

### Privacy & Security

**Q: Is my data safe when using the web app?**

A: Yes. The web app runs entirely in your browser – your GitHub token and code never leave your machine. We don't have servers that process your data. The only information sent externally is anonymous usage analytics (page views, scan counts) to help us improve the product.

**Q: What analytics do you collect?**

A: We collect anonymous, aggregate metrics only:
- Page views and tab clicks
- Number of scans performed
- Count of MCPs found (not the actual MCP names or configurations)
- Export format used

We do NOT collect: GitHub tokens, repository names, code content, MCP configurations, or any personally identifiable information.

**Q: Can I use this on private repositories?**

A: Yes. The scanning happens in your browser using your GitHub token. Private repository contents are never sent to our servers.

**Q: Is the CLI tool safe to run on my machine?**

A: Yes. The CLI tool runs 100% locally and doesn't send any data anywhere. You can review the source code on GitHub.

---

### Web App Questions

**Q: How does the GitHub scanning work?**

A: The web app uses GitHub's API (authenticated with your personal access token) to:
1. List all repositories in your organization
2. Check each repo for known MCP config files (mcp.json, package.json, etc.)
3. Search for MCP-related patterns using GitHub's code search
4. Download and parse configuration files to extract MCP details
5. Match found MCPs against our known registry

All of this happens in your browser – we never see your code or token.

**Q: What GitHub permissions does the token need?**

A: The token needs:
- `repo` – To read repository contents (including private repos)
- `read:org` – To list organizations you belong to

**Q: Why isn't the scan finding MCPs in my new repository?**

A: GitHub's code search index can take 15-30 minutes to index new repositories. However, MCP Audit also does direct file checks, so it should find MCPs in common locations (mcp.json, package.json) immediately.

**Q: What source code platforms are supported?**

A: Currently, only GitHub is supported. GitLab, Bitbucket, Azure DevOps, and SVN support are planned for future releases.

---

### CLI Tool Questions

**Q: What does the CLI tool scan?**

A: The CLI scans MCP configurations in:
- **Claude Desktop** – Anthropic's desktop application
- **Cursor** – AI-powered code editor
- **VS Code** – With Continue extension
- **Windsurf** – Codeium's editor
- **Zed** – Modern code editor
- **Project folders** – .mcp/ directories and mcp.json files

**Q: How do I install the CLI?**

A: Download the CLI from the web app or install from source:
```bash
pip install -e .
mcp-audit scan
```

Requires Python 3.9 or higher.

**Q: Can I integrate the CLI into CI/CD pipelines?**

A: Yes! Use the JSON output format:
```bash
mcp-audit scan --format json --output results.json
```

Then parse the results in your pipeline to fail builds with unauthorized MCPs.

---

### Risk Assessment Questions

**Q: How are risk levels determined?**

A: Risk levels are assigned based on the MCP's capabilities:

| Risk Level | Criteria |
|------------|----------|
| **Critical** | Database write, cloud infrastructure, payments, shell execution |
| **High** | Filesystem write, browser automation, email sending |
| **Medium** | API access, messaging (Slack, Discord), calendar |
| **Low** | Read-only access, search, memory/cache |

**Q: What does "Known" vs "Unknown" mean?**

A:
- **Known** – The MCP is in our curated registry of verified MCP servers. We've reviewed it and assigned a risk level.
- **Unknown** – The MCP is not in our registry. It may be legitimate but requires manual review. Risk is calculated using heuristics.

**Q: How does heuristic risk scoring work?**

A: For unknown MCPs, we analyze:
- **Name/source keywords** – "shell", "database", "filesystem" increase risk
- **Environment variables** – Presence of PASSWORD, TOKEN, SECRET, API_KEY
- **Command type** – Local scripts, shell commands, Docker containers
- **Publisher verification** – Whether it's from a known vendor (@anthropic, @stripe, etc.)

**Q: Can I add MCPs to the known registry?**

A: The registry is maintained by APIsec. If you'd like to submit an MCP for inclusion, please open an issue on our GitHub repository with the MCP details.

---

### Enterprise Questions

**Q: Can I deploy this internally?**

A: Yes. The web app is static HTML/CSS/JS and can be hosted on any internal web server. The CLI can be installed on any machine with Python.

**Q: Do you offer an enterprise version?**

A: Not currently. MCP Audit is free for all users. If you have specific enterprise needs (custom integrations, SLA support, on-premise deployment assistance), please contact us at rajaram@apisec.ai.

**Q: Can I scan multiple organizations?**

A: Yes. The web app allows you to select any organization your GitHub token has access to. Run separate scans for each org.

**Q: How do I collect MCP configs from all developer machines?**

A: Use the MDM collector scripts included with the CLI:
- `collectors/collect-macos.sh` – For Mac computers
- `collectors/collect-windows.ps1` – For Windows computers

Deploy these via your MDM solution (Jamf, Intune, etc.) to gather configs centrally.

---

### Troubleshooting

**Q: The scan shows 0 MCPs but I know we have some. Why?**

A: Common causes:
1. MCPs are in private repos your token can't access
2. MCPs are configured locally on developer machines (use the CLI tool)
3. Config files use non-standard names or locations
4. GitHub's search index hasn't updated yet (wait 15-30 minutes)

**Q: The web app won't connect to GitHub. What's wrong?**

A: Check that:
1. Your token is valid and not expired
2. Token has `repo` and `read:org` scopes
3. You're not hitting GitHub's rate limits (wait a few minutes)

**Q: Export isn't working. What should I do?**

A: The export creates a file download. Make sure your browser isn't blocking downloads from the site. Try a different browser if issues persist.

---

### Future Roadmap

**Q: What features are planned?**

A: Upcoming features include:
- GitLab, Bitbucket, Azure DevOps scanning
- Policy enforcement (block unapproved MCPs)
- Scheduled automated scans
- Slack/email notifications for new MCPs
- Integration with SIEM tools
- MCP behavior monitoring (runtime analysis)

**Q: How can I request a feature?**

A: Open an issue on our GitHub repository: https://github.com/apisec-inc/mcp-audit/issues

---

## Contact

- **Website**: https://apisec-inc.github.io/mcp-audit/
- **GitHub**: https://github.com/apisec-inc/mcp-audit
- **Email**: rajaram@apisec.ai
- **Company**: https://apisec.ai
