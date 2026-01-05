# Privacy Q&A

**Q: Does any company data leave the browser?**

A: No. Your GitHub token and code never touch our servers. The scanning happens entirely client-side - your browser talks directly to GitHub's API. We only collect anonymous usage analytics (page views, scan counts, number of MCPs found) with no company data, no organization names, no repository names, and no MCP configurations.

**Q: What analytics do you collect?**

A: We collect only anonymous, aggregate metrics:
- Page views
- Number of scans run
- Count of MCPs found (not what they are)
- Export format used (JSON/CSV/Markdown)
- CLI downloads

We do NOT collect:
- GitHub tokens
- Organization or user names
- Repository names
- MCP configurations or contents
- Source code
- Any identifying information

**Q: Where does the scanning happen?**

A: All scanning runs in your browser. When you scan GitHub repositories, your browser makes direct API calls to GitHub using your token. The results are displayed locally and never sent to our servers.

**Q: Is the CLI tool also private?**

A: Yes. The CLI runs 100% locally on your machine. It scans local configuration files and outputs results to your terminal or local files. There is no telemetry or phone-home capability in the CLI.

**Q: Can I use this in an air-gapped environment?**

A: The CLI works fully offline. The web app requires internet access only to reach GitHub's API - it does not require connectivity to any APIsec servers.
