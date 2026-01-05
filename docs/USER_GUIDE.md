# MCP Audit - User Guide

## What is MCP Audit?

MCP Audit is a security tool that helps you discover and track **MCP servers** (Model Context Protocol servers) in your organization.

### What are MCP Servers?

MCP servers are plugins that give AI assistants (like Claude, Cursor, or GitHub Copilot) special abilities - like reading files, accessing databases, or connecting to services like Slack or GitHub. While powerful, these plugins can pose security risks if not properly monitored.

**Think of it like this:** MCP servers are like giving your AI assistant keys to different rooms in your house. MCP Audit helps you see which keys exist and who has them.

---

## Two Ways to Use MCP Audit

MCP Audit comes in **two versions** for different needs:

| Feature | CLI Tool | Web App |
|---------|----------|---------|
| **What it scans** | Your computer | GitHub repositories |
| **Installation** | Requires Python | None (runs in browser) |
| **Best for** | Individual developers, IT teams | Security teams, managers |
| **Data privacy** | Runs locally | All data stays in your browser |

### Quick Comparison

```
┌─────────────────────────────────────────────────────────────┐
│                      MCP AUDIT                               │
├─────────────────────────┬───────────────────────────────────┤
│      CLI TOOL           │          WEB APP                  │
│  (Command Line)         │      (Browser-based)              │
├─────────────────────────┼───────────────────────────────────┤
│  Scans YOUR computer    │  Scans GitHub organization        │
│  for MCP configs in:    │  repositories for MCP configs     │
│  • Claude Desktop       │                                   │
│  • Cursor               │  Just need a GitHub token         │
│  • VS Code              │  to get started                   │
│  • Windsurf             │                                   │
│  • Zed                  │  Perfect for:                     │
│                         │  • Quick org-wide visibility      │
│  Perfect for:           │  • Sharing results with team      │
│  • Deep local analysis  │  • No installation needed         │
│  • Policy enforcement   │                                   │
│  • CI/CD integration    │                                   │
└─────────────────────────┴───────────────────────────────────┘
```

---

## Part 1: Using the Web App (Easiest)

The web app lets you scan your GitHub organization for MCP configurations without installing anything.

### Step 1: Open the Web App

Open `index.html` in your web browser, or visit the hosted version at your organization's URL.

### Step 2: Connect to GitHub

1. You'll need a **GitHub Personal Access Token**
2. Click the link to create one, or go to: `GitHub Settings → Developer Settings → Personal Access Tokens`
3. Create a token with these permissions:
   - `repo` (to read repository contents)
   - `read:org` (to see your organizations)
4. Paste the token and click **Connect to GitHub**

### Step 3: Select and Scan

1. Choose your organization from the dropdown
2. Click **Scan Organization**
3. Wait for the scan to complete (usually 1-2 minutes)

### Step 4: Review Results

You'll see a table showing:
- **MCP Name** - The name of the MCP server
- **Source** - Where it comes from (npm package, Python, etc.)
- **Repository** - Which repo contains this config
- **Known** - Whether it's in our trusted registry
- **Provider** - Who made this MCP
- **Risk Level** - How much access this MCP has
- **Risk Flags** - Specific concerns (filesystem access, shell access, etc.)

### Step 5: Export Results

Click **Export JSON**, **Export CSV**, or **Export Markdown** to save your results for reporting.

---

## Part 2: Using the CLI Tool (More Powerful)

The command-line tool offers more features and can scan your local computer.

### Installation

#### Option A: Download from Web App (Easiest)

1. Open the MCP Audit web app in your browser
2. Scroll to the bottom and click **"Download CLI Tool (ZIP)"**
3. Unzip the downloaded file
4. Open Terminal (Mac) or Command Prompt (Windows)
5. Navigate to the folder: `cd mcp-audit-cli`
6. Install: `pip install -e .`
7. Test: `mcp-audit --help`

#### Option B: Install from Source

```bash
# 1. Open Terminal (Mac) or Command Prompt (Windows)

# 2. Navigate to the mcp-audit folder
cd /path/to/mcp-audit

# 3. Install with pip
pip install -e .

# 4. Test the installation
mcp-audit --help
```

**Troubleshooting:**
- If you get "command not found", try: `python -m mcp_audit.cli --help`
- If pip fails, make sure you have Python 3.9 or higher: `python --version`
- On Mac, you may need to use `pip3` instead of `pip`

### Basic Commands

#### Scan Your Computer

```bash
# Basic scan - finds all MCP configs on your machine
mcp-audit scan

# Scan with detailed output
mcp-audit scan --verbose

# Scan a specific project folder
mcp-audit scan --path /path/to/project

# Export results to a file
mcp-audit scan --format json --output results.json
```

#### View the Known MCP Registry

```bash
# See all known MCPs
mcp-audit registry

# See only high-risk MCPs
mcp-audit registry --risk critical

# Look up a specific MCP
mcp-audit registry lookup "@anthropic/mcp-server-filesystem"

# See registry statistics
mcp-audit registry stats
```

#### Check Trust Scores

```bash
# Scan with trust checking (checks npm/GitHub for package reputation)
mcp-audit scan --with-trust
```

#### Validate Against Security Policies

```bash
# Check if your MCPs comply with a security policy
mcp-audit policy validate --policy policies/strict.yaml
```

---

## Understanding the Results

### Risk Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **CRITICAL** | Red | Full access to sensitive systems (databases, cloud, payments) |
| **HIGH** | Orange | Write access to important data or systems |
| **MEDIUM** | Yellow | Read/write access to business data |
| **LOW** | Green | Read-only or limited scope access |

### Risk Flags

| Flag | What It Means |
|------|---------------|
| `filesystem-access` | Can read/write files on your computer |
| `database-access` | Can access databases |
| `shell-access` | Can run commands on your computer |
| `network-access` | Can make web requests |
| `secrets-in-env` | Has API keys or passwords in config |
| `unverified-source` | Not from a known/trusted publisher |
| `local-binary` | Running a local script (not a package) |

### Known vs Unknown MCPs

- **Known (Green)**: This MCP is in our registry of recognized MCP servers
- **Unknown (Red)**: This MCP is not in our registry - may need review

---

## Common Use Cases

### For Developers

**"What MCPs do I have installed?"**
```bash
mcp-audit scan --verbose
```

**"Is this MCP safe to use?"**
```bash
mcp-audit registry lookup "package-name"
mcp-audit trust check "package-name"
```

### For Security Teams

**"Show me all critical-risk MCPs in our org"**
```bash
mcp-audit registry --risk critical
```

**"Export a compliance report"**
```bash
mcp-audit scan --format json --output audit-report.json
```

**"Check against our security policy"**
```bash
mcp-audit policy validate --policy policies/enterprise.yaml
```

### For IT Administrators

**"Collect MCP configs from all developer machines"**

Use the MDM collector scripts in `mdm-collectors/` folder:
- `collect-macos.sh` - For Mac computers
- `collect-windows.ps1` - For Windows computers

---

## Frequently Asked Questions

### Is my data safe?

**Yes!**
- The CLI tool runs entirely on your computer - no data is sent anywhere
- The Web App runs entirely in your browser - your GitHub token and code never leave your browser

### What applications does MCP Audit check?

The CLI tool scans configurations for:
- Claude Desktop
- Cursor
- VS Code (with Continue extension)
- Windsurf
- Zed Editor
- Docker/Kubernetes configs
- Project-level `.mcp/` folders

### How often should I run a scan?

We recommend:
- **Weekly** for individual developers
- **Before deployments** for CI/CD pipelines
- **Monthly** for organization-wide audits

### What should I do if I find a risky MCP?

1. **Review** - Check if the MCP is actually needed
2. **Verify** - Look up the MCP in the registry to confirm it's legitimate
3. **Assess** - Determine if the risk level is acceptable for your use case
4. **Act** - Either keep it (with documentation) or remove it

---

## Getting Help

- **Documentation**: Check the `docs/` folder for more detailed guides
- **CLI Help**: Run `mcp-audit --help` for command options

---

## Quick Reference Card

```
┌────────────────────────────────────────────────────────────┐
│                 MCP AUDIT QUICK REFERENCE                  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  SCAN COMMANDS                                             │
│  ─────────────                                             │
│  mcp-audit scan              # Scan local machine          │
│  mcp-audit scan -v           # Verbose output              │
│  mcp-audit scan -p ./path    # Scan specific folder        │
│  mcp-audit scan -f json      # Output as JSON              │
│                                                            │
│  REGISTRY COMMANDS                                         │
│  ─────────────────                                         │
│  mcp-audit registry          # List all known MCPs         │
│  mcp-audit registry stats    # Show statistics             │
│  mcp-audit registry lookup X # Look up specific MCP        │
│  mcp-audit registry -r high  # Filter by risk level        │
│                                                            │
│  OTHER COMMANDS                                            │
│  ──────────────                                            │
│  mcp-audit trust check X     # Check trust score           │
│  mcp-audit policy validate   # Validate against policy     │
│  mcp-audit --help            # Show all options            │
│                                                            │
│  RISK LEVELS                                               │
│  ───────────                                               │
│  CRITICAL = Full system access (databases, cloud)          │
│  HIGH     = Write access to important data                 │
│  MEDIUM   = Read/write business data                       │
│  LOW      = Read-only or limited access                    │
│                                                            │
└────────────────────────────────────────────────────────────┘
```
