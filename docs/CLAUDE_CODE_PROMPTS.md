# Claude Code Prompts for MCP Audit

Copy and paste these prompts into Claude Code for continued development.

---

## Prompt 1: Initial Setup and Testing

```
I have an MCP Audit project in my current directory. Help me:

1. Review the project structure and ensure all files are correct
2. Install the CLI tool locally with `pip install -e .`
3. Run `mcp-audit scan --local` to test the CLI
4. Start the web app locally and test in browser
5. Fix any bugs or issues found

The project should have:
- Python CLI (mcp_audit/ directory)
- Static web app (webapp/ directory)
- Collector scripts (collectors/ directory)

After testing, give me a summary of what works and what needs fixing.
```

---

## Prompt 2: Add Trust Checking Feature

```
Add a trust checking feature to mcp-audit that verifies MCP sources.

Requirements:
1. New command: `mcp-audit trust --input inventory.json`
2. For npm packages:
   - Check npm registry for package info
   - Get download counts, last updated, publisher
   - Check for known vulnerabilities (via npm audit API or similar)
3. For GitHub sources:
   - Get repo stars, last commit, contributor count
   - Check if org is verified

Output should show trust score (HIGH/MEDIUM/LOW/UNKNOWN) for each MCP.

The scan command should also have a `--with-trust` flag that includes trust info.

Keep the security principles: minimal dependencies, document any new packages added.
```

---

## Prompt 3: Add Policy Validation Feature

```
Add a policy validation feature to mcp-audit.

Requirements:
1. New command: `mcp-audit policy --policy policy.yaml --input inventory.json`
2. Policy file format (YAML):
   ```yaml
   allowed_sources:
     - "@anthropic/*"
     - "@modelcontextprotocol/*"
   
   denied_capabilities:
     - shell-access
     - filesystem-write
   
   require_review:
     - unverified-source
   ```
3. Output should show:
   - VIOLATION: MCPs that break policy
   - WARNING: MCPs that require review
   - COMPLIANT: MCPs that pass

4. Exit code should be non-zero if violations exist (for CI/CD integration)

Include sample policy files for common use cases.
```

---

## Prompt 4: Deploy Web App to Vercel

```
Help me deploy the MCP Audit web app to Vercel.

1. The web app is in the webapp/ directory
2. It's a static site (HTML, CSS, JS only)
3. No build step required

Steps needed:
1. Create vercel.json configuration if needed
2. Walk me through Vercel CLI deployment
3. Suggest a good subdomain (e.g., mcp-audit.vercel.app)
4. Set up any headers needed for security (CSP, etc.)

Make sure the deployed app works exactly like local testing.
```

---

## Prompt 5: Add More MCP Detection Patterns

```
Enhance MCP detection in the scanners to catch more patterns.

Currently we detect:
- Claude Desktop config
- Cursor config
- VS Code/Continue config
- package.json dependencies
- requirements.txt dependencies

Add detection for:
1. Windsurf IDE MCP configs
2. Zed editor MCP configs (if applicable)
3. Any other AI IDEs that support MCP
4. Docker Compose files that might run MCP servers
5. Kubernetes manifests with MCP containers
6. AWS/GCP/Azure deployment configs for MCPs

For each new detection:
1. Research where configs are stored
2. Add scanner in mcp_audit/scanners/
3. Update the scan command to use it
4. Test with sample configs
```

---

## Prompt 6: Add GitHub Actions Integration

```
Create a GitHub Action that runs MCP Audit on a repository.

Requirements:
1. Create .github/workflows/mcp-audit.yml
2. Run on: push to main, pull requests
3. Scan the repository for MCP configs and dependencies
4. Output findings as:
   - GitHub Action summary
   - PR comment (on PRs)
   - SARIF format for GitHub Security tab
5. Fail the action if high-risk MCPs are found (configurable)

The action should be usable by any repo:
```yaml
- uses: apisec/mcp-audit-action@v1
  with:
    fail_on_risk: high
```

Include documentation for the action.
```

---

## Prompt 7: Create Comprehensive Test Suite

```
Create a test suite for mcp-audit.

Requirements:
1. Use pytest
2. Create test fixtures:
   - Sample Claude Desktop config
   - Sample Cursor config
   - Sample package.json with MCP deps
   - Sample collected configs from MDM
3. Test each scanner individually
4. Test the full scan command
5. Test the analyze command
6. Test output formatters (JSON, CSV, Markdown)
7. Test risk flag identification

Aim for >80% code coverage. Include both unit tests and integration tests.

Run tests with: `pytest --cov=mcp_audit tests/`
```

---

## Prompt 8: Fix Bugs After User Testing

```
I've tested mcp-audit and found these issues:

[PASTE YOUR ISSUES HERE]

Please:
1. Identify the root cause of each issue
2. Fix the bugs
3. Add tests to prevent regression
4. Update documentation if behavior changes

Show me the fixes and explain what was wrong.
```

---

## Prompt 9: Add Scheduled Scanning Report

```
Add a feature to generate periodic scan reports.

Requirements:
1. New command: `mcp-audit report --since 7d --compare-to baseline.json`
2. Report should show:
   - New MCPs since last scan
   - Removed MCPs since last scan
   - Changed MCPs (different version, different config)
   - Risk summary with trends
3. Output formats: HTML (email-friendly), Markdown, JSON
4. Include visual diff for changes

This helps security teams track MCP drift over time.
```

---

## Prompt 10: Package for Distribution

```
Prepare mcp-audit for public distribution.

1. Ensure pyproject.toml is production-ready
2. Create proper versioning (semantic versioning)
3. Add CHANGELOG.md
4. Add LICENSE file (MIT)
5. Add CONTRIBUTING.md
6. Create GitHub release workflow
7. Set up PyPI publishing (document steps)
8. Create homebrew formula for Mac users
9. Document installation methods

Test the full install flow from scratch to ensure it works for end users.
```

---

## Tips for Using Claude Code

1. **Run one prompt at a time** - Let it complete before moving to next
2. **Test after each change** - Run `mcp-audit scan --local` frequently
3. **Keep context** - If Claude Code loses context, paste relevant files
4. **Be specific about errors** - Include full error messages
5. **Review security changes** - Any new dependencies should be scrutinized

---

## Project Context (Paste if Claude Code needs context)

```
MCP Audit is a security tool for discovering Model Context Protocol (MCP) 
servers across an organization. It has three components:

1. CLI Tool (Python): Scans local machine for MCP configs
2. Web App (Static): Scans GitHub orgs for MCP configs  
3. MDM Collector (Shell): Collects configs from developer machines

Key principles:
- Minimal dependencies (only typer and rich for CLI)
- No backend/server for web app (all client-side)
- Privacy-first (no data transmission to APIsec)
- Security-focused (we review all code and deps)

Target users: AppSec teams evaluating MCP security posture
```
