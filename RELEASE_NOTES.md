# MCP Audit Release Notes

---

## v0.1.2 - December 19, 2024

### Security: Registry Integrity Check

Added SHA-256 hash verification for the MCP registry file to detect tampering.

**What it does:**
- Verifies `known_mcps.json` hasn't been modified on each load
- Displays warning if tampering is detected
- Tool continues to work but warns user that trust data may be unreliable

**If tampering is detected, you'll see:**
```
WARNING: Registry integrity check failed! The known_mcps.json file may have been tampered with. Registry trust data may be unreliable. Re-install mcp-audit to restore the official registry.
```

**Thanks to** the security researcher who reported this via responsible disclosure.

### How to Update

1. Download latest CLI from https://apisec-inc.github.io/mcp-audit/
2. Extract the zip
3. Reinstall:
   ```bash
   cd mcp-audit-cli
   pip install -e . --force-reinstall
   ```

---

## v0.1.1 - December 18, 2024

### Remote/Hosted MCP Support

MCP Audit now correctly identifies and matches remote MCPs that connect via URL endpoints (SSE, HTTP) rather than local commands.

**Before:** Remote MCPs like GitHub's hosted MCP showed as "Unknown" with no registry match.

**After:** Remote MCPs are detected, matched against our registry, and display proper provider/verification info.

### Changes

- **Remote MCP Detection:** Now parses `url`, `serverUrl`, `endpoint`, and `uri` fields in MCP configs
- **Transport Detection:** Recognizes `sse`, `http`, `websocket` transport types
- **Registry Matching:** Matches remote MCPs by endpoint URL/domain in addition to package name
- **Name Matching:** Falls back to matching by MCP name (e.g., "github" matches GitHub MCP)
- **New Risk Flag:** Adds `remote-mcp` flag for URL-based MCPs
- **Registry Update:** Added GitHub's official hosted MCP endpoint (`https://mcp.github.com`)

### Example

Config like this now works correctly:
```json
{
  "github": {
    "url": "https://mcp.github.com/sse"
  }
}
```

Scan output:
```
MCP Name: github
Source: https://mcp.github.com/sse
Type: remote
Known: Yes
Provider: GitHub
Verified: Yes
Risk: high
```

---

## v0.1.0 - December 11, 2024

Initial release.

- Local scanning: Claude Desktop, Cursor, VS Code, Windsurf, Zed
- Project scanning: mcp.json, .mcp/, package.json, requirements.txt, docker-compose.yml
- Registry of 50+ known MCPs with risk levels
- Risk flag detection: secrets-in-env, shell-access, database-access, filesystem-access, local-binary
- Export formats: JSON, CSV, Markdown
- Policy enforcement via YAML
