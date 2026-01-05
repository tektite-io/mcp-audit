# MCP Audit - Verified Registry Q&A

## Q: How does MCP Audit determine if an MCP is "verified" or "known"?

A: MCP Audit maintains a curated registry of known MCP servers. When we scan and discover an MCP, we check if its package name matches an entry in our registry. If it matches, we mark it as "known" and display the trust information we've recorded (provider, risk level, capabilities). MCPs are marked as "verified" if they're maintained by trusted publishers: Anthropic/Model Context Protocol org (official), or the actual service vendor (e.g., Stripe, AWS, Salesforce). Community-built MCPs are in our registry but marked as unverified. If an MCP isn't in our registry at all, it shows as "unknown" - which is the highest concern since we have no information about it.

---

## Registry Listing (50 MCPs)

### Official (Anthropic / Model Context Protocol)

| MCP | Package | Risk | Verified |
|-----|---------|------|----------|
| Filesystem | `@modelcontextprotocol/server-filesystem` | High | Yes |
| GitHub | `@modelcontextprotocol/server-github` | High | Yes |
| GitLab | `@modelcontextprotocol/server-gitlab` | High | Yes |
| Google Drive | `@modelcontextprotocol/server-google-drive` | High | Yes |
| Slack | `@modelcontextprotocol/server-slack` | Medium | Yes |
| PostgreSQL | `@modelcontextprotocol/server-postgres` | Critical | Yes |
| SQLite | `@modelcontextprotocol/server-sqlite` | High | Yes |
| Memory | `@modelcontextprotocol/server-memory` | Low | Yes |
| Puppeteer | `@modelcontextprotocol/server-puppeteer` | Critical | Yes |
| Brave Search | `@modelcontextprotocol/server-brave-search` | Low | Yes |
| Fetch | `@modelcontextprotocol/server-fetch` | Medium | Yes |

### Vendor (Service Providers)

| MCP | Provider | Package | Risk | Verified |
|-----|----------|---------|------|----------|
| Asana | Asana | `asana-mcp` | Medium | Yes |
| Linear | Linear | `linear-mcp` | Medium | Yes |
| Notion | Notion | `notion-mcp` | Medium | Yes |
| Jira | Atlassian | `jira-mcp` | Medium | Yes |
| Confluence | Atlassian | `confluence-mcp` | Medium | Yes |
| Trello | Atlassian | `trello-mcp` | Low | Yes |
| Airtable | Airtable | `airtable-mcp` | Medium | Yes |
| Monday.com | Monday.com | `monday-mcp` | Medium | Yes |
| ClickUp | ClickUp | `clickup-mcp` | Medium | Yes |
| HubSpot | HubSpot | `hubspot-mcp` | High | Yes |
| Salesforce | Salesforce | `salesforce-mcp` | High | Yes |
| Zendesk | Zendesk | `zendesk-mcp` | Medium | Yes |
| Intercom | Intercom | `intercom-mcp` | Medium | Yes |
| Twilio | Twilio | `twilio-mcp` | High | Yes |
| SendGrid | Twilio | `sendgrid-mcp` | Medium | Yes |
| Stripe | Stripe | `stripe-mcp` | Critical | Yes |
| AWS | Amazon | `aws-mcp` | Critical | Yes |
| Google Cloud | Google | `gcp-mcp` | Critical | Yes |
| Azure | Microsoft | `azure-mcp` | Critical | Yes |
| Datadog | Datadog | `datadog-mcp` | Medium | Yes |
| PagerDuty | PagerDuty | `pagerduty-mcp` | Medium | Yes |
| Sentry | Sentry | `sentry-mcp` | Low | Yes |
| Figma | Figma | `figma-mcp` | Low | Yes |
| Dropbox | Dropbox | `dropbox-mcp` | High | Yes |
| Box | Box | `box-mcp` | High | Yes |
| Todoist | Doist | `todoist-mcp` | Low | Yes |
| Shopify | Shopify | `shopify-mcp` | High | Yes |
| QuickBooks | Intuit | `quickbooks-mcp` | Critical | Yes |
| Xero | Xero | `xero-mcp` | Critical | Yes |

### Community (Unverified)

| MCP | Package | Risk | Verified |
|-----|---------|------|----------|
| Discord | `discord-mcp` | Medium | No |
| Telegram | `telegram-mcp` | Medium | No |

---

## Risk Level Definitions

| Level | Meaning |
|-------|---------|
| **Critical** | Full access to sensitive systems (databases, cloud infrastructure, financial data) |
| **High** | Write access to important data or systems |
| **Medium** | Read/write access to business data |
| **Low** | Read-only or limited scope access |
