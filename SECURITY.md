# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ Yes |
| 1.0.x   | ✅ Yes (critical fixes only) |
| < 1.0   | ❌ No |

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### 🔒 Private Disclosure (Preferred)

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report via:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the [Security tab](https://github.com/Flechzao/API-Sentinel/security/advisories)
2. **Email**: Send details to the maintainers (check recent commits for contact info)

### What to Include

- **Description**: What's the vulnerability?
- **Impact**: What can an attacker do? (e.g., RCE, data leak, privilege escalation)
- **Steps to reproduce**: Minimal code/config to demonstrate the issue
- **Proof of concept**: If applicable
- **Suggested fix**: If you have ideas (optional)

### Response Timeline

| Phase | Timeframe |
|-------|-----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Varies (1-30 days depending on complexity) |
| Public disclosure | After fix is released (or 90 days, whichever comes first) |

---

## Vulnerability Scope

### In Scope

- **Code execution** in the Burp extension (e.g., unsafe deserialization, code injection)
- **Prompt injection** that bypasses anti-hallucination defenses
- **Authentication bypass** in MCP Server (Bearer token, CSRF, DNS rebinding)
- **Data leakage** (e.g., credentials, API keys, sensitive traffic)
- **Privilege escalation** (e.g., sandbox escape, unauthorized tool access)
- **Denial of service** that crashes Burp Suite or the extension

### Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Issues in Burp Suite itself (report to PortSwigger)
- Social engineering attacks
- Physical access attacks
- Issues requiring user to install malicious extensions

---

## Security Features

API Sentinel includes several security mechanisms:

### 1. Anti-Hallucination Defense

Three-layer protection against LLM hallucinations:

- **Prompt-level rules**: `SafetyRules` with 12 NEVER_CONFIRM rules
- **Programmatic validation**: `VerdictValidator` checks payload binding, evidence anchoring
- **Identity audit**: IDOR/auth-bypass findings require three-question identity proof

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) §Anti-Hallucination for details.

### 2. MCP Server Security

- **Bearer token authentication**: Random 256-bit token, printed to Burp console
- **CSRF protection**: Rejects requests with `Origin` header
- **DNS rebinding protection**: Validates `Host` header matches `127.0.0.1:<port>` or `localhost:<port>`
- **Content-Type validation**: Requires `application/json`
- **Localhost-only binding**: `ServerSocket` binds to `127.0.0.1` only

### 3. Untrusted Content Fencing

- **Nonce-based wrapping**: `UntrustedContent.wrap(nonce, raw)` isolates attacker-controlled data
- **Sanitization**: Strips fence markers, markdown headers, "UNTRUSTED" keywords from untrusted content
- **128-bit random nonce**: Per-analysis, unpredictable, prevents fence forgery

### 4. Tool Permission Model

- **Read-only tools** (heuristic_scan, search_source_code): Always available
- **Active tools** (send_request, verify_*): Require user opt-in for MCP external clients
- **Destructive tools** (browser_auto_crawl): Confirmation dialogs + audit logging

### 5. Evidence-Driven Verdicts

- **Confirmed vulnerabilities** must cite real payload execution (payload binding check)
- **Evidence anchoring**: `response_snippet` must be substring of real response
- **WAF-blocked payloads** cannot serve as evidence
- **HIGH risk** requires at least one surviving confirmed vulnerability

---

## Security Best Practices for Users

### 1. Authorized Testing Only

⚠️ **Only test systems you own or have explicit written authorization to test.**

Unauthorized security testing is illegal in most jurisdictions. See [LEGAL.md](LEGAL.md).

### 2. MCP Server Configuration

- **Never expose MCP Server to the internet** (it binds to localhost only by design)
- **Keep the Bearer token secret** (it's printed to Burp console on startup)
- **Enable active tools only for trusted MCP clients** (`mcpAllowActiveTools=false` by default)

### 3. AI Provider Security

- **Local models** (Ollama): Data never leaves your machine
- **Cloud providers** (Claude/OpenAI): Traffic sent to external APIs
  - Review provider's data retention policy
  - Disable `includeRawCredentialsInLlm` if concerned (default: `false`)

### 4. Sensitive Data Handling

- **API keys**: Stored in `~/.api-sentinel/ai-config.json`, never bundled in JAR
- **Traffic data**: Stored in `~/.api-sentinel/data.json`
- **Logs**: May contain sensitive data, review before sharing

### 5. Network Security

- **MCP Server**: Binds to `127.0.0.1` only, not accessible from network
- **Browser automation**: Playwright runs locally, no remote browser service
- **OOB callbacks**: Collaborator/internal dnslog only, no arbitrary outbound

---

## Known Limitations

### 1. LLM Hallucinations

Despite three-layer defenses, LLMs can still hallucinate. Always verify:

- **Confirmed vulnerabilities** have real payload execution evidence
- **Suspected vulnerabilities** require manual verification
- **Check `rejectionReasons`** for downgrade audit trail

### 2. False Positives

Some patterns are inherently ambiguous:

- **5xx responses**: Server error ≠ vulnerability (intentionally not flagged)
- **WAF blocks**: Blocked payload ≠ successful attack
- **Informational findings**: Missing headers, version exposure (downgraded from confirmed)

### 3. Prompt Injection

While nonce-based fencing mitigates most attacks:

- **Sophisticated attackers** may find novel injection vectors
- **Report any bypass** via private disclosure (see above)

---

## Security Updates

Subscribe to security announcements:

- **GitHub**: Watch the repository for release notifications
- **CHANGELOG.md**: Security fixes marked with 🔒 emoji

---

## Responsible Disclosure Hall of Fame

We acknowledge researchers who report vulnerabilities responsibly:

| Researcher | Date | Finding |
|------------|------|---------|
| *(Your name here!)* | *(Date)* | *(Brief description)* |

*To be added: Report a valid vulnerability and request attribution.*

---

## Contact

- **Security issues**: Use GitHub Security Advisories (see above)
- **General questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue (non-security only)

---

## License

This security policy is part of the API Sentinel project, licensed under MIT (see [LICENSE](LICENSE)).
