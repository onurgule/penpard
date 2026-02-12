# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in PenPard, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email us at **thepenpard@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge your report within **48 hours**.
- **Assessment**: We will assess the vulnerability and determine its severity within **7 days**.
- **Fix**: Critical vulnerabilities will be patched as quickly as possible.
- **Disclosure**: We will coordinate with you on public disclosure timing.

### Scope

The following are in scope:

- PenPard backend API (Express.js)
- PenPard frontend (Next.js)
- PenPard Electron shell
- PenPard MCP Connect Burp extension
- Authentication and authorization mechanisms
- Data storage and handling

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these to the respective projects)
- Social engineering attacks
- Denial of service attacks

### Default Credentials

PenPard uses a **lock screen** model. There are no traditional username/password login credentials.

| Item | Default Value | Change In |
|------|--------------|-----------|
| Lock Key | `penpard` | Settings → Lock Key |

The backend also creates an internal `operator` user (used for scan ownership). This user is not directly accessible via the lock screen UI.

**These defaults must be changed immediately after first use.** This is documented behavior, not a vulnerability.

## Security Best Practices for Users

1. **Change the default lock key** immediately after installation
2. **Set a strong `JWT_SECRET`** in your `.env` file (if not set, a random key is generated per restart)
3. **Set `CORS_ORIGINS`** in your `.env` if deploying beyond localhost
4. **Keep PenPard updated** to the latest version
5. **Only use PenPard for authorized security testing** — unauthorized testing is illegal
6. **Do not expose PenPard's backend port** (4000) to the public internet

## Acknowledgments

We appreciate the security research community's efforts in helping keep PenPard secure. Reporters of valid vulnerabilities will be acknowledged here (with permission).
