# Changelog

All notable changes to PenPard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-17

### Added

#### Core Features
- **Web Application Scanning**: Automated vulnerability testing using Burp Suite integration
- **Mobile App Analysis**: APK security analysis via MobSF integration
- **AI-Enhanced Testing**: OWASP Top 10/20 vulnerability detection with LLM-powered agents
- **PDF Report Generation**: Comprehensive reports with CVSS 4.0 scores

#### User Management
- JWT-based authentication system
- Role-based access control (Super Admin, Admin, User)
- User creation and management via admin panel
- Default admin account (admin/securepass)

#### Credits System
- Per-user credit allocation
- Credit deduction on scan initiation
- Admin credit assignment
- Low credit warnings (yellow <10, red <5)

#### Whitelists
- Domain-based scan restrictions per user
- Wildcard pattern support (*.example.com)
- Admin-managed whitelist configuration

#### Integrations
- Burp Suite Professional REST API
- MobSF REST API for mobile analysis
- Graceful fallback when tools unavailable

#### AI Agents
- Scan Agent: Orchestrates vulnerability testing
- Recheck Agent: Validates findings, filters false positives
- Report Agent: Generates PDF reports with CVSS scores
- Oversight Agent: Chains agents with retry logic

### Security
- bcrypt password hashing
- JWT token authentication
- Rate limiting on API endpoints
- Helmet security headers
- Input validation and sanitization
- CORS protection

### Infrastructure
- Docker Compose orchestration
- SQLite database for data persistence
- Winston logging with file rotation
- Volume mounts for tool integration

---

## [Unreleased]

### Planned
- Cloud deployment support (AWS/Azure)
- Partner ecosystem integration
- Email notifications for scan completion
- Scheduled/recurring scans
- Team collaboration features
- Custom scan configurations
- Vulnerability remediation tracking
- Git-based rollback via UI
