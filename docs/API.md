# PenPard API Documentation

Base URL: `http://localhost:4000/api`

## Authentication

All authenticated endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <token>
```

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "securepass"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "super_admin",
    "credits": 100
  }
}
```

### Get Current User

```http
GET /auth/me
Authorization: Bearer <token>
```

**Response:**
```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "super_admin",
    "credits": 100
  }
}
```

---

## Scans

### Initiate Web Scan

```http
POST /scans/web
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Scan initiated",
  "creditsRemaining": 99
}
```

### Initiate Mobile Scan

```http
POST /scans/mobile
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <apk file>
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440001",
  "message": "Analysis initiated",
  "creditsRemaining": 99
}
```

### Get Scan Status

```http
GET /scans/:scanId
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "web",
  "target": "https://example.com",
  "status": "completed",
  "createdAt": "2026-01-17T12:00:00Z",
  "completedAt": "2026-01-17T12:05:00Z",
  "vulnerabilities": [
    {
      "id": 1,
      "name": "SQL Injection",
      "description": "SQL injection vulnerability in login form",
      "severity": "critical",
      "cvssScore": 9.8,
      "cwe": "89"
    }
  ]
}
```

### List Scans

```http
GET /scans
Authorization: Bearer <token>
```

**Response:**
```json
{
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "web",
      "target": "https://example.com",
      "status": "completed",
      "created_at": "2026-01-17T12:00:00Z"
    }
  ]
}
```

---

## Reports

### Get Report

```http
GET /reports/:scanId
Authorization: Bearer <token>
```

**Response:**
```json
{
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "reportUrl": "/api/reports/550e8400-e29b-41d4-a716-446655440000/download",
  "createdAt": "2026-01-17T12:05:00Z"
}
```

### Download Report PDF

```http
GET /reports/:scanId/download
Authorization: Bearer <token>
```

Returns: PDF file download

---

## Admin Endpoints

*Requires admin or super_admin role*

### List Users

```http
GET /admin/users
Authorization: Bearer <token>
```

### Create User (super_admin only)

```http
POST /admin/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123",
  "role": "user",
  "credits": 10
}
```

### Update User

```http
PUT /admin/users/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "role": "admin",
  "credits": 50
}
```

### Delete User (super_admin only)

```http
DELETE /admin/users/:id
Authorization: Bearer <token>
```

### Add Credits

```http
POST /admin/users/:id/credits
Authorization: Bearer <token>
Content-Type: application/json

{
  "amount": 10
}
```

### List Whitelists

```http
GET /admin/whitelists
Authorization: Bearer <token>
```

### Create Whitelist

```http
POST /admin/whitelists
Authorization: Bearer <token>
Content-Type: application/json

{
  "userId": 2,
  "domainPattern": "*.example.com"
}
```

### Delete Whitelist

```http
DELETE /admin/whitelists/:id
Authorization: Bearer <token>
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": true,
  "message": "Error description"
}
```

### Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Internal Server Error |

---

## Rate Limiting

- 100 requests per 15 minutes per IP
- Rate limit headers included in responses:
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`
