# Sensitive Routes Sample Site

A test site for verifying sensitive route matching (prefix, regex, suffix, wildcard) with the PX PHP enforcer.

## Setup

### Option 1: PHP built-in server

```bash
cd examples/sample-site

# Install dependencies (from the SDK root)
composer install --no-dev

# Start the server
PX_APP_ID=<YOUR_APP_ID> \
PX_COOKIE_KEY=<YOUR_COOKIE_KEY> \
PX_AUTH_TOKEN=<YOUR_AUTH_TOKEN> \
php -S localhost:8080 router.php
```

### Option 2: Docker

```bash
cd examples/sample-site

# Edit docker-compose.yml and fill in your PX credentials, then:
docker compose up --build
```

Open http://localhost:8080 in your browser.

## Configured sensitive routes

| Pattern | Type | Matches |
|---|---|---|
| `/login` | Prefix | `/login`, `/login/reset`, `/loginx` |
| `/^\/api\/.*\/payment$/i` | Regex | `/api/v1/payment`, `/API/v2/Payment` |
| `/.*\/checkout$/` | Regex (suffix) | `/shop/checkout` |
| `/^\/admin$/` | Regex (exact) | `/admin` only, not `/admin/settings` |
| `/^\/account\/.*\/delete$/` | Regex | `/account/123/delete` |
| `/.*\.json$/` | Regex (extension) | `/data/config.json` |

## Testing

1. Open a **non-sensitive** page first (e.g. `/about`) so the PX sensor sets a valid cookie.
2. Navigate to a **sensitive** route — check your PX logs for `s2s_call_reason: sensitive_route`.
3. Compare with non-sensitive routes (`/contact`, `/api/v1/users`) which should show no Risk API call when the cookie is valid.

Normalization test URLs:
- `http://localhost:8080/logi%6E` — URL decoding
- `http://localhost:8080/fake/../login` — traversal resolution
- `http://localhost:8080/login/?foo=bar` — trailing slash + query string stripping
