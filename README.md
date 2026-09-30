# Shortly - URL Shortener (Python / Flask)

A web service that turns long URLs into short links, redirects visitors, tracks clicks, and lets users and an admin manage links.

**Tech stack:** Python 3 · Flask · SQLite (built in) · HTML/CSS/JavaScript dashboard · `unittest` for tests

## 1. Features
- Shorten long URLs into unique 7-character Base62 codes
- Custom aliases (`/my-brand`) and optional link expiry
- Same user + same URL returns the existing short link (no duplicates)
- Fast redirect engine (in-memory LRU cache, HTTP 302); analytics logging never blocks a redirect
- Analytics per link: total clicks, referrers, countries, clicks per day
- User sign-up / login, personal dashboard (view, copy, stats, delete)
- Admin dashboard (first registered user is admin): platform totals, all links, remove any link
- Per-IP rate limiting, input validation, security headers

## 2. System architecture
```
Browser (dashboard)  ->  Flask REST API  ->  SQLite (users, links, clicks)
Visitor /<code>      ->  Cache lookup -> DB fallback -> log click -> 302 redirect
```

## 3. URL shortening workflow
1. User submits a long URL (optional alias / expiry)
2. Validate: must be http(s), not this service, alias is 3-32 safe characters and not reserved
3. If the user already shortened this URL, return the existing link
4. Generate a random Base62 code (retry on collision) or use the alias (409 if taken)
5. Store in the database and return the short URL
6. On visit: find the link (cache first), check expiry (410 if expired), record the click, redirect

## 4. Database design
| Table | Columns |
|---|---|
| users | id, email (unique), hash, is_admin |
| links | id, code (unique), url, user_id -> users, expires_at, created_at |
| clicks | id, link_id -> links (ON DELETE CASCADE), ts, referrer, country, ua |

Index on `clicks(link_id, ts)` keeps analytics queries fast.

## 5. REST API
Send the token as `Authorization: Bearer <token>`.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /api/v1/auth/register | - | Sign up, returns token |
| POST | /api/v1/auth/login | - | Log in, returns token |
| GET | /api/v1/auth/me | user | Current user and admin flag |
| POST | /api/v1/links | optional | Create link `{url, alias?, expiresAt?}` |
| GET | /api/v1/links | user | List my links with click counts |
| GET | /{shortCode} | - | Redirect (302) and log click |
| GET | /api/v1/links/{id}/stats | owner | Click analytics |
| DELETE | /api/v1/links/{id} | owner | Delete a link |
| GET | /api/v1/admin/overview | admin | Totals and all links |
| DELETE | /api/v1/admin/links/{id} | admin | Remove any link |

## 6. Security and performance
- Passwords hashed (Werkzeug), signed expiring tokens (7 days)
- Parameterised SQL queries (no SQL injection); output escaped in the dashboard (no XSS)
- Only http/https URLs accepted; reserved aliases blocked; ownership checks on stats/delete
- Rate limits per IP: 60 API calls/min, 20 auth attempts/15 min, 300 redirects/min
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- LRU cache for redirects, DB index on clicks

## 7. Run
Windows: double-click `run.bat`. Or manually:
```
python -m venv venv
venv\Scripts\activate          (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python app.py
```
Open http://localhost:3000. Optional env vars: `PORT`, `JWT_SECRET`, `DB_PATH`.

## 8. Testing
```
python -m unittest -v
```
12 tests cover auth, shortening, aliases, expiry, redirects, analytics, ownership, admin access and rate limiting.

## 9. Future enhancements
Redis cache, PostgreSQL, QR codes, link editing, real GeoIP lookup, email verification, Docker deployment.
