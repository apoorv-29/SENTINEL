# 🛡️ SENTINEL

**Zero-trust security intelligence for URLs, source code and API responses.**

Authenticated, organization-scoped scanning with a multi-page dashboard, live charts, team chat and voice messages.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-FF6384?logo=chartdotjs&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)

</div>

---

## Overview

SENTINEL helps a team review the security posture of the things they ship. Paste a URL, a code snippet or a set of response headers, and it flags common red flags (phishing patterns, missing HTTPS, hardcoded secrets, absent rate-limit headers). Results are stored per organization, summarized automatically, and shown on a dashboard with charts and graphs.

Every API request is authenticated and every query is filtered by organization on the server, so one tenant can never read another tenant's scans.

> **Note:** SENTINEL uses heuristics. An empty result is not proof that an asset is safe. Only scan targets and source code you are authorized to assess.

<!-- Add screenshots to docs/ and uncomment:
![Overview](docs/overview.png)
![Analytics](docs/analytics.png)
-->

## Features

**Security scanning**
- **URL analysis:** flags missing HTTPS, unusually hyphenated hostnames and keywords often used in phishing (`login`, `verify`, `wallet`, ...).
- **Secret detection:** finds hardcoded API keys, secret tokens and private keys in pasted source code.
- **Header checks:** reports when no rate-limit header is present.
- **Evidence graph:** each scan produces a graph linking the target to its findings.

**Platform**
- **Auth:** registration and login with salted `scrypt` password hashing, 15-minute access tokens and rotating 7-day refresh tokens.
- **Multi-tenancy:** an organization is created at registration, and all scans are scoped to it.
- **Search:** filter scans by text, severity, category and status, with browser text-to-speech to read results aloud.
- **Automated summary:** `GET /api/v1/automation/scan-summary` returns scan count, finding count and severity/category totals in a single call.
- **Team chat:** persisted direct messages over REST with live delivery over WebSocket.
- **Voice messages:** record a short clip from the home page and send it to a teammate. Audio is only downloadable by the sender and recipient.

**Dashboard (8 pages)**

| Page | What it shows |
|---|---|
| Overview | Totals, severity doughnut, findings by category, threat categories, live feed, API endpoint posture, voice bar |
| Scanner | URL, code and header form with a per-scan severity chart |
| Scans | Scan history with a graph for each selected scan |
| Analytics | Stacked findings per scan, risk score gauge, scans over time, category radar |
| Trust Graph | The zero-trust request path as an interactive graph |
| Search | Filters and read-aloud |
| Chat | Teammate lookup and live messaging |
| Account | Sign in, register, session details |

Pages fade in on navigation, cards animate on scroll, and a progress bar tracks the page position. Signed-out visitors see clearly labelled sample data.

## Tech stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI, Pydantic v2, Uvicorn |
| Storage | SQLite (interim; see [Roadmap](#roadmap)) |
| Frontend | Single HTML file, Tailwind CSS, Chart.js, vis-network, Lucide icons |
| Realtime | WebSocket (chat and voice notifications), `MediaRecorder` API (voice) |
| Packaging | Docker |
| Testing | pytest, httpx |

## Getting started

### Run locally

```bash
git clone https://github.com/<your-username>/sentinel.git
cd sentinel

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn main:app --reload
```

Open **http://127.0.0.1:8000/** for the dashboard and **/docs** for the interactive API reference.

1. Go to the **Account** page and register. Passwords need at least 12 characters.
2. Open **Scanner** and run a scan.
3. Check **Overview** and **Analytics** to see your data.
<img width="1366" height="730" alt="Screenshot (182)" src="https://github.com/user-attachments/assets/c98dd886-d086-4258-a326-3cd5555f1541" />
<img width="1366" height="725" alt="Screenshot (183)" src="https://github.com/user-attachments/assets/8e868e93-506c-4df9-8783-cce115892d36" />
<img width="1366" height="730" alt="Screenshot (184)" src="https://github.com/user-attachments/assets/7133ea1b-2ca0-425e-bb7d-9b228fa04561" />
<img width="1366" height="730" alt="Screenshot (185)" src="https://github.com/user-attachments/assets/6feaa426-c872-4bca-b58b-d0414d99f469" />
<img width="1366" height="725" alt="Screenshot (186)" src="https://github.com/user-attachments/assets/e414ae9d-539c-430b-8d58-35726856c94f" />
<img width="1366" height="730" alt="Screenshot (187)" src="https://github.com/user-attachments/assets/c55b9ae1-15e9-486b-8521-9de5b2a63030" />
