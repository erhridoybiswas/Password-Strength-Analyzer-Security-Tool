# 🔐 Password Strength Analyzer & Security Suggestion Tool

A privacy-focused, defensive cybersecurity tool that evaluates password
strength using **length**, **unpredictability**, **pattern resistance**,
**common-password checks**, and **context** — not composition rules alone.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Overview

`Password123!` satisfies every classic composition rule and is still one of
the weakest passwords you can choose. This project demonstrates why, and
provides a transparent, explainable alternative.

## Problem Statement

Composition rules (uppercase + lowercase + number + symbol) measure *which
characters exist*, not *how predictable the whole string is*. Modern guidance
favours length, unpredictability, breach checks, and context-aware scoring.

## Objectives

- Analyze passwords locally, in memory
- Score 0–100 with documented, explainable components
- Detect patterns: sequences, keyboard walks, repetition, predictable structures
- Provide specific, actionable security suggestions
- Educate on passphrases, entropy, hashing and MFA
- Never store, log, or transmit user passwords

## Cybersecurity Relevance

Maps directly to Authentication, IAM, Application Security, Secure Coding and
Security Awareness practices.

## Features

- Real-time strength meter with classification
- Length, character, sequence, keyboard, repetition and structure analysis
- Common-password detection (educational local list)
- Optional personal-context overlap warning (never stored)
- Theoretical + practical entropy estimation
- Specific, actionable security suggestions
- Policy checker (separate from strength score)
- Secure password & passphrase generator (`secrets`)
- Privacy-safe analytics dashboard
- 45+ automated tests including privacy tests

## Architecture

```
User → Web UI → POST /api/analyze → In-memory analyzers
     → Scoring Engine → Suggestions → User
     (optional) Aggregate metadata → SQLite → Dashboard
```

## Technology Stack

- **Backend:** Python 3.10+, Flask 3
- **Frontend:** HTML, CSS, vanilla JavaScript
- **Charts:** Chart.js
- **Analytics:** SQLite (metadata only)
- **Tests:** pytest
- **Hashing demo:** argon2-cffi

## Password Analysis

Every analysis returns:

```json
{
  "score": 74,
  "classification": "STRONG",
  "findings": [ ... ],
  "suggestions": [ ... ],
  "metrics": { ... },
  "policy": { ... }
}
```

## Length Analysis

| Length | Band |
|---|---|
| < 8 | Very short |
| 8–11 | Short |
| 12–15 | Better length |
| 16+ | Strong length contribution |

> Length alone is not security. `aaaaaaaaaaaaaaaaaaaa` is 20 chars and weak.

## Pattern Detection

- Ascending / descending sequences (`abcd`, `9876`)
- Keyboard walks (`qwerty`, `asdf`, `zxcv`)
- Repeated characters and repeated substrings
- Word + number templates (`welcome123`)
- Year fragments (`1998`, `2026`)

## Common Password Detection

Uses `data/common_passwords.txt` — a small, educational, non-personal list.
Matching passwords are hard-capped at 15/100.

## Entropy Estimation

```
theoretical_bits = L × log2(N)
practical_bits   = theoretical_bits × pattern_penalty_factor
```

Entropy alone is not used for scoring — it is always combined with pattern
analysis, because human passwords are not random.

## Strength Scoring

| Component | Max |
|---|---|
| Length | +35 |
| Character diversity | +15 |
| Unique-character ratio | +10 |
| Pattern resistance | +20 |
| Non-common password | +10 |
| Additional unpredictability | +10 |

| Score | Classification |
|---|---|
| 0–20 | VERY WEAK |
| 21–40 | WEAK |
| 41–60 | MODERATE |
| 61–80 | STRONG |
| 81–100 | VERY STRONG |

> These bands are project-defined, not universal standards.

## Security Suggestions

Specific and actionable, e.g.:

- "Your password contains a predictable numeric sequence."
- "Consider using a longer password or passphrase."
- "Enable Multi-Factor Authentication (MFA) wherever available."

Suggestions never echo the submitted password.

## Password Generator

Uses Python's `secrets` (CSPRNG) — **never** `random`. Nothing is stored.

## Password Policy Checker

Reports `POLICY PASS` / `POLICY FAIL` separately from the strength score.

## Privacy Design

- Passwords are processed **in memory only**
- Never logged
- Never stored in the database
- Never returned in API responses
- Never placed in URLs
- No `localStorage` / `sessionStorage` usage
- Analytics stores only: `score`, `classification`, `length`, `unique_ratio`,
  `weakness_count`, `created_at` and finding type/severity/description

## Installation

```bash
git clone <repository-url>
cd Password-Strength-Analyzer
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

## Usage

```bash
python -m backend.app
# open http://127.0.0.1:5000
```

## API Documentation

### `POST /api/analyze`

Request:
```json
{ "password": "<transient>", "context": { "first_name": "Demo" } }
```

Response:
```json
{
  "score": 74,
  "classification": "STRONG",
  "findings": [],
  "suggestions": [],
  "metrics": {},
  "policy": { "policy_pass": true, "violations": [] }
}
```

**Status codes:** `200` OK · `400` invalid request · `413` payload too large · `500` server error

### `GET /api/dashboard/stats`
### `GET /api/analytics/weaknesses`
### `POST /api/generate-password`
### `POST /api/generate-passphrase`

## Testing

```bash
pytest -v
```

## Security Testing

See `tests/test_privacy.py` — verifies that passwords are not stored,
not logged, not returned and not written to the database.

## Results

- Correctly classifies common passwords as VERY WEAK regardless of composition
- Correctly penalizes keyboard walks, sequences and repetition
- Correctly rewards long, unpredictable passphrases
- Zero password persistence across all tests

## Limitations

- Entropy estimation is heuristic and educational
- Common-password list is small and educational
- Scoring bands are project-defined
- Not a replacement for breach-corpus checks (HIBP-style) or a password manager
- No real-world cracking resistance is claimed

## Future Improvements

- Breach-corpus checks via k-anonymity (privacy-preserving)
- Enterprise policy configuration UI
- WebAuthn / passkey awareness module
- Accessibility and localization
- Organisation-level aggregate reporting without collecting passwords

## Screenshots

See the `screenshots/` folder.

## Learning Outcomes

Password security, authentication, hashing concepts, secure coding, privacy
engineering, API design, testing, and security awareness.

## Security Disclaimer

This is an **educational, defensive** tool. It does not crack passwords, does
not attempt passwords against accounts, and does not store, log, or transmit
user passwords. Never reuse any demonstration password shown in this project.

## Author

HRIDOY BISWAS 