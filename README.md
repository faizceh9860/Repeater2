# Repeater2 — Burp Suite Extension

**By Faizan Kurawle**

> A unified Burp Suite extension that consolidates three independent security-testing sub-tools — **NoAuth**, **JWT Attacker**, and **AuthZ Tester** — into a single installable tab with a shared dark-themed UI.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Architecture](#architecture)
- [Sub-Extension 1 — NoAuth](#sub-extension-1--noauth)
- [Sub-Extension 2 — JWT Attacker](#sub-extension-2--jwt-attacker)
- [Sub-Extension 3 — AuthZ Tester](#sub-extension-3--authz-tester)
- [Shared Features](#shared-features)
- [Context Menu Integration](#context-menu-integration)
- [Export / Import](#export--import)
- [Profile Management](#profile-management)
- [UI Theme Reference](#ui-theme-reference)
- [Known Limitations](#known-limitations)

---

## Overview

Repeater2 is a Jython-based Burp Suite extension designed for **authorization and authentication security testing**. It intercepts requests passing through Burp's Repeater tool and automatically queues attack variants for replay — all without leaving the Burp UI.

The three sub-extensions target distinct vulnerability classes:

| Sub-Extension | Target Vulnerability Class |
|---|---|
| **NoAuth** | Missing authentication / auth-bypass (OWASP API2, API5) |
| **JWT Attacker** | JWT algorithm confusion, none-attack, unverified signature |
| **AuthZ Tester** | Broken object-level auth — IDOR / BFLA / BOLA |

All three run concurrently, share a consistent UI paradigm, and are accessible via a single `Repeater2 By Faizan Kurawle` tab added to the Burp Suite main panel.

---

## Requirements

| Requirement | Detail |
|---|---|
| Burp Suite | Community or Professional, any recent version |
| Jython | 2.7.x standalone JAR (configured in Burp → Extender → Options) |
| Java | 8 or later (bundled with Burp) |
| Python | Jython 2.7 (not CPython) |

> **Important:** This extension uses the legacy Burp Extender API and Jython-specific Java interop. It is **not** compatible with the newer Montoya API.

---

## Installation

1. Download or clone `Reapeater2.py` to your local machine.
2. In Burp Suite, go to **Extender → Options → Python Environment** and set the path to your Jython standalone JAR.
3. Go to **Extender → Extensions → Add**.
4. Set **Extension Type** to `Python`.
5. Browse to `Reapeater2.py` and click **Next**.
6. Confirm that the **Output** tab shows:
   ```
   Repeater2 loaded: NoAuth + JWT Attacker + AuthzTester.
   ```
7. A new tab labeled **Repeater2 By Faizan Kurawle** will appear in the Burp Suite main tab bar.

---

## Architecture

```
BurpExtender  (IBurpExtender, ITab, IHttpListener, IContextMenuFactory)
│
├── NoAuthExtender          ← sub-tab: "NoAuth"
├── JWTAttackerExtender     ← sub-tab: "JWT Attacker"
│     ├── UnverifiedPanel   ← inner sub-tab: "Unverified Signature"
│     └── NoneAttackPanel   ← inner sub-tab: "None Attack"
└── AuthZTesterExtender     ← sub-tab: "AuthzTester"
```

HTTP traffic flows into `BurpExtender.processHttpMessage()`, which fans out to all three sub-extensions. Each sub-extension independently decides whether to enqueue the request based on its own detection logic.

A `CombinedContextMenuFactory` registers a single right-click menu across all Burp tools, exposing **Send to NoAuth**, **Send to AuthZ Tester**, and (conditionally) **Send to JWT Attacker** for any selected request.

---

## Sub-Extension 1 — NoAuth

### Purpose

Strips authentication material from captured Repeater requests and queues the stripped copies for replay. This tests whether endpoints enforce authentication or silently serve responses to unauthenticated requests.

### How It Works

1. **Capture:** When a request passes through Burp's Repeater tool (after a response is received), NoAuth automatically ingests it.
2. **Strip:** The following auth-related headers are removed from the copy:
   - `Authorization`, `Cookie`, `Proxy-Authorization`
   - `X-API-Key`, `X-Auth-Token`, `X-Access-Token`, `X-CSRF-Token`
   - `Token`, `API-Key`, `X-Amz-Security-Token`
3. **Strip (Body/Query Params):** Auth-related query string and body parameters are also removed, including: `token`, `access_token`, `refresh_token`, `jwt`, `session`, `csrf_token`, `password`, `bearer`, and any parameter whose name contains the substring `token`.
4. **Do NOT Strip (Exclusions):** A configurable exclusion field lets you whitelist specific header names or parameter names that should be preserved even if they match the auth pattern.
5. **Queue:** The stripped request is queued under the active profile.
6. **Send:** Queued items can be replayed individually or in bulk. The queue table shows both the **original response** (Prev Status / Prev Size in red) and the **stripped response** (Status / Size) side-by-side for quick comparison.

### Queue Table Columns

| Column | Description |
|---|---|
| `#` | Row number |
| `Method` | HTTP method |
| `URL` | Full request URL |
| `Prev Status` | Status code of the original (authenticated) request |
| `Status` | Status code of the stripped (unauthenticated) request |
| `Prev Size` | Response size of the original request (bytes) |
| `Size (bytes)` | Response size after stripping |
| `Time (ms)` | Response time for the stripped request |

### Controls

| Button | Action |
|---|---|
| **Capture: ON/OFF** | Toggles automatic ingestion from Repeater |
| **Send All** | Replay all queued items sequentially |
| **Send Selected** | Replay only highlighted rows |
| **Stop** | Interrupt an in-progress send run |
| **Resume** | Continue a stopped run from where it paused |
| **Clear Selected** | Remove highlighted rows from the queue |
| **Clear All** | Clear the entire queue |
| **Export** | Save the active profile's queue to a JSON file |
| **Import** | Load a previously exported JSON file |

### Deduplication

NoAuth computes an MD5 hash of each request (after normalizing the HTTP version string) and deduplicates per-profile. A request with the same method, URL, and body will not be enqueued twice within the same profile.

### Request History Navigation

Each queued item accumulates a history of every send attempt. Use the `<` / `>` navigation buttons above the request viewer to step through past send results for the selected item.

---

## Sub-Extension 2 — JWT Attacker

### Purpose

Detects JSON Web Tokens (JWTs) in Repeater requests and automatically generates and queues attack variants targeting common JWT vulnerabilities.

### Attack Modes

The JWT Attacker tab has two independent inner sub-tabs:

#### Unverified Signature

Replaces the last 7 characters of the JWT signature with `abcdefg`. If the server accepts the tampered token, it indicates the signature is not being verified.

- **Label:** `Unverified sig (...abcdefg)`

#### None Attack

Attempts to bypass signature verification by setting the `alg` field in the JWT header to `none` (and its case variants) and stripping the signature entirely.

Four variants are generated per captured JWT:

| Variant Label | `alg` value |
|---|---|
| `alg:none, sig stripped` | `none` |
| `alg:None, sig stripped` | `None` |
| `alg:NONE, sig stripped` | `NONE` |
| `alg:nOnE, sig stripped` | `nOnE` |

### JWT Detection

The extension scans request bytes for the regex pattern:

```
eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*
```

This matches the standard Base64url-encoded `eyJ...` prefix of JWT headers.

### Queue Table Columns

| Column | Description |
|---|---|
| `#` | Row number |
| `Req #` | The original captured request number (groups variants together) |
| `Attack` | Variant label describing the modification applied |
| `Method` | HTTP method |
| `URL` | Full request URL |
| `Prev Status` | Status of the original request |
| `Status` | Status after the attack variant was sent |
| `Prev Size` | Original response size |
| `Size (bytes)` | Attack variant response size |
| `Time (ms)` | Response time |

### Controls

Each inner sub-tab (Unverified Signature / None Attack) has its own independent queue and the same control set: Send All, Send Selected, Stop, Resume, Clear Selected, Clear All, Export, Import.

### Profile Management

JWT Attacker supports named profiles (same pattern as NoAuth): create, rename, delete, and switch profiles independently from the other sub-extensions.

---

## Sub-Extension 3 — AuthZ Tester

### Purpose

Captures requests from Burp's Repeater tool into named **user profiles** (e.g., `admin`, `user`, `guest`), then replays a chosen profile's requests using the **auth credentials of a different profile**. This tests for Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA).

### How It Works

1. **Capture Profiles:** Intercepts Repeater requests and assigns them to the currently active capture profile. Each profile holds a queue of `CapturedRequest` objects.
2. **Auth Profiles:** A separate editable table (bottom panel) stores the authentication material (headers or query parameters) associated with a "sending" identity.
3. **Cross-Profile Replay:** When sending, the extension takes the requests from the **captured profile** but injects the **auth credentials of the selected auth profile** before dispatching. This lets you answer: "Can `user` access `admin`'s resources?"

### Queue Table Columns

| Column | Description |
|---|---|
| `#` | Row number |
| `Method` | HTTP method |
| `URL` | Full request URL |
| `Prev Status` | Status of the original captured request |
| `Status` | Status after replay with injected auth |
| `Prev Size` | Original response size |
| `Size (bytes)` | Replayed response size |
| `Time (ms)` | Response time |

### Auth Credentials Table

The auth credentials table (visible at the bottom of the AuthZ Tester panel) has three columns:

| Column | Description |
|---|---|
| `Type` | `Header` or `Param` |
| `Name` | Header name or parameter key |
| `Value` | The credential value to inject |

Each row is fully editable. Use **Add Row** and **Remove Row** to manage credentials. The table is scoped to the active auth profile.

### Controls

| Button | Action |
|---|---|
| **Capture: ON/OFF** | Toggle automatic ingestion from Repeater |
| **Send All** | Replay all captured requests with injected auth |
| **Send Selected** | Replay selected rows |
| **Stop / Resume** | Interrupt or continue an in-progress run |
| **Clear Selected / Clear All** | Remove items from the queue |
| **Sync Edits** | Push manual edits from the request viewer back into the queue |
| **Export / Import** | Save or restore the active profile's queue to/from JSON |

### History Navigation

Like NoAuth, each captured request accumulates a send history. Use `<` / `>` to navigate between past send attempts for the selected request. The label above the navigator shows the current position (e.g., `2 / 5`).

---

## Shared Features

### Live Search / Filter

Every queue table has a live search bar at the top. Typing filters rows in real time using a case-insensitive regex match across all visible columns (URL, Method, Status, etc.). An **x** button clears the filter instantly.

### Column Sorting

All queue tables support click-to-sort on any column. Numeric columns (Status, Size, Time) sort numerically rather than lexicographically, using a custom `SharedNumericComparator`.

### Request / Response Viewer

Each sub-extension embeds Burp's native message editor components for request and response viewing. The request viewer is editable — changes are synced back to the queue item when you navigate away or click **Sync Edits** (AuthZ Tester).

### History Navigation

Each queued item maintains a full history of every send attempt. Use `<` / `>` arrows to step through attempts. The history counter displays as `current / total` (e.g., `3 / 5`).

### Send to Repeater (NoAuth)

Right-clicking a row in the NoAuth queue shows a context menu with **Send to Repeater**, which forwards the stripped request to Burp's native Repeater tool for further manual testing.

---

## Context Menu Integration

Right-clicking any request in any Burp tool (Proxy, Repeater, HTTP History, etc.) exposes a context menu with:

| Menu Item | Condition |
|---|---|
| **Send to NoAuth** | Always available |
| **Send to AuthZ Tester** | Always available |
| **Send to JWT Attacker** | Only shown when the selected request contains a valid JWT |

This allows manual forwarding of any request from anywhere in Burp into the appropriate queue without waiting for the automatic Repeater-based capture.

---

## Export / Import

All three sub-extensions support JSON-based export/import of their queue state, scoped to the currently active profile.

### Export Format

```json
{
  "tool": "NoAuth",
  "version": 2,
  "profile": "Default",
  "items": [
    {
      "host": "example.com",
      "port": 443,
      "protocol": "https",
      "request": "<base64>",
      "response": "<base64>",
      "prev_status": "200",
      "prev_size": "1234",
      "status": "401",
      "method": "GET",
      "url": "https://example.com/api/resource",
      "time_ms": "142",
      "size": "0",
      "history": [...],
      "historyIndex": 0
    }
  ]
}
```

- All raw request/response bytes are Base64-encoded.
- The `history` array stores every past send attempt for each item.
- `historyIndex` restores the last-viewed history position on import.
- Filenames are auto-suggested as `<tool>_<profile>_<timestamp>.json`.

### Backward Compatibility

The importer detects legacy single-profile exports (version 1) and imports them into the "Default" profile automatically.

---

## Profile Management

All three sub-extensions implement the same profile management pattern:

| Action | Detail |
|---|---|
| **New Profile** | Prompt for a name; creates an empty profile and switches to it |
| **Rename Profile** | Renames the active profile (the `Default` profile cannot be renamed) |
| **Delete Profile** | Deletes the active profile and all its requests (the `Default` profile cannot be deleted) |
| **Switch Profile** | Use the dropdown combo box to switch; queue state is saved and restored per-profile |

Profiles are isolated: requests, seen-request hashes, and paused-row state are stored per-profile. Switching profiles does not discard existing data.

---

## UI Theme Reference

Repeater2 uses a custom dark theme throughout:

| Role | Color (Hex) |
|---|---|
| Panel background | `#232629` |
| Header / border background | `#181a1c` |
| Even row | `#2b2f33` |
| Odd row | `#34383d` |
| Selected row | `#5f5fed` |
| Primary text | `#e1e4e6` |
| Muted text | `#aaaeB2` |
| Success / ON | `#2ecc71` (green) |
| Warning / Send Selected | `#f39c12` (orange) |
| Error / Stop / Clear | `#e74c3c` (red) |
| Previous-capture columns | `#ff3c3c` (bright red) |
| Queued / Resume | `#40c4c8` (teal) |
| Navigation buttons | `#5a82b4` (blue-gray) |

The **Repeater2** header banner uses an animated gradient from green to red with a drop shadow, implemented as a custom `SharedFlashyNameLabel` panel.

---

## Known Limitations

- **Jython 2.7 only.** The extension uses `unicode`, `print` as a statement, and Java interface proxying patterns that are Jython-specific. CPython is not supported.
- **Legacy Extender API only.** Incompatible with Burp's newer Montoya API introduced in 2022+. If Burp shows deprecation warnings, they are expected and non-fatal.
- **No persistence across Burp restarts.** All queue state is in-memory. Use Export before closing Burp if you need to preserve your queues.
- **JWT detection is regex-based.** The extension detects the first JWT it finds per request. Requests with multiple JWTs will only process the first match.
- **Single-threaded sends.** Each send run processes items sequentially in a background thread. There is no parallelism between queue items.
- **Content-Length is auto-corrected** for JWT Attacker variants but **not** for arbitrary manual edits in the NoAuth viewer (use Sync Edits in AuthZ Tester to trigger re-analysis).
