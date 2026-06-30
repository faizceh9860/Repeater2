# Repeater2

A Burp Suite extension that consolidates multiple authorization testing utilities into a single interface, making it easier to perform authentication and authorization security testing during penetration tests.

The extension is implemented in Python (Jython) and packaged into a standalone Java JAR for use within Burp Suite.

---

# Features

Repeater2 combines three independent testing modules into a single Burp Suite tab.

## 1. NoAuth

The NoAuth module automatically removes authentication information from captured HTTP requests and creates unauthenticated variants for testing.

Supported authentication removal includes:

- Authorization headers
- Bearer tokens
- Basic Authentication
- Cookies
- Session identifiers
- API Keys
- Custom authentication headers

This module helps identify endpoints that incorrectly allow access without authentication.

Typical use cases include:

- Missing Authentication
- Broken Authentication
- Authentication Bypass
- Improper Session Validation

---

## 2. JWT Attacker

JWT Attacker automatically detects JSON Web Tokens within captured requests.

The extension searches for JWTs in:

- Authorization headers
- Cookies
- URL Parameters
- Query Strings
- JSON Request Bodies
- Form Parameters

Once detected, the extension automatically creates attack variants.

### Supported attacks

#### Unverified Signature Attack

Creates a modified JWT using the original header and payload while replacing the signature with a forged signature.

This allows testers to verify whether the application validates JWT signatures correctly.

---

#### None Algorithm Attack

Generates unsigned JWTs using multiple algorithm variants including:

- none
- None
- NONE
- nOnE

This helps identify applications that incorrectly accept unsigned JWTs.

---

### Inject Token

The Inject Token feature allows testers to replace the JWT used across every queued request without recapturing traffic.

This is useful when:

- Tokens expire
- New login sessions are created
- Tokens rotate frequently

The extension updates every queued request automatically.

---

## 3. AuthzTester

AuthzTester simplifies authorization testing by storing requests into named user profiles.

Authentication material from another user can then be injected into the captured requests.

Supported replacements include:

- Cookies
- Authorization Headers
- URL Parameters
- Form Parameters
- JSON Parameters

This greatly simplifies testing for:

- IDOR
- BOLA
- BFLA
- Horizontal Privilege Escalation
- Vertical Privilege Escalation

---

# Repository Contents

This repository contains the complete source code required to reproduce the extension.

Files included:

```
README.md
Repeater2.py
build.sh
```

The compiled JAR is intentionally not stored in this repository.

Users may build the extension themselves using the provided source code and build script.

---

# Requirements

To build the extension, the following software is required.

## Runtime

- Java 11 or later
- Bash

## Build Dependency

- Jython Standalone 2.7.4

Download the Jython Standalone JAR and place it in the project directory before building.

---

# Building

Clone the repository.

```bash
git clone https://github.com/<username>/Repeater2.git
```

Enter the project directory.

```bash
cd Repeater2
```

Make the build script executable.

```bash
chmod +x build.sh
```

Build the extension.

```bash
./build.sh Repeater2.py jython-standalone-2.7.4.jar
```

After a successful build, the following file will be generated.

```
Repeater2.jar
```

---

# Installing in Burp Suite

Open Burp Suite.

Navigate to:

```
Extensions
    → Installed
        → Add
```

Select:

```
Extension Type:
Java
```

Browse to:

```
Repeater2.jar
```

Click **Next**.

The extension will appear as a new **Repeater2** tab inside Burp Suite.

---

# Usage

## NoAuth

1. Send requests to Repeater.
2. Capture requests inside NoAuth.
3. Generate unauthenticated requests.
4. Replay requests.
5. Compare responses.

---

## JWT Attacker

1. Capture a request containing a JWT.
2. Generate attack variants.
3. Review generated requests.
4. Send requests.
5. Compare responses.

Use **Inject Token** whenever the JWT changes.

---

## AuthzTester

1. Create user profiles.
2. Capture requests.
3. Select the target profile.
4. Replace authentication.
5. Send requests.
6. Compare responses.

---

# Troubleshooting

If the extension reports errors, open:

```
Extensions
    → Installed
        → Repeater2
            → Errors
```

Burp Suite logs all extension exceptions here.

---

# Development

The extension is written in Python using the Burp Extender API.

The build script:

- Generates Burp API stubs
- Compiles the Java bootstrap
- Packages the Python extension
- Bundles the Jython runtime
- Produces a standalone Burp-compatible JAR

No additional manual packaging is required.

---

# Note for Reviewers

This repository contains the complete source code used to build the extension.

The provided build script reproduces the distributed Burp Suite extension from source.

The compiled JAR is intentionally excluded from the repository because it can be reproduced using the documented build process.

---

# Disclaimer

This project is intended solely for authorized security testing.

Only use this software against systems that you own or have explicit permission to assess.

The author assumes no responsibility for misuse or damage resulting from the use of this software.