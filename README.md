# 🚀 Repeater2 By Faizan Kurawle

**Repeater2** is a Burp Suite extension that unifies **NoAuth**, **JWT Attacker**, and **AuthzTester** into a single workflow for efficient authorization testing and JWT security assessment.

> 💡 To the best of the author's knowledge, Repeater2 is the first Burp Suite extension to combine these capabilities within a single interface.

## ✨ Features

### 🔓 NoAuth

* Capture HTTP requests from Burp tools
* Remove Authorization headers
* Remove Cookies
* Bulk replay requests
* Compare authenticated and unauthenticated responses

### 🎟️ JWT Attacker

* Capture JWT-based requests
* Generate JWT attack variations
* Test common JWT misconfigurations
* Simplify JWT security assessments

### 👥 AuthzTester

* Multi-user authorization testing
* Profile-based request replay
* Access control validation
* Identify IDOR and BOLA vulnerabilities
* Detect privilege escalation issues

## 🎯 Why Repeater2?

Authorization testing often requires multiple tools and repetitive workflows. Repeater2 combines NoAuth testing, JWT security testing, and multi-user authorization validation into a single extension, reducing manual effort and improving testing efficiency.

## 🔥 Key Benefits

* ⚡ Unified workflow for authorization testing
* 🔐 JWT security assessment capabilities
* 👤 Multi-user access control validation
* 🕵️ Efficient identification of IDOR & BOLA vulnerabilities
* 📈 Streamlined privilege escalation testing
* 🎯 Faster security assessments

## 📦 Installation

### Requirements

* Burp Suite Professional or Community Edition
* Jython 2.7

### Steps

1. Install Jython 2.7
2. Open Burp Suite
3. Navigate to **Extensions**
4. Configure the Jython standalone JAR
5. Add `Repeater2.py` as a Python extension
6. Load the extension

## 🖼️ Screenshots

### 🔓 NoAuth

<img width="1909" height="1016" alt="image" src="https://github.com/user-attachments/assets/fd34c5cb-82d6-47e1-9924-7c79670b5e51" />


### 🎟️ JWT Attacker

<img width="1908" height="1039" alt="image" src="https://github.com/user-attachments/assets/b92b81f7-656a-44b0-bd3d-05a8aa6e725d" />
<img width="1904" height="1034" alt="image" src="https://github.com/user-attachments/assets/ce92666e-c1b2-4608-a901-90e3b8e8ce13" />


### 👥 AuthzTester
<img width="1899" height="1048" alt="image" src="https://github.com/user-attachments/assets/01cc4a67-aeaf-4284-9c35-c389e550dc65" />


## 👨‍💻 Author

**Faizan Kurawle**

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only.

