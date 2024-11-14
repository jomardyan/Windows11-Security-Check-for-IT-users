# Windows Security Check Script
[![PSScriptAnalyzer](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/powershell.yml/badge.svg?branch=main)](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/powershell.yml) [![Mark stale issues and pull requests](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/stale.yml/badge.svg)](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/stale.yml) [![Codacy Security Scan](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/codacy.yml/badge.svg)](https://github.com/jomardyan/Windows11-Security-Check-for-IT-users/actions/workflows/codacy.yml)

A comprehensive PowerShell script to assess and report on the security configuration of Windows 10 and Windows 11 systems.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Parameters](#parameters)
- [Sample Output](#sample-output)
- [Customization](#customization)
- [Contributing](#contributing)
- [License](#license)

## Overview

This script performs a series of security checks to evaluate the security posture of a Windows system. It covers firewall status, antivirus status, Windows Update, account policies, audit policies, unnecessary services, network settings, installed software vulnerabilities, drive encryption, browser security settings, and domain-specific checks if applicable.

## Features

- Checks Windows Firewall status for all profiles.
- Verifies antivirus status and definitions.
- Ensures Windows Update service is running and checks for pending updates.
- Evaluates account lockout and password policies.
- Checks audit policies for security events.
- Identifies and reports unnecessary services.
- Assesses network security settings, including protocols and services.
- Reviews firewall rules for potential security risks.
- Detects administrative shares.
- Scans for installed software with known vulnerabilities.
- Checks drive encryption status (BitLocker or Device Encryption).
- Verifies browser security settings (e.g., SmartScreen in Edge).
- Performs domain-specific checks for domain-joined systems:
  - Domain controller connectivity.
  - Group Policy compliance.
  - VPN connection status.
  - Network share permissions.
  - Required domain software installation.

## Prerequisites

- **Operating System:** Windows 10 or Windows 11.
- **PowerShell Version:** 5.1 or later.
- **Administrative Privileges:** Run the script as an administrator.
- **Execution Policy:** Set to allow running scripts (e.g., `RemoteSigned`).

## Usage

1. **Download the Script:**

   Clone the repository or download the `Check-WindowsSecurity.ps1` script.

2. **Run PowerShell as Administrator:**

   Open PowerShell with administrative privileges.

3. **Set Execution Policy (if necessary):**

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
