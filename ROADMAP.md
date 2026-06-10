# Roadmap: Fable-class Capabilities for Kraken

Build Fable 5-level capabilities (vision, memory, self-validation, multi-agent,
autonomous migration, enhanced security) into Kraken using Big Pickle (OpenCode
Zen) as the base model. Each phase builds on the previous one.

---

## ✅ Phase 1 — Vision / Image Input

**Goal**: Send images (screenshots, diagrams, UI mockups) to the model via the
OpenAI-compatible provider (Big Pickle).

### Types (`rust/crates/api/src/types.rs`)

- `MediaType` enum: `Png`, `Jpeg`, `Gif`, `Webp`, `Bmp`
- `ImageSource` struct: `{ media_type: MediaType, data: String (base64), type: String }`
- `InputContentBlock::Image { source: ImageSource }` variant

### OpenAI serialization (`rust/crates/api/src/providers/openai_compat.rs`)

- Handle `InputContentBlock::Image` in `translate_message()`
- Convert to `{"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}`
- When any block is an image, wrap user message content in array format

### Runtime types (`rust/crates/runtime/src/conversation.rs`)

- `ContentBlock::Image { media_type, data, source_type }` variant
- Update all match arms across the codebase

### Message converters (2 files)

- `rust/crates/rusty-claude-cli/src/main.rs` — `convert_messages()`
- `rust/crates/tools/src/lib.rs` — `convert_messages()` (duplicated)

Map `ContentBlock::Image` → `InputContentBlock::Image`

### Tool implementations (`rust/crates/tools/src/lib.rs`)

- Implement `/screenshot` — capture screen → base64
- Implement `/image <path>` — read image file → base64 → send to model
- Move both from `STUB_COMMANDS` to real commands in `main.rs`

### Tests

- Image block serialization roundtrip (serde)
- OpenAI compat translate_message with image blocks
- OpenAI compat mixed text+image content array
- Anthropic compat image block serialization
- Screenshot tool (mock display)
- Image file reading tool
- ContentBlock→InputContentBlock conversion

---

## ✅ Phase 2 — Persistent Memory / Note-taking

**Goal**: Agent writes notes to files and recalls them across turns, improving
long-horizon task performance (Fable 5 showed 3x improvement with file-based
memory).

### New tools (`rust/crates/tools/src/lib.rs`)

- `WriteNote { key, content, append? }` — save to `.kraken/memory/<key>.md`
- `ReadNote { key }` — retrieve note
- `ListNotes { prefix? }` — list available notes

### System prompt (`rust/crates/runtime/src/prompt.rs`)

Add memory usage instructions:

```
## Working Memory
You have persistent file-based memory. Before complex tasks, review existing
notes. After subtasks, save progress. Use WriteNote/ReadNote/ListNotes.
Store: task state, decisions, partial results, hypotheses.
```

### User command (`rust/crates/commands/src/lib.rs`)

- `/notes [list|read <key>|write <key> <content>]`

### Tests

- WriteNote creates correct file path
- ReadNote retrieves content
- ListNotes returns filtered results
- Append mode preserves existing content
- System prompt section renders correctly

---

## ✅ Phase 3 — Self-Validation (High-Effort Mode)

**Goal**: Agent reviews and validates its own work before presenting results,
matching Fable 5's high-effort reflection behavior.

### Conditional system prompt (`rust/crates/runtime/src/prompt.rs`)

```
## Self-Validation Mode (active when effort=high)
After each task:
1. Review correctness and edge cases
2. Validate against acceptance criteria
3. Fix issues found
4. Report checks performed and fixes applied
```

### Effort level wiring

- `/effort [low|medium|high]` — already a stub in commands, connect to runtime
- Pass `reasoning_effort` from CLI → runtime → prompt builder
- Prompt builder conditionally includes validation section

### Post-task hook (`rust/crates/runtime/src/conversation.rs`)

- After tool execution cycle, if effort=high, inject validation prompt
- Parse model's self-validation report and log it

### Tests

- Effort level propagates through config → runtime → prompt
- High effort includes validation section in prompt
- Low/medium exclude validation section
- Validation report is parsed correctly

---

## ✅ Phase 4 — Advanced Multi-Agent Orchestration

**Goal**: Coordinate multiple sub-agents with parallel task execution, context
sharing, and result consolidation.

### Enhanced Agent tool (`rust/crates/tools/src/lib.rs`)

- Delegation with context passthrough (files, images, notes)
- Parallel sub-agent execution
- Structured result format for chaining

### Team coordination (`rust/crates/commands/src/lib.rs`)

- `/team [create|list|status]` — manage agent teams
- `PlanWithTeam { objective, decomposition }` — break work into parallel tasks

### System prompt additions

```
## Multi-Agent Workflow
For complex tasks, decompose into parallel subtasks and delegate to sub-agents.
Each sub-agent handles one concern. Consolidate results when all complete.
Use Agent tool with clear objective and scope.
```

### Tests

- Sub-agent receives correct context
- Parallel execution produces correct results
- Result consolidation merges correctly
- Team commands parse and validate

---

## Phase 5 — Autonomous Codebase Migrations

**Goal**: Plan and execute large-scale refactors across multiple files with
verification and rollback.

### New tools (`rust/crates/tools/src/lib.rs`)

- `PlanMigration { description, files[] }` — analyze and plan multi-file changes
- `BatchEdit { edits[] }` — atomic multi-file edits with preview
- `VerifyMigration { command }` — run compile/test/check after changes

### System prompt migration protocol

```
## Migration Protocol
1. Map: identify all files and dependencies
2. Plan: define changes per file, order, and risks
3. Preview: show diff before executing
4. Execute: apply BatchEdit with atomic commits
5. Verify: compile, test, lint
6. Commit or rollback based on results
```

### Tests

- Migration plan generation from description
- BatchEdit applies all edits correctly
- Verify command runs and returns pass/fail
- Rollback restores originals on failure

---

## Phase 6 — Enhanced Security Analysis (vulnscan)

**Goal**: Leverage Big Pickle LLM analysis inside the vulnerability scanning
pipeline, using specialized system prompts per vulnerability class.

### LLM-powered analysis (`rust/crates/vulnscan/src/pipeline.rs`)

- Integrate Big Pickle as analysis backend for `--deep` and `--overnight` modes
- Per-class system prompts: SQLi, XSS, command injection, crypto flaws, etc.
- Cross-validation: compare tree-sitter AST findings with LLM analysis

### New analyzer module (`rust/crates/vulnscan/src/llm_analyst.rs`)

- `LlmFinding` struct with confidence, explanation, remediation
- `LlmAnalystConfig` with model selection, temperature, per-class prompts
- `analyze_file(path, findings[])` — send code + AST findings to LLM
- `rank_findings(findings[])` — probability ranking with LLM

### Autonomous bughunt pipeline

- Feed raw findings from AST scanners into LLM for validation
- LLM generates exploit primitives from validated findings
- Chain primitives with existing BFS solver
- Generate human-readable report with LLM summaries

### Tests

- LlmAnalyst config parsing
- System prompt assembly per vulnerability class
- Finding validation against known true/false positives
- Full pipeline integration test with mock model responses

---

## Phase 7 — OSINT Foundation

**Goal**: Build a data collection framework for open-source intelligence — email
extraction, DNS/WHOIS resolution, web scraping, search aggregation. This is the
base layer for all person and infrastructure OSINT phases.

### New crate (`rust/crates/osint/`)

- `Cargo.toml` — `reqwest`, `scraper`, `select.rs`, `dns-parser`, `url`
- `src/lib.rs` — core types: `OsintTarget`, `OsintSource`, `OsintFinding`,
  `OsintReport`
- `src/collector.rs` — `DataCollector`: regex-based extraction of emails,
  usernames, URLs, IPs, phone numbers from HTML/PDF/plaintext
- `src/search.rs` — `SearchAggregator`: queries multiple web search engines,
  deduplicates, ranks results by source reliability
- `src/dns.rs` — `DnsResolver`: DNS record queries (A, AAAA, MX, TXT, NS,
  SOA, CNAME), WHOIS lookup via public servers

### New tools (`rust/crates/tools/src/lib.rs`)

- `OsintCollect { target, sources[] }` — collect all public data on a target
- `DnsLookup { domain, record_type }` — query DNS records
- `WhoisQuery { domain }` — WHOIS information for a domain

### System prompt (`rust/crates/runtime/src/prompt.rs`)

```
## OSINT Methodology
1. Collect: gather raw data from public sources (DNS, WHOIS, web, search)
2. Normalize: clean and standardize collected data into structured fields
3. Correlate: cross-reference findings across sources, resolve conflicts
4. Report: present findings with source attribution and confidence levels
```

### Tests

- DataCollector extracts emails/URLs from HTML correctly
- SearchAggregator deduplicates and ranks results
- DnsResolver queries return expected record structures
- WhoisQuery parses whois text into structured fields
- Tool input/output roundtrip serialization

---

## Phase 8 — Social Media OSINT

**Goal**: Discover and extract public information from social media platforms.
Username search across 50+ platforms, email-to-profile correlation, social
graph enumeration.

### Module (`rust/crates/osint/src/social.rs`)

- `SocialSearcher` — checks username availability/existence on 50+ platforms
  (GitHub, Twitter/X, LinkedIn, Reddit, Instagram, Telegram, Discord, etc.)
  via HTTP probes and public API endpoints
- `ProfileExtractor` — scrapes/extracts public profile info per platform
- `Platform` enum — each platform with base URL, profile path pattern, rate
  limit info

### Module (`rust/crates/osint/src/email.rs`)

- `EmailEnricher` — verifies email format/domain, checks breach databases
  (HaveIBeenPwned API v3), searches for associated profiles
- `BreachEntry` — service name, breach date, data classes exposed

### New tools (`rust/crates/tools/src/lib.rs`)

- `UsernameSearch { username, platforms? }` — find profiles by username
- `EmailLookup { email }` — enrich email with associated data
- `SocialProfile { platform, username }` — extract public profile data

### Tests

- UsernameSearch returns correct URL patterns per platform
- EmailEnricher validates email format and domain MX records
- ProfileExtractor handles rate limits gracefully
- Tool error handling for non-existent accounts

---

## Phase 9 — Person Identity Correlation

**Goal**: Cross-reference OSINT fragments to build comprehensive person profiles.
Correlate identities across platforms, construct timelines, map relationships.

### Module (`rust/crates/osint/src/person.rs`)

- `PersonProfile` — full identity: real name, aliases, emails, phones,
  locations, education, employment, social links, confidence score
- `PersonBuilder` — incremental builder that merges new findings into profile
- `PersonStore` — SQLite-backed storage (rusqlite or via existing offline
  crate)

### Module (`rust/crates/osint/src/correlator.rs`)

- `IdentityCorrelator` — matches identity fragments using fuzzy matching
  (Levenshtein, token overlap, email/username exact match)
- `CorrelationResult` — match score, matched fields, evidence chain

### Module (`rust/crates/osint/src/timeline.rs`)

- `TimelineBuilder` — sorts findings by timestamp, deduplicates, constructs
  chronological narrative

### Output

- `OsintReport::Person` — structured profile in JSON, text, and HTML
- Confidence levels per field with source citations

### New tools (`rust/crates/tools/src/lib.rs`)

- `PersonSearch { query, depth }` — search all sources, build profile
- `CorrelateProfiles { profiles[] }` — merge/match multiple partial profiles
- `PersonTimeline { person_id }` — chronological timeline of findings

### Tests

- PersonBuilder merges duplicate fields correctly
- IdentityCorrelator matches by email, username, name variants
- TimelineBuilder sorts and deduplicates correctly
- PersonStore CRUD operations
- Full person search pipeline with mocked sources

---

## Phase 10 — Dark & Surface Web Reconnaissance

**Goal**: Enumerate subdomains, certificate transparency logs, breached
credentials, paste sites. Map the external attack surface of a domain.

### Module (`rust/crates/osint/src/subdomain.rs`)

- `SubdomainEnumerator` — certificate transparency (crt.sh API), DNS
  brute-force with wordlist, DNS zone transfer attempts, search engine
  dorking (google/bing site: queries)
- `SubdomainResult` — subdomain, resolved IPs, source, discovery method

### Module (`rust/crates/osint/src/surface.rs`)

- `SurfaceAnalyzer` — technology fingerprinting via HTTP response headers,
  HTML meta, favicon hash, JS library detection; security header audit
  (HSTS, CSP, X-Frame-Options, etc.)

### Module (`rust/crates/osint/src/threat.rs`)

- `ThreatIntel` — check IPs/domains against AlienVault OTX, URLhaus,
  built-in blocklists; breach data lookup

### New tools (`rust/crates/tools/src/lib.rs`)

- `SubdomainEnum { domain, wordlist? }` — enumerate subdomains via CT + DNS
- `TechDetect { url }` — fingerprint technologies and security headers
- `ThreatCheck { target }` — check domain/IP against threat intel feeds

### Tests

- SubdomainEnumerator parses crt.sh JSON response correctly
- SurfaceAnalyzer detects known technologies from headers
- ThreatIntel returns correct blocklist status
- All tools handle network errors gracefully
- Wordlist loading from built-in and custom paths

---

## Phase 11 — Network Attack Surface

**Goal**: Scan and enumerate network services, fingerprint versions, identify
known vulnerabilities. Supports both internal and external targets.

### Module (`rust/crates/vulnscan/src/network.rs`)

- `NetworkScanner` — connect-based TCP port scanning with configurable
  concurrency, service detection via banner grab, TLS fingerprinting
- `PortResult` — port number, protocol, service name, banner, TLS version,
  CVE hits

### Module (`rust/crates/vulnscan/src/service.rs`)

- `ServiceEnumerator` — deep service fingerprinting: HTTP server header,
  SSH version string, SMTP EHLO, FTP banner; matches against CVE database
  entries
- `VulnLookup` — offline CVE lookup by service/version (built-in CVE index)

### Integration with vulnscan pipeline

- Network findings feed into `LateralMovement` and `AttackGraph` for
  chaining with code-level vulnerabilities
- Port scan results become nodes in the attack graph

### New tools (`rust/crates/tools/src/lib.rs`)

- `PortScan { target, ports?, rate? }` — scan TCP ports on target
- `ServiceDetect { host, port }` — fingerprint service and check CVEs
- `VulnLookup { service, version }` — query CVE database

### Tests

- NetworkScanner discovers open ports correctly (against mock listener)
- ServiceDetector banners match expected patterns
- VulnLookup returns correct CVE entries for known versions
- Integration: scan results feed into attack graph construction

---

## Phase 12 — System Security Audit

**Goal**: Deep-audit the local system — permissions, services, kernel config,
crypto policies, containers, network state. Generate a comprehensive security
report.

### New crate (`rust/crates/audit/`)

- `Cargo.toml` — `walkdir`, `nix`, `sysinfo`, `serde`
- `src/lib.rs` — `AuditReport`, `AuditCategory`, `AuditCheck`, `Severity`,
  `Remediation`
- `src/permissions.rs` — `PermissionAuditor`: world-writable files, SUID/
  SGID binaries, file capabilities, ACLs, sticky-bit, dotfile permissions
- `src/services.rs` — `ServiceAuditor`: listening sockets (TcpListener),
  systemd units (enabled/running), cron jobs, timers
- `src/kernel.rs` — `KernelAuditor`: sysctl security params (net.ipv4.
  conf.*.rp_filter, kernel.randomize_va_space, etc.), loaded modules,
  kernel config
- `src/network.rs` — `NetworkAuditor`: listening ports, active connections,
  iptables/nftables rules, ARP table, routing table
- `src/crypto.rs` — `CryptoPolicyAuditor`: TLS certs in use, key sizes,
  algorithm weaknesses, expiration dates in trust stores
- `src/container.rs` — `ContainerAuditor`: Docker/podman container
  permissions, capabilities, seccomp profile, mount privileges

### New tools (`rust/crates/tools/src/lib.rs`)

- `SysAudit { categories?, format? }` — run full or partial security audit
- `AuditReport { id?, format }` — view/generate report in JSON, HTML, text

### Tests

- PermissionAuditor finds known world-writable test files
- ServiceAuditor enumerates systemd units correctly
- KernelAuditor reads and parses sysctl values
- NetworkAuditor detects test listening ports
- AuditReport serializes to JSON/HTML correctly

---

## Phase 13 — System Hardening Engine

**Goal**: Apply security hardening configurations automatically. Firewall rules,
SSH hardening, kernel parameters, AppArmor/SELinux policies, crypto policies.
Profile-based (desktop/server/dev).

### New crate (`rust/crates/hardening/`)

- `Cargo.toml` — `nix`, `serde`, `toml`
- `src/lib.rs` — `HardeningProfile`, `HardeningRule`, `HardeningResult`,
  `HardenAction (Set|Append|Replace|Remove)`
- `src/profiles/desktop.rs` — desktop profile: firewall default deny, SSH
  disable root password, kernel ASLR, secure mount opts
- `src/profiles/server.rs` — server profile: +fail2ban, +auditd, +strict
  SSH, +sysctl network hardening, +AIDE
- `src/profiles/dev.rs` — development profile: permissive but not insecure,
  allows local services, locks remote access

### Module (`rust/crates/hardening/src/firewall.rs`)

- `FirewallConfig` — nftables/iptables rule generation from profile,
  default policies, port allow/deny, rate limiting, logging
- `FirewallBackend` enum — detect and use nftables > iptables > ufw

### Module (`rust/crates/hardening/src/ssh.rs`)

- `SshHardener` — read `/etc/ssh/sshd_config`, enforce secure settings:
  PermitRootLogin no, PasswordAuthentication no, PubkeyAuth yes,
  Protocol 2, Ciphers strong-only, etc.

### Module (`rust/crates/hardening/src/kernel.rs`)

- `KernelHardener` — sysctl parameters: ASLR, dmesg restrict, ptrace
  scope, ICMP ignore, TCP syncookies, BPF JIT disable

### Module (`rust/crates/hardening/src/lsm.rs`)

- `AppArmorConfig` — enforce profiles, complain mode for debug
- `SeLinuxConfig` — enforcing/permissive, context validation

### New tools (`rust/crates/tools/src/lib.rs`)

- `HardeningApply { profile, dry_run? }` — apply hardening profile
- `HardeningCheck { profile }` — check compliance against profile
- `FirewallRule { action, rule }` — manage firewall rules

### Tests

- HardeningRule application dry-run produces correct diff
- FirewallConfig generates valid nftables ruleset
- SshHardener detects and proposes fixes for weak config
- KernelHardener produces correct sysctl key/value pairs
- Profile merge: desktop + server overlaps resolve correctly

---

## Phase 14 — Threat Detection & Monitoring

**Goal**: Real-time system monitoring — file integrity, log watching, network
anomaly detection. Configurable alert rules with notification actions.

### New crate (`rust/crates/monitor/`)

- `Cargo.toml` — `notify` (file watcher), `serde`, `chrono`, `sha2`
- `src/lib.rs` — `MonitorEngine`, `Alert`, `AlertRule`, `AlertSeverity`
- `src/fim.rs` — `FileIntegrityMonitor`: SHA-256 baseline, periodic
  re-checks, alert on modification/new/deleted for critical file paths
  (/etc/passwd, /etc/shadow, /etc/ssh/sshd_config, /etc/sudoers, etc.)
- `src/logwatch.rs` — `LogWatcher`: tail log files (auth.log, syslog,
  kern.log), regex patterns for auth failures, port scans, sudo usage,
  cron anomalies, kernel panics
- `src/network_monitor.rs` — `NetworkMonitor`: periodic netstat/ss polls,
  detect new listening ports, unexpected outbound connections,
  connections to known-bad IPs
- `src/alerter.rs` — `AlertDispatcher`: console, log file, webhook
  (Slack/email/webhook URL) actions

### New tools (`rust/crates/tools/src/lib.rs`)

- `MonitorStart { rules? }` — start monitoring with rule set
- `MonitorStatus` — show active monitors, recent alerts
- `MonitorAlert { acknowledge? }` — acknowledge/resolve alerts

### Tests

- FIM detects file changes in watched directory
- LogWatcher pattern matching against known log lines
- NetworkMonitor detects new listening port events
- AlertDispatcher sends formatted alerts through configured channels
- Rule persistence across monitor restarts

---

## Phase 15 — Advanced Exploitation Chain

**Goal**: Enhanced exploit generation using AI context understanding, privilege
escalation automation, and lateral movement detection. Builds on vulnscan's
existing exploit generator.

### Module (`rust/crates/vulnscan/src/exploit_adv.rs`)

- `AdvancedExploitGenerator` — wraps the LLM (Big Pickle) with exploit-
  specific system prompts: generate PoC code, ROP chains, shellcode,
  web exploits (SQLi, XSS, CSRF, SSRF) contextualized to the target code
- `ExploitContext` — finding details, code snippet, language, OS, arch,
  mitigations (ASLR, NX, stack canary)
- `ExploitValidation` — compile PoC, check syntax, test against target

### Module (`rust/crates/vulnscan/src/privesc.rs`)

- `PrivilegeEscalation` — enumerate local privesc vectors: kernel
  exploits (CVE lookup), sudo rules, SUID binaries, capabilities, cron
  jobs writable by user, NFS exports, docker group membership
- `PrivescResult` — vector type, command, risk, success confidence

### Module (`rust/crates/vulnscan/src/pivot.rs`)

- `PivotScanner` — from a compromised host, detect reachable internal
  networks, services, and authentication materials (SSH keys, k8s tokens,
  cloud provider metadata)
- `PivotPath` — source host → target host/service, protocol, auth method

### New tools (`rust/crates/tools/src/lib.rs`)

- `ExploitGen { finding_id, format? }` — generate exploit from finding
- `PrivEscCheck` — enumerate local privilege escalation vectors
- `PivotMap` — map lateral movement opportunities

### Tests

- AdvancedExploitGenerator produces compilable PoC (syntax-checked)
- PrivEsc enumerates known sudo rules and SUID bins in test env
- PivotScanner detects mock internal services
- Integration: exploit chain from finding → exploitation → privesc

---

## Phase 16 — Automated Defense & Incident Response

**Goal**: Automated incident response playbooks triggered by monitor alerts.
Containment (firewall isolation, process kill, network namespace), recovery
(config rollback, snapshot restore), and forensic snapshot generation.

### New crate (`rust/crates/response/`)

- `Cargo.toml` — `serde`, `chrono`, `nix`, `toml`
- `src/lib.rs` — `IncidentResponder`, `Playbook`, `ResponseAction`,
  `IncidentPhase (Detect|Contain|Eradicate|Recover|Lessons)`
- `src/playbooks/mod.rs` — playbook definitions
- `src/playbooks/ssh_bruteforce.rs` — detect >5 auth failures/min, add
  source IP to deny list, alert, log
- `src/playbooks/new_service_detected.rs` — detect unknown listening port,
  verify with user, add to allowlist or block
- `src/playbacks/file_integrity_violation.rs` — critical file changed,
  alert, snapshot, compare with baseline, restore if authorized
- `src/playbooks/outbound_ratelimit.rs` — burst of outbound connections,
  rate-limit, investigate, isolate if confirmed C2

### Module (`rust/crates/response/src/isolation.rs`)

- `IsolationEngine` — nftables/iptables isolation rules, network namespace
  creation, cgroup process isolation, process kill with SIGTERM/SIGKILL
- `IsolationLevel` enum — `NetworkOnly | ProcessOnly | Full`

### Module (`rust/crates/response/src/recovery.rs`)

- `RecoveryEngine` — config file restore from backup, sysctl revert,
  firewall rule rollback, service restart
- `Snapshot` — pre-change state capture (file hashes, iptables dump,
  sysctl values, running services)

### Module (`rust/crates/response/src/report.rs`)

- `IncidentReport` — timeline of events, actions taken, current status,
  forensic artifacts, recommendations

### New tools (`rust/crates/tools/src/lib.rs`)

- `IncidentRespond { alert_id, playbook? }` — execute incident response
- `IsolateHost { level }` — isolate this or target host
- `RecoverState { snapshot_id }` — revert to pre-incident state

### Tests

- Playbook for ssh_bruteforce generates correct nftables drop rule
- IsolationEngine creates correct network namespace isolation
- RecoveryEngine restores sysctl to previous values
- IncidentReport contains complete timeline and action log
- Full playbook dry-run produces expected action sequence

---

## Phase 17 — Process & Service Control

**Goal**: Native Rust control of Linux processes and systemd services — spawn,
kill, signal, resource limits, cgroups, unit lifecycle. Zero bash dependency.

### Crate (`rust/crates/sysctrl/`)

- `Cargo.toml` — `nix`, `libc`, `serde`
- `src/lib.rs` — `SysCtrl { distro: Distro }`, `Distro` enum (Debian, Ubuntu,
  Fedora, RHEL, Arch, Alpine, Suse, Gentoo, Void), auto-detection
- `src/process.rs` — `ProcessManager`: spawn with `fork()`/`exec()` via nix,
  `kill()`/`signal()` via libc, `/proc/` parsing for state/mem/cpu
- `src/service.rs` — `ServiceManager`: systemd D-Bus API via `dbus` crate or
  sd-bus; start/stop/restart/enable/disable/status/create unit files
- `src/resource.rs` — `ResourceController`: `setrlimit()`/`getrlimit()` via
  libc, cgroups v1/v2 integration (cgroupfs), `nice()`/`ionice()`,
  `prlimit()` for foreign processes
- `src/session.rs` — `SessionManager`: logind D-Bus interface for user
  sessions, KillUser, Inhibit, LockSession

### Tools

- `Service { action, unit, properties? }` — systemd unit lifecycle without
  `systemctl` subprocess
- `Process { action, target, signal? }` — spawn/kill/signal by PID or name
- `ProcessList { filter?, sort? }` — list processes with CPU/mem/state via
  `/proc/` parsing
- `ResourceLimit { pid, limits[] }` — get/set rlimits on any process
- `CGroup { group, action, property?, value? }` — cgroup management

### Tests

- Service unit file creation renders correct systemd syntax
- Process spawn returns correct PID and status
- ResourceLimit sets and reads back rlimit values
- CGroup path detection: v1 vs v2 hierarchy
- Distro auto-detection returns correct enum for known /etc/os-release

---

## Phase 18 — Storage & Filesystem

**Goal**: Full control over Linux storage — mount, LVM, RAID, partitions,
filesystem creation/check, quotas, ACLs. All via native syscalls.

### Modules (`rust/crates/sysctrl/src/fs/`)

- `src/fs/mount.rs` — `MountManager`: `mount()`/`umount2()` syscalls (nix
  crate), `/etc/fstab` parsing (custom parser or `fstab` crate), tmpfs,
  bind mounts, overlayfs, `findmnt`-style tree walking
- `src/fs/disk.rs` — `DiskManager`: `blkid` output parsing,
  `/sys/block/` enumeration, partition table reading (GPT header parser),
  `lsblk`-style device tree
- `src/fs/lvm.rs` — `LvmManager`: shell out to `lvm` CLI but parse
  structured output (`lvm pvs/vgs/lvs --reportformat=json`), LVM REST
  API would be ideal but CLI is practical
- `src/fs/raid.rs` — `RaidManager`: `/proc/mdstat` parser, mdadm wrapper
  with JSON output parsing
- `src/fs/quota.rs` — `QuotaManager`: `quotactl()` syscall for XFS/ext4
  quota management, `repquota` parsing as fallback
- `src/fs/acl.rs` — `AclManager`: `acl_get_file()`/`acl_set_file()` via
  POSIX ACLs (libc), `getxattr()`/`setxattr()` for extended attributes,
  `cap_get_file()`/`cap_set_file()` for file capabilities
- `src/fs/backup.rs` — `BackupManager`: rsync wrapper with structured
  parsing, tar archive creation with `libarchive` or `tar` crate

### Tools

- `Mount { device?, path, fstype?, options?, action }` — mount/remount/
  umount operations using native syscalls
- `DiskInfo { device? }` — detailed disk/partition information
- `Lvm { action, vg?, lv?, pv?, size? }` — LVM logical volume management
- `Fsck { device, force, type? }` — filesystem check wrapper
- `FsOp { path, action, mode?, owner?, group?, recursive? }` — chmod/
  chown/chattr nativos sin bash

### Tests

- MountManager calls mount() with correct flags (mock via LD_PRELOAD or
  test namespace)
- DiskManager parses /sys/block/ topology correctly
- LvmManager parses lvm JSON output into structured types
- QuotaManager constructs correct quotactl() calls
- AclManager roundtrips POSIX ACLs on temp files

---

## Phase 19 — Network & User Control

**Goal**: Native control of Linux networking (interfaces, routes, DNS, bridges,
traffic control) and user management (users, groups, sudo, PAM, SSH).

### Modules (`rust/crates/sysctrl/src/net/`)

- `src/net/interface.rs` — `NetInterfaceManager`: netlink sockets
  (`NETLINK_ROUTE`) via `neli` crate or `rtnetlink`; `SIOCGIFFLAGS`/
  `SIOCSIFADDR` ioctls; interface up/down, MAC change, MTU set,
  IP address add/remove, VLAN interfaces
- `src/net/route.rs` — `RouteManager`: netlink RTM_NEWROUTE/RTM_DELROUTE,
  IPv4/IPv6 route manipulation, default gateway, multipath routing
- `src/net/dns.rs` — `DnsManager`: `/etc/resolv.conf` parser and writer,
  systemd-resolved D-Bus API, NetworkManager D-Bus API
- `src/net/hostname.rs` — `HostnameManager`: `sethostname()`/`setdomainname()`
  syscalls, `/etc/hostname`, `/etc/hosts` management
- `src/net/bridge.rs` — `BridgeManager`: bridge creation via netlink,
  bonding, VXLAN, VLAN interfaces
- `src/net/tc.rs` — `TrafficControlManager`: netlink `NETLINK_SCHED`,
  qdisc/class/filter creation for traffic shaping

### Modules (`rust/crates/sysctrl/src/user/`)

- `src/user/users.rs` — `UserManager`: shadow functions (`getpwnam_r()`,
  `putpwent()`, `setpwent()`) via libc; useradd/userdel/usermod via
  `libuser` or `chsh`/`passwd` wrappers
- `src/user/groups.rs` — `GroupManager`: `getgrnam_r()`, `getgrent()`,
  groupadd/groupdel via `libuser` or direct `/etc/group` manipulation
- `src/user/sudo.rs` — `SudoManager`: `/etc/sudoers` parser (visudo-safe
  editing), sudo rule management
- `src/user/ssh.rs` — `SshManager`: authorized_keys management,
  `/etc/ssh/sshd_config` parser and validator
- `src/user/pam.rs` — `PamManager`: PAM configuration file parser,
  `/etc/pam.d/` service file management

### Tools

- `NetInterface { name, action, config? }` — interface up/down, IP/MAC/MTU
- `NetRoute { action, dest, gateway?, iface?, metric? }` — add/remove routes
- `DnsConfig { nameservers[], search?, action }` — configure DNS servers
- `User { action, username, groups?, shell?, uid? }` — user CRUD
- `SudoRule { user, hosts, commands[], nopasswd? }` — manage sudo rules

### Tests

- NetInterfaceManager constructs correct netlink messages
- RouteManager adds and removes routes in a network namespace
- DnsManager roundtrips resolv.conf content correctly
- UserManager creates valid passwd entries
- SudoRule validates syntax against sudoers grammar

---

## Phase 20 — Package & Automation Control

**Goal**: Cross-distro package management, cron/timer scheduling, boot/kernel
control, system snapshots and recovery.

### Modules (`rust/crates/sysctrl/src/pkg/`)

- `src/pkg/mod.rs` — `PkgManager` trait with dispatch:
  - `AptPkg` — `apt-get`/`apt-cache` with structured output parsing
  - `DnfPkg` — `dnf` JSON output
  - `PacmanPkg` — `pacman` with `/var/log/pacman.log` parsing
  - `ZypperPkg` — `zypper --xmlout` parsing
  - `AlpinePkg` — `apk` output parsing
- `src/pkg/cargo.rs` — `CargoInstall`: `cargo install` with progress
  tracking, binary path management
- `src/pkg/flatpak.rs` — `FlatpakManager`: flatpak/snap/appimage
  lifecycle

### Modules (`rust/crates/sysctrl/src/time/`)

- `src/time/cron.rs` — `CronManager`: crontab parser (5-field + 6-field),
  `/etc/cron.d/` file management, `crontab` command wrapper with
  structured error handling
- `src/time/timer.rs` — `TimerManager`: systemd timer unit creation/
  enable/disable/list, calendar event parsing

### Modules (`rust/crates/sysctrl/src/boot/`)

- `src/boot/grub.rs` — `GrubManager`: `/etc/default/grub` parser,
  kernel cmdline manipulation, default entry selection,
  `update-grub`/`grub-mkconfig` wrapper
- `src/boot/kernel.rs` — `KernelManager`: module lifecycle via
  `finit_module()`/`delete_module()` syscalls, kernel param query
  via `/sys/module/*/parameters/`, kexec via `kexec_load()` syscall
- `src/boot/initrd.rs` — `InitrdManager`: mkinitcpio/dracut/
  update-initramfs wrapper, initramfs rebuild triggers

### Modules (`rust/crates/sysctrl/src/recovery/`)

- `src/recovery/snapshot.rs` — `SnapshotManager`: LVM thin snapshot,
  Btrfs snapshot (`btrfs subvolume snapshot`), ZFS snapshot
  (`zfs snapshot`) wrappers
- `src/recovery/postmarket.rs` — `RollbackManager`: rollback to
  previous known-good state using snapper/timeshift/etckeeper

### Tools

- `Pkg { action, packages[], distro? }` — cross-distro package management
- `Cron { action, entry?, user? }` — cron job management
- `Timer { action, name, calendar?, command? }` — systemd timer management
- `BootConfig { kernel_params?, default_entry? }` — GRUB/kernel config
- `KernelModule { action, module, params? }` — kernel module lifecycle
- `Snapshot { action, volume?, description }` — storage snapshot

### Tests

- AptPkg parses `apt-cache show` output correctly
- CronManager roundtrips crontab 5-field expressions
- TimerManager creates valid systemd timer unit files
- KernelManager loads and unloads test module
- SnapshotManager detects available snapshot backends

---

## Phase 21 — Multi-Agent Debate & Consensus

**Goal**: For complex/high-risk problems, spawn multiple sub-agents with
different perspectives, cross-validate results, reach consensus through
voting/ranking before acting.

### New tools (`rust/crates/tools/src/lib.rs`)

- `DebateProblem { problem, perspectives[], min_consensus }` — spawn N
  sub-agents each with a biased prompt (skeptic, optimist, security-first,
  performance-first), collect all proposals, converge
- `JudgeResult { proposals[], criteria? }` — spawn a neutral judge agent
  that evaluates all proposals against criteria and picks the best
- `ConsensusVote { proposals[], rounds }` — iterative voting: show each
  agent all proposals, let them revise, repeat until convergence

### Orchestrator (`rust/crates/runtime/src/debate.rs`)

- `DebateOrchestrator` — manages the debate lifecycle:
  1. Normalize problem statement
  2. Generate perspective prompts (template per perspective)
  3. Spawn sub-agents in parallel threads
  4. Collect results (or timeout)
  5. Run Judge agent
  6. If consensus < threshold, enter feedback loop
  7. Return winning proposal + runner-up + reasoning
- `Perspective` enum: `Balanced | Skeptic | Optimist | Security | Performance | Usability`
- `DebateConfig` — `max_agents`, `timeout_seconds`, `consensus_threshold`,
  `max_rounds`

### System prompt additions

```
## Multi-Agent Consensus Protocol
Before acting on high-risk or ambiguous tasks:
1. Spawn 3-5 sub-agents with diverse perspectives
2. Each agent analyzes independently and proposes a solution
3. A judge agent evaluates all proposals
4. If consensus ≥ 80%, proceed with the winning approach
5. If not, iterate: share proposals, let agents revise, re-judge
6. After max rounds, the judge makes a final call
```

### Integration

- Connected to Phase 3 (Self-Validation): high-effort + high-risk tasks
  auto-trigger debate
- Connected to Phase 22 (Self-Healing): if a fix fails, debate the next
  approach instead of guessing
- Connected to Phase 15 (Exploitation): before generating exploits,
  debate the approach for maximum reliability

### Tests

- DebateOrchestrator spawns correct number of agents
- Perspective prompts bias agents as expected
- JudgeResult selects best proposal by criteria
- ConsensusVote converges within max rounds
- Timeout handling kills hung agents cleanly
- Integration: full debate cycle with mock agents

---

## Phase 22 — Self-Healing Auto-Recovery

**Goal**: When the agent makes an error (compile failure, test failure,
runtime panic, unexpected output), automatically spawn a debug agent to
analyze the failure, propose fixes, and retry. Track recovery success to
avoid infinite loops.

### New tools (`rust/crates/tools/src/lib.rs`)

- `SelfHeal { error_context, history? }` — spawn a debug agent with full
  error context (stderr, stdout, exit code, recent tool calls, code
  snippets), analyze root cause, propose fix
- `DebugAnalyze { error, code[], logs[] }` — root cause analysis with
  tags: `SyntaxError | LogicBug | DependencyMissing | PermissionDenied |
  NetworkTimeout | ResourceExhausted | Unknown`
- `ProposeFix { analysis, constraints? }` — generate specific edit
  operations to fix the error
- `ApplyFixAndRetry { fix[], original_task, max_retries? }` — apply
  the proposed fix(es) and re-execute the original task

### Recovery system (`rust/crates/runtime/src/recovery_auto.rs`)

- `AutoRecoveryOrchestrator` — lifecycle manager:
  1. Capture error (tool output + exit code + context)
  2. Classify error type (compile, runtime, permission, network, resource)
  3. Spawn DebugAgent with error + last N code states
  4. DebugAgent returns analysis + candidate fixes
  5. Apply fix via EditFile tool
  6. Re-execute original operation
  7. If success → log recovery + update memory
  8. If fail → escalate: increment attempt counter
  9. If counter > max (default 3) → escalate to user or debate (Phase 21)
- `RecoveryLedger` — persists recovery attempts to `.kraken/recovery.json`
  with: `error_type`, `debug_agent_id`, `proposed_fix`, `applied`,
  `success`, `duration`, `timestamp`
- `RecoveryStrategy` enum — `RetrySame | RetryWithFix | EscalateToDebate |
  EscalateToUser`

### Pipeline integration

```
Tool execution → error
  → Phase 1-2: classify error
  → Phase 3: spawn DebugAgent
  → Phase 4: receive fix
  → Phase 5: apply via EditFile
  → Phase 6: retry
  → Success ✓  |  Fail → increment → retry up to 3x
  → After 3 fails → escalate to Debate (Phase 21)
```

### Tests

- AutoRecoveryOrchestrator classifies errors correctly by pattern
- DebugAgent receives full context (no truncation of error)
- ProposalFix generates valid EditFile-compatible operations
- RecoveryLedger persists and loads recovery history
- Max retry escalation works correctly
- Integration: full recovery cycle with mock error

---

## Phase 23 — Autonomous Research Pipeline

**Goal**: Given a research question, decompose into sub-questions, spawn
parallel research agents per sub-question, each searching web/docs, then
synthesize into a structured report.

### New tools (`rust/crates/tools/src/lib.rs`)

- `ResearchPlan { question, depth?, sources[]? }` — decompose a research
  question into sub-questions, recommend sources per sub-question,
  estimate research scope
- `ResearchAgent { sub_question, sources[], depth }` — spawn an agent
  dedicated to researching one sub-question: web search, fetch pages,
  read docs, extract findings, return structured result
- `SynthesizeFindings { findings[], format? }` — consolidate findings
  from multiple research agents, resolve contradictions, rank by source
  reliability, produce unified result
- `GenerateReport { structure, findings, output_format? }` — produce
  final report in JSON, Markdown, or HTML with methodology, findings,
  confidence scores, source citations

### Pipeline (`rust/crates/osint/src/research.rs`)

- `ResearchPipeline` — full lifecycle orchestrator:
  1. `plan()` — LLM analyzes question, decomposes into 3-7 sub-questions
  2. `assign_sources()` — per sub-question: web search, document URLs,
     local files, codebase, or all
  3. `execute_parallel()` — spawn ResearchAgent per sub-question with
     timeout (default 120s per agent)
  4. `synthesize()` — SynthesizeFindings consolidates all agent results
  5. `report()` — GenerateReport produces final output
- `ResearchDepth` enum — `Quick | Normal | Deep | Exhaustive`
- `ResearchReport` — `question`, `sub_questions[]`, `findings[]`,
  `confidence`, `sources[]`, `execution_time`, `agent_count`

### Research agent system prompt

```
## Research Agent Instructions
You are a research sub-agent. Your task:
1. Search the web for the most relevant and authoritative sources
2. Fetch and read each source thoroughly
3. Extract key facts, data points, and citations
4. Note contradictions and uncertainties
5. Return: { findings: [...], sources: [...], confidence: 0.0-1.0 }

Do not speculate. Only report what sources actually say.
Rank sources by authority (official docs > peer-reviewed > blogs > forums).
```

### Integration

- Connected to Phase 7 (OSINT Foundation) — uses WebSearch/WebFetch tools
- Connected to Phase 9 (Person Identity) — research pipeline for person
  profiling
- Connected to Phase 24 (Self-Reflection) — research how to fix
  identified limitations
- Connected to Phase 25 (Self-Improvement) — research solutions before
  implementing code changes

### Tests

- ResearchPlan decomposes sample question into valid sub-questions
- ResearchAgent completes within timeout and returns structured output
- SynthesizeFindings resolves simple contradictions (by source rank)
- GenerateReport produces valid JSON/MD/HTML output
- Full pipeline: research → synthesize → report on a known topic
- Source reliability ranking works correctly

---

## Phase 24 — Code Self-Reflection & Improvement

**Goal**: After completing code tasks, the agent reflects on its own work
quality, identifies error patterns, and updates CLAUDE.md with lessons
learned to continuously improve future performance.

### New tools (`rust/crates/tools/src/lib.rs`)

- `ReflectOnWork { task_id, scope? }` — analyze completed task: what
  went well, what went wrong, what to do differently, extract actionable
  rules
- `IdentifyPatterns { history[], category? }` — scan past N tasks for
  recurring patterns: common error types, slow patterns, tool misuse,
  unnecessary steps
- `UpdateInstructions { insights[], target? }` — update CLAUDE.md (or
  `.kraken/instructions.md`) with new rules learned from reflection
- `SelfAudit { scope }` — audit agent's own performance: task success
  rate, average iterations, error frequency, tool usage stats

### Reflection engine (`rust/crates/runtime/src/reflection.rs`)

- `ReflectionEngine` — triggers after significant task completion:
  1. Collect task artifacts: tool calls, errors, iterations, output
  2. Analyze: success/failure, quality score, pattern detection
  3. Generate actionable rules (specific, testable, concise)
  4. Deduplicate against existing CLAUDE.md rules
  5. Append to CLAUDE.md with `### Learned {date}` section
- `TaskArtifact` — `task_id`, `prompt`, `tool_calls[]`, `errors[]`,
  `iterations`, `duration`, `success`
- `Insight` — `pattern`, `rule`, `examples[]`, `confidence`, `source_task`

### System prompt additions

```
## Self-Improvement Protocol
After completing significant tasks:
1. Use ReflectOnWork to analyze the task outcome
2. Identify what went well and what went wrong
3. Use IdentifyPatterns to find recurring issues
4. If patterns found, use UpdateInstructions to add rules
5. Rules should be: specific, actionable, one rule per line

Your CLAUDE.md evolves as you learn. Each update makes you more
effective on future tasks.
```

### Rules format in CLAUDE.md

```markdown
# Learned Rules (auto-generated)

## 2026-06-10
- When using cargo test, always run `cargo test --workspace` not `cargo test`
- After editing TOML files, run `cargo check` before `cargo test`
- For dependency issues, check Cargo.lock before modifying Cargo.toml
```

### Guardrails

- Max 3 new rules per reflection (prevent bloat)
- Deduplication: skip if semantically similar rule already exists
- Auto-generated rules are tagged with `(auto)` for human review
- Rules with `confidence < 0.7` are stored but not appended until validated

### Tests

- ReflectionEngine generates rules from mock task errors
- Deduplication prevents identical rules from being added twice
- UpdateInstructions correctly appends to existing CLAUDE.md
- Confidence scoring: correct patterns score > 0.8, coincidences < 0.5
- SelfAudit returns accurate success rate statistics

---

## Phase 25 — Full Self-Improvement Autonomy

**Goal**: The agent identifies its own capability limitations, researches
solutions, implements new tools or code improvements, compiles, tests, and
deploys changes — all autonomously. The agent grows its own capabilities
without human intervention.

### New tools (`rust/crates/tools/src/lib.rs`)

- `SelfIdentifyLimitation { task_history[], capability_gaps? }` — analyze
  failed or suboptimal tasks to identify missing capabilities (no tool
  for X, slow at Y, can't do Z)
- `ResearchSolution { limitation, constraints? }` — research how to
  implement the missing capability: search crates.io, docs, similar
  tools in codebase, propose implementation plan
- `ImplementChange { design, files[], test_command? }` — write new code
  or modify existing code following the design plan; supports: new tool,
  new crate, new module, modified module
- `SelfTest { changes, test_pattern? }` — compile workspace, run relevant
  tests (by pattern), report pass/fail with details
- `SelfDeploy { changes, test_results }` — if all tests pass, finalize
  the change: write to disk, register new tool, restart runtime component

### Self-improvement engine (`rust/crates/runtime/src/self_improve.rs`)

- `SelfImprovementEngine` — full autonomy lifecycle:
  1. **Detect gap**: task fails or is suboptimal → `SelfIdentifyLimitation`
  2. **Research**: `ResearchSolution` searches crates.io, docs, codebase
     for approaches (e.g., "need PDF parser → `pdf-extract` crate")
  3. **Design**: generate implementation plan (files to modify, types to
     add, dependencies to add)
  4. **Implement**: `ImplementChange` writes code, adds dependencies to
     Cargo.toml, registers new tools
  5. **Test**: `SelfTest` compiles + runs relevant tests
  6. **Deploy**: `SelfDeploy` integrates the change
  7. **Log**: update `/root/code/claw-vzla/.kraken/capabilities.md` with
     new capability
- `SelfImprovementMode` — `SuggestOnly | AutoMinor | AutoMajor`
  - `SuggestOnly`: research and design but ask before writing
  - `AutoMinor`: auto-implement tool additions and minor changes
  - `AutoMajor`: full autonomy including crate creation
- `CapabilityRegistry` — tracks known capabilities, limitations, and
  improvement history in `.kraken/capabilities.md`

### System prompt additions

```
## Self-Improvement Mode (auto-improve)
You have the ability to improve your own capabilities. When you:
1. CANNOT do something → identify the gap
2. Research the best way to implement it
3. Write code to add the capability
4. Test that it works
5. Register the new capability for future use

This is how you grow. Each improvement makes you more capable
for the next task.

Current mode: {SuggestOnly | AutoMinor | AutoMajor}
```

### Safety architecture

- All self-improvement is opt-in via `--self-improve` flag
- Changes are made in a sandbox directory first (`/tmp/kraken-self-mod/`)
- Compilation must succeed before changes are integrated
- Tests must pass before deployment
- A `.kraken/self-improve.log` tracks every change for audit
- `AutoMajor` mode requires explicit user confirmation via environment
  variable `KRAKEN_SELF_IMPROVE=auto-major`

### Complete self-improvement cycle example

```
Task: "Parse this PDF and extract the tables"
  → Main agent has no PDF tool
  → SelfIdentifyLimitation: "missing PDF/text extraction capability"
  → ResearchSolution: searches crates.io → finds `pdf-extract` + `lopdf`
  → Design: create PdfExtract tool in tools/src/lib.rs, add dependencies
  → ImplementChange: writes ~150 lines of Rust, adds deps to Cargo.toml
  → SelfTest: cargo build + cargo test --lib pdf_extract → PASS
  → SelfDeploy: registers tool, adds to tool registry
  → Retry original task with new PdfExtract tool → SUCCESS
  → Update capabilities.md: "Added PDF extraction (2026-06-10)"
```

### Tests

- SelfIdentifyLimitation detects missing tool from error pattern
- ResearchSolution returns valid crate candidates for known gaps
- ImplementChange writes syntactically valid Rust code
- SelfTest correctly reports pass/fail from mock build output
- SelfDeploy registers new tool in global tool registry
- Mode enforcement: SuggestOnly blocks auto-implementation
- Integration: full cycle with mock build returning success

---

## Summary

| Phase | Capability | Files/Crates new | Tools | Complexity |
|-------|-----------|------------------|-------|------------|
| 1 | Vision / Image Input | 6 files | 2 | High |
| 2 | Persistent Memory | 3 files | 3 | Low |
| 3 | Self-Validation | 3 files | — | Low |
| 4 | Multi-Agent Orchestration | 2 files | — | Medium |
| 5 | Autonomous Migration | 1 file | 3 | Medium |
| 6 | Enhanced Security (vulnscan) | 2 files | — | Medium |
| 7 | OSINT Foundation | crate `osint` (4 files) | 3 | Medium |
| 8 | Social Media OSINT | `osint` (2 files) | 3 | Medium |
| 9 | Person Identity Correlation | `osint` (4 files) | 3 | Medium |
| 10 | Dark & Surface Web Recon | `osint` (3 files) | 3 | Medium |
| 11 | Network Attack Surface | `vulnscan` (2 files) | 3 | Medium |
| 12 | System Security Audit | crate `audit` (6 files) | 2 | High |
| 13 | System Hardening Engine | crate `hardening` (5 files) | 3 | High |
| 14 | Threat Detection & Monitoring | crate `monitor` (4 files) | 3 | High |
| 15 | Advanced Exploitation Chain | `vulnscan` (3 files) | 3 | High |
| 16 | Automated Defense & IR | crate `response` (3 files) | 3 | High |
| 17 | Process & Service Control | crate `sysctrl` (6 files) | 5 | High |
| 18 | Storage & Filesystem | `sysctrl` (7 files) | 5 | High |
| 19 | Network & User Control | `sysctrl` (11 files) | 5 | High |
| 20 | Package & Automation Control | `sysctrl` (12 files) | 6 | High |
| 21 | Multi-Agent Debate & Consensus | `runtime` (1 file) + tools | 3 | High |
| 22 | Self-Healing Auto-Recovery | `runtime` (1 file) + tools | 4 | High |
| 23 | Autonomous Research Pipeline | `osint` (1 file) + tools | 4 | High |
| 24 | Code Self-Reflection & Improvement | `runtime` (1 file) + tools | 4 | Medium |
| 25 | Full Self-Improvement Autonomy | `runtime` (1 file) + tools | 5 | Extreme |

**Total**: 9 new crates, ~90 files, ~75 new tools
**Model**: Big Pickle (OpenCode Zen) — unlimited free, OpenAI-compatible API
**Stack**: Rust + Tokio async + reqwest HTTP + sqlite storage + nix + libc
