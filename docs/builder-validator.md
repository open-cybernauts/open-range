# Builder + Validator Design

## Overview

**LLM generates, rules validate.** The builder uses LiteLLM to generate candidate company snapshots. The validator is purely mechanical -- executable checks against live containers, no LLM judgment.

Snapshot creation happens **asynchronously between episodes**. `reset()` picks a pre-validated frozen snapshot. No LLM calls in the hot path.

```mermaid
flowchart LR
    MF[Manifest<br/>legal family] --> BLD[Builder LLM<br/>via LiteLLM]
    CURR[Curriculum stats<br/>solve rates, weaknesses] --> BLD
    BLD --> SNAP[Candidate snapshot<br/>topology, truth graph,<br/>evidence, tasks, docker artifacts]
    SNAP --> VAL{Validator gate<br/>mechanical checks only}
    VAL -->|pass| STORE[Snapshot store<br/>frozen, ready for reset]
    VAL -->|fail| BLD

    style BLD fill:#ff6b6b,color:#fff
    style VAL fill:#ffd93d,color:#333
    style STORE fill:#6bcb77,color:#fff
```

## Builder (LLM via LiteLLM)

The Builder generates complete enterprise snapshots from YAML manifests. It runs asynchronously, producing a queue of validated snapshots that `reset()` draws from.

### Input

```yaml
# Manifest defines the legal company family
name: acme_corp
tier: 1

topology:
  hosts:
    - name: web
      zone: dmz
      services: [nginx, php, sshd]
      connects_to: [db, ldap]
    - name: mail
      zone: dmz
      services: [postfix, dovecot]
      connects_to: [ldap]
    - name: db
      zone: internal
      services: [mysql]
      connects_to: [ldap]
    - name: files
      zone: internal
      services: [samba]
      connects_to: [ldap]
    - name: ldap
      zone: management
      services: [slapd, krb5]
    - name: siem
      zone: management
      services: [rsyslog, elasticsearch]
      receives_logs_from: [web, mail, db, files, ldap, firewall]
    - name: firewall
      zone: perimeter
      services: [iptables]
    - name: attacker
      zone: external
      services: [kali-tools]
  networks:
    - name: external
    - name: dmz
      cidr: 10.0.1.0/24
    - name: internal
      cidr: 10.0.2.0/24
    - name: management
      cidr: 10.0.3.0/24
  firewall_rules:
    - allow: {from: external, to: dmz, ports: [80, 443, 25]}
    - allow: {from: dmz, to: internal, ports: [3306, 445]}
    - allow: {from: dmz, to: management, ports: [389, 636]}
    - allow: {from: internal, to: management, ports: [389]}
    - deny: {from: internal, to: external}
    - deny: {from: management, to: external}

bug_families: [sqli, xss, idor, path_traversal, command_injection, ssrf, weak_creds, broken_auth]
task_families: [exploit, investigate, patch, report]

difficulty:
  max_steps: 12
  min_vulns: 1
  max_vulns: 3

# Injected at runtime
runtime_context:
  previous_vuln_classes: [sqli, weak_creds]
  red_solve_rate: 0.6
  blue_detect_rate: 0.4
```

### Output (Candidate Snapshot)

The Builder outputs a structured JSON snapshot spec. The LLM does the creative work (designing realistic vulnerabilities, generating vulnerable code, constructing exploit chains). Templates handle mechanical file rendering.

```json
{
  "snapshot_id": "acme_v14",
  "topology": {
    "hosts": ["attacker", "firewall", "web", "mail", "db", "files", "ldap", "siem"],
    "zones": {"external": ["attacker"], "dmz": ["web", "mail"], "internal": ["db", "files"], "management": ["ldap", "siem"]},
    "users": [
      {"username": "admin", "password": "Adm1n!2024", "groups": ["admins"], "hosts": ["web", "db"]},
      {"username": "jsmith", "password": "Welcome1", "groups": ["users"], "hosts": ["web", "mail", "files"]},
      {"username": "svc_backup", "password": "backup123", "groups": ["service"], "hosts": ["db", "files"]}
    ]
  },
  "truth_graph": {
    "vulns": [
      {
        "id": "vuln1",
        "type": "idor",
        "host": "web",
        "service": "nginx+php",
        "injection_point": "/api/users/{id}/profile",
        "vulnerable_code": "<?php $id=$_GET['id']; $stmt=$conn->query(\"SELECT * FROM users WHERE id=$id\"); ?>",
        "root_cause": "No authorization check on user ID parameter",
        "blast_radius": ["user data exposure", "credential leakage"],
        "remediation": "Add session-based authorization check before query"
      },
      {
        "id": "vuln2",
        "type": "weak_creds",
        "host": "db",
        "service": "mysql",
        "injection_point": "mysql -u svc_backup -pbackup123",
        "root_cause": "Service account with weak password and excessive privileges",
        "blast_radius": ["full database access", "flag exfiltration"],
        "remediation": "Rotate password, restrict to backup-only permissions"
      }
    ],
    "exploit_chain": [
      {"step": 1, "action": "Enumerate web app via IDOR", "vuln": "vuln1", "yields": "svc_backup credentials"},
      {"step": 2, "action": "Pivot to DB with stolen creds", "vuln": "vuln2", "yields": "flag from secrets table"}
    ]
  },
  "flags": [
    {"id": "flag1", "value": "FLAG{1d0r_ch41n_2_db}", "path": "db:flags.secrets.flag", "host": "db"}
  ],
  "golden_path": [
    {"step": 1, "cmd": "nmap -sV 10.0.1.0/24", "expect_stdout": "80/tcp open http", "host": "attacker"},
    {"step": 2, "cmd": "curl http://web/api/users/1/profile", "expect_stdout": "admin", "host": "attacker"},
    {"step": 3, "cmd": "curl http://web/api/users/3/profile", "expect_stdout": "svc_backup", "host": "attacker"},
    {"step": 4, "cmd": "mysql -h db -u svc_backup -pbackup123 -e 'SELECT flag FROM flags.secrets'", "expect_stdout": "FLAG{1d0r_ch41n_2_db}", "host": "attacker"},
    {"step": 5, "cmd": "submit_flag FLAG{1d0r_ch41n_2_db}", "expect_stdout": "correct", "host": "attacker"}
  ],
  "evidence_spec": {
    "web_access_log": "IDOR requests show sequential user ID enumeration from attacker IP",
    "db_query_log": "Unexpected SELECT on flags.secrets from svc_backup account",
    "siem_alerts": ["Suspicious user enumeration pattern", "Service account accessing sensitive table"]
  },
  "npc_traffic": {
    "http_rate": 30,
    "smtp_rate": 5,
    "ldap_rate": 10,
    "smb_rate": 8
  },
  "npc_personas": [
    {
      "id": "npc_jsmith",
      "name": "Janet Smith",
      "role": "Marketing Coordinator",
      "department": "Marketing",
      "reports_to": "npc_director_marketing",
      "communication_style": "casual, responds quickly, uses exclamation marks",
      "security_awareness": 0.3,
      "susceptibility": {
        "phishing_email": 0.7,
        "credential_sharing": 0.4,
        "attachment_opening": 0.8,
        "vishing": 0.6
      },
      "relationships": ["trusts IT helpdesk", "friends with npc_bob in accounting"],
      "routine": {
        "email_check_interval_min": 15,
        "typical_actions": ["browse intranet", "send marketing reports", "LDAP lookups"]
      },
      "accounts": {"email": "jsmith@acmecorp.local", "ldap": "jsmith", "smb_shares": ["marketing", "shared"]}
    },
    {
      "id": "npc_ciso",
      "name": "David Chen",
      "role": "CISO",
      "department": "Security",
      "communication_style": "formal, suspicious of unusual requests, always verifies sender",
      "security_awareness": 0.95,
      "susceptibility": {
        "phishing_email": 0.05,
        "credential_sharing": 0.01,
        "attachment_opening": 0.1,
        "vishing": 0.05
      },
      "relationships": ["reports to CEO", "manages SOC team"],
      "routine": {
        "email_check_interval_min": 5,
        "typical_actions": ["review SIEM alerts", "approve access requests", "policy updates"]
      },
      "accounts": {"email": "dchen@acmecorp.local", "ldap": "dchen", "smb_shares": ["security", "executive"]}
    }
  ],
  "task": {
    "red_briefing": "A corporate network with web services and backend infrastructure. Investigate the environment and capture the flags.",
    "blue_briefing": "You are the SOC analyst for AcmeCorp. Monitor the SIEM for suspicious activity, investigate alerts, and respond to threats."
  }
}
```

### LiteLLM Integration

```python
import litellm

response = litellm.completion(
    model=os.environ.get("OPENRANGE_BUILDER_MODEL", "anthropic/claude-sonnet-4-20250514"),
    messages=[
        {"role": "system", "content": BUILDER_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({
            "manifest": manifest_dict,
            "runtime_context": runtime_context,
        })}
    ],
    response_format={"type": "json_object"},
    temperature=0.7,
)
snapshot_spec = json.loads(response.choices[0].message.content)
```

Configure via environment:
- `OPENRANGE_BUILDER_MODEL` -- any LiteLLM-supported model string
- Model-specific keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_API_BASE`, etc.

### Template Layer

The LLM generates the structured spec. A thin template layer renders it into Docker artifacts:

| Template | Renders from | Output |
|----------|-------------|--------|
| `docker-compose.yml.j2` | topology, zones, firewall_rules | Compose file with networks and services |
| `Dockerfile.web.j2` | topology.hosts[web] | nginx + PHP app container |
| `Dockerfile.db.j2` | topology.hosts[db] | MySQL with schema |
| `nginx.conf.j2` | vuln injection points | Web server config |
| `app.php.j2` | vulnerable_code from truth_graph | Vulnerable application code |
| `init.sql.j2` | users, flags, app data | Database initialization |
| `smb.conf.j2` | files host config | Samba share configuration |
| `slapd.conf.j2` | users, groups | LDAP directory setup |
| `iptables.rules.j2` | firewall_rules | Firewall rule set |
| `npc_traffic.sh.j2` | npc_traffic rates | Background traffic scripts |
| `npc_personas.yaml.j2` | npc_personas array | Persona cards for LLM-driven NPCs |

## Validator Gate (Mechanical Only)

The validator is **purely mechanical**. No LLM calls. Every check is an executable script run against live containers.

### Admission Pipeline

```mermaid
flowchart LR
    S1[1. Build + boot<br/>docker compose up<br/>all healthchecks pass] --> S2[2. Exploitability<br/>run golden path<br/>all steps succeed]
    S2 --> S3[3. Patchability<br/>revert each vuln<br/>golden path breaks]
    S3 --> S4[4. Evidence sufficiency<br/>logs + alerts exist<br/>for Blue investigation]
    S4 --> S5[5. Reward grounding<br/>rubrics produce<br/>valid scores]
    S5 --> S6[6. Isolation + leakage<br/>zones enforced<br/>no answer leaks]
    S6 --> S7[7. NPC consistency<br/>personas respond<br/>per security_awareness]

    S7 -->|All pass| PASS[ADMIT SNAPSHOT]
    S7 -->|Any fail| FAIL[REJECT + RETRY]

    style PASS fill:#6bcb77,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
    style S3 fill:#ffd93d,color:#333
```

### Check Details

| Check | What it does | How | Pass condition |
|-------|-------------|-----|----------------|
| **1. Build + boot** | Start all containers, verify services | `docker compose up -d` + healthchecks | All 8 containers healthy, all ports respond |
| **2. Exploitability** | Execute golden path end-to-end | Run each step from attacker container | `expect_stdout` found in each step's output |
| **3. Patchability** | Inverse mutation test | For each vuln: apply remediation, re-run its golden path step | Step MUST fail after patch |
| **4. Evidence sufficiency** | Blue has enough to investigate | Check logs exist, SIEM alerts fire, evidence files present | All evidence_spec items found |
| **5. Reward grounding** | Rubrics produce valid scores | Run CompositeRedReward and CompositeBlueReward against known scenarios | Scores in expected ranges |
| **6. Isolation + leakage** | Network segmentation holds, no answer leaks | Attacker tries to reach internal directly; grep task briefings for flag values | Connection refused; no flag strings in briefings |
| **7. NPC consistency** | Personas behave per security_awareness | Send calibrated test phishing to each NPC persona | High-awareness NPCs reject, low-awareness NPCs fall for well-crafted lures |

### Check 3: Patchability (Most Important)

This is the inverse mutation test from Self-Play SWE-RL. For each planted vulnerability:

1. Apply the **remediation** from the truth graph (e.g., parameterize the SQL query)
2. Re-run the golden path step that exploits it
3. That step **MUST fail**
4. Revert the remediation (restore vulnerable code)

If patching a vuln doesn't break the golden path, the vuln is decorative -- the exploit works for a different reason. The snapshot is rejected.

### Failure Handling

```
Builder generates candidate snapshot
  -> Validator builds + boots containers
  -> Runs 6 admission checks
  -> Any fail -> Builder receives failure context, generates new snapshot
  -> 3 consecutive failures -> Flag for human review, use last known-good snapshot
```

### Validation Metrics

Every admission decision is logged for quality monitoring:

```json
{
  "snapshot_id": "acme_v14",
  "builder_model": "anthropic/claude-sonnet-4-20250514",
  "attempt": 1,
  "checks": {
    "build_boot": {"pass": true, "time_s": 12.3},
    "exploitability": {"pass": true, "time_s": 8.1},
    "patchability": {"pass": true, "time_s": 15.2},
    "evidence_sufficiency": {"pass": true, "time_s": 2.1},
    "reward_grounding": {"pass": true, "time_s": 3.4},
    "isolation_leakage": {"pass": true, "time_s": 4.0}
  },
  "total_time_s": 45.1,
  "admitted": true,
  "vuln_classes": ["idor", "weak_creds"],
  "golden_path_steps": 5
}
```

### Toxic Validation Warning

R2E-Gym found ~10% of validations incorrectly favor wrong solutions. Track:
- False-positive rate (admitted broken snapshots that don't produce training signal)
- False-negative rate (rejected valid snapshots unnecessarily)
- Log every admission decision for post-hoc auditing

## LLM NPCs: Social Engineering Surface

### Why

Shell-script NPCs generate noise. LLM NPCs create an **attack surface**. Social engineering is the #1 real-world breach vector, but current cybersecurity AI training environments ignore it entirely because there's nobody to phish.

LLM NPCs let Red learn to craft phishing emails, pretext calls, and watering hole attacks. Blue simultaneously learns to detect these patterns in logs. The coupled reward creates an arms race in social engineering.

### Architecture

NPCs follow the same platform pattern: **Builder generates persona cards, Validator checks consistency, NPCs run as lightweight LLM agents during episodes.**

```mermaid
flowchart LR
    BLD[Builder LLM] --> PC[Persona Cards<br/>name, role, security_awareness,<br/>susceptibility, relationships]
    PC --> VAL{Validator<br/>NPC consistency check}
    VAL -->|pass| SNAP[Snapshot store]

    subgraph episode [During Episode]
        STIM[Stimulus<br/>email, chat, call] --> NPC[NPC LLM Agent<br/>persona + context]
        NPC --> ACT{Action}
        ACT --> CLICK[Click link]
        ACT --> REPLY[Reply with info]
        ACT --> IGNORE[Ignore]
        ACT --> REPORT[Report to IT]
    end

    SNAP --> episode

    style BLD fill:#ff6b6b,color:#fff
    style VAL fill:#ffd93d,color:#333
    style NPC fill:#7c73e6,color:#fff
```

### NPC Decision Function

Each NPC receives incoming stimuli and decides based on persona:

```
Input:  persona_card + stimulus (email body, sender, subject) + time_of_day + conversation_history
Output: action (click_link | open_attachment | reply | share_credentials | ignore | report_to_IT | forward)
```

The NPC LLM call is **not in the hot path** of `step()`. It runs asynchronously -- Red sends a phishing email in one step, the NPC processes it on its own schedule (based on `email_check_interval_min`), and Red sees the result in subsequent observations (access logs, new sessions, SIEM alerts).

### Red Social Engineering Actions

| Attack Vector | Channel | Red Action | NPC Response Based On |
|---------------|---------|------------|----------------------|
| Spearphishing | Email (Postfix) | Craft email from spoofed sender | `security_awareness` + email plausibility + sender reputation |
| Pretexting | Email/Chat | Impersonate IT, request creds | `credential_sharing` susceptibility + pretext quality |
| Watering hole | Web | Plant malicious page on compromised intranet | NPC browsing routine + link plausibility |
| Baiting | SMB | Drop malicious file on shared drive | `attachment_opening` susceptibility + file name/type |
| Vishing | Voice (stretch) | Call NPC, social-engineer credentials | `vishing` susceptibility + conversation plausibility |

### Blue Detection

Blue sees the **effects** in logs, never the NPC's internal reasoning:
- Anomalous email patterns (external sender → credential reset → new login)
- Unusual login locations (NPC account authenticates from attacker IP)
- Credential usage from wrong hosts (jsmith's creds used on DB, not marketing)

### Reward Extensions

| Signal | Agent | Source |
|--------|-------|--------|
| `r_social_engineering` | Red | NPC fell for attack (clicked link, shared creds) |
| `r_pretext_quality` | Red | Consistency of social engineering narrative |
| `r_phishing_detection` | Blue | Correctly identified phishing email in mail logs |
| `r_social_FP` | Blue | -0.2 per legitimate NPC email flagged as phishing |

### Multimodal Progression

| Level | Modality | Infrastructure | Training Signal |
|-------|----------|---------------|-----------------|
| 0 | None | Shell scripts | Noise ratio only |
| 1 | Text email | Postfix + LLM NPC agent | Social engineering + phishing detection |
| 2 | Text chat | Internal messaging service + LLM | Lateral social engineering |
| 3 | Voice | TTS/STT (Whisper + voice synthesis) | Vishing + voice phishing detection |
| 4 | Documents | Multimodal LLM (vision) | Malicious document analysis |

### Validator Check 7: NPC Consistency

For each NPC persona in the snapshot:
1. Send a **calibrated test phishing email** matching the persona's role
2. NPC with `security_awareness >= 0.8` MUST reject/report it
3. NPC with `security_awareness <= 0.3` MUST fall for a well-crafted lure
4. Verify communication style matches persona (formal CISO vs casual intern)
5. Verify NPC never leaks flag values or truth graph details
