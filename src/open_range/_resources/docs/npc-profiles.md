# NPC Profile Spec

This document defines the public manifest contract for role-level green-user
behavior in OpenRange V1.

`npc_profiles` is a public business-world input. It shapes generated
`GreenPersona` objects without exposing private validator references or hidden
weakness inventory.

## Goals

- Let manifest authors vary role-level NPC behavior without editing Python code.
- Keep the contract backward compatible with existing manifests.
- Make the current semantics explicit so newcomers do not need to read the
  compiler or runtime to use the feature safely.

## Manifest Shape

`npc_profiles` is an optional top-level manifest field.

```yaml
users:
  roles:
    sales: 2
    engineer: 1
    it_admin: 1

npc_profiles:
  sales:
    awareness: 0.2
    susceptibility:
      initial_access: 0.8
      credential_obtained: 0.7
    routine:
      - check_mail
      - browse_app
      - access_fileshare
  it_admin:
    awareness: 0.9
    susceptibility:
      unauthorized_credential_use: 0.2
    routine:
      - review_idp
      - triage_alerts
      - reset_password
```

Rules:

- `npc_profiles` is optional. Omitting it preserves current compiler behavior.
- Keys MUST match names declared in `users.roles`.
- All fields are optional. Omitted fields fall back to the existing compiler
  defaults for that role.
- Profiles apply per role, not per individual user.
- `awareness` and all `susceptibility` values must be between `0.0` and `1.0`.

## Field Definitions

### `awareness`

`awareness` is a normalized caution score.

- `0.0` means minimally aware.
- `1.0` means maximally aware.

Current V1 semantics:

- Used by the green scheduler when choosing which persona reacts in the
  `small_llm` backend.
- Higher awareness makes a persona more likely to be selected as the reporter.
- Higher awareness also makes recovery actions more likely once a malicious
  event has been observed.

### `susceptibility`

`susceptibility` is a map from label to probability-like score.

- `0.0` means minimally susceptible for that label.
- `1.0` means maximally susceptible for that label.
- Keys are free-form strings at the schema level.

Recommended stable keys for V1:

- `initial_access`
- `credential_obtained`
- `unauthorized_credential_use`

Current V1 semantics:

- The `small_llm` green backend first looks up the event-style key associated
  with the observed malicious event.
- If that exact key is missing, it falls back to the maximum value in the map.
- Other backends currently do not use `susceptibility` directly.

Implication:

- Free-form labels such as `phishing`, `pretexting`, or `spear_phishing` are
  accepted and preserved in the manifest and `WorldIR`.
- For predictable runtime behavior today, prefer the event-style keys above.

### `routine`

`routine` is an ordered list of benign activities for that role.

Current V1 semantics:

- The green scheduler cycles through the list over time.
- Each token is interpreted heuristically into a service target.
- The order matters because the scheduler advances through the list.

Recommended stable routine tokens for V1:

- `check_mail`
- `browse_app`
- `access_fileshare`
- `open_payroll_dashboard`
- `review_idp`
- `triage_alerts`
- `reset_password`

Current service mapping:

- tokens containing `mail` -> email
- tokens containing `file` or `share` -> fileshare
- tokens containing `idp` or `password` -> IDP
- tokens containing `alert` or `triage` -> SIEM
- tokens containing `payroll` -> database
- everything else -> web app

## Compiler Rules

At compile time:

- OpenRange validates that every `npc_profiles` key exists in `users.roles`.
- A role profile is applied uniformly to all generated users for that role.
- A profile only overrides fields that are explicitly set.
- Omitted fields keep the same defaults as before the feature was added.

## What This Covers Today

`npc_profiles` is useful today for:

- coarse role-level benign routine shaping
- coarse role-level green reaction weighting in the `small_llm` backend
- reproducible manifest-authored variation across snapshots

## What This Does Not Cover Yet

`npc_profiles` does not yet provide:

- per-individual overrides within a role
- an explicit click-through model for phishing links or attachments
- a first-class taxonomy of social-engineering technique keys
- uniform `susceptibility` semantics across all green backends
- explicit policies for escalation, ticketing, or reporting thresholds beyond
  the current scheduler heuristics

If V1 needs "careless reps click every lure" or "admins report every anomaly"
as first-class scenario semantics, the next step should be a dedicated NPC
behavior model with explicit pre-compromise and post-compromise controls rather
than relying only on the current `awareness` and `susceptibility` heuristics.
