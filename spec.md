# OpenRange V1 Design Doc

## 1. One-line definition

**OpenRange V1 is a mutable red/blue/green enterprise cyber training system that builds a business from a manifest, validates it with hidden deterministic witnesses, runs episodes on immutable live snapshots, and trains separate red and blue agent sessions against realistic user traffic and operational constraints.**

## 2. Why this exists

Public cyber-agent artifacts today are strong at **evaluation** or **simulation**, but they do not directly give you a mutable enterprise training environment with real services, realistic blue-team observability, and normal user traffic. CyBench is a fixed evaluation benchmark with 40 professional CTF tasks; CAGE 4 is an enterprise defense simulator with green users; Worlds shows a manifest-first deterministic cyber simulation that emits tool-call events and can generate synthetic trajectories cheaply; SSR shows how to use a hidden formal oracle, consistency validation, inverse-mutation checks, and simple verifiable rewards; and Kind is a practical local Kubernetes-in-Docker backend for reproducible development rather than the core research contribution itself. ([cybench.github.io][1])

OpenRange borrows:

* from **SSR**: hidden oracle, deterministic admission, necessity checks, simple terminal reward, evolving task distribution,
* from **Worlds**: manifest-first world modeling, text/tool semantics, event emission, optional cheap synthetic traces,
* from **CAGE-style defense**: green users are first-class because blue realism requires noise, continuity, and ambiguity,
* from **Kind**: a clean live backend, but not the scientific claim. ([arXiv][2])

## 3. V1 scope

### In scope

One bounded world family: `enterprise_saas_v1`

Services:

* public web app
* email
* identity provider
* fileshare / document store
* relational database
* SIEM / log sink

Actors:

* red attacker
* blue defender
* green users / business traffic

Capabilities:

* manifest-driven world generation
* deterministic admission
* immutable snapshots
* live training on Kind
* separate red/blue sessions in the same episode
* green traffic inside the same episode
* typed mutations between generations
* optional lightweight sim plane for cheap bootstrap traces

### Out of scope

* arbitrary company generation
* arbitrary internet access
* public golden paths
* LLM judge for reward or admission
* free-form LLM-authored infra
* mutation during an episode
* one shared red/blue memory stream
* evidence-as-reward
* patch reward based on command names
* browser-agent-heavy autonomy as a hard dependency

## 4. Core principles

1. **Manifest defines the business, not the answer key.**
   The public manifest describes a legal family of worlds: topology, workflows, roles, assets, observability, weakness families, difficulty, and mutation bounds.

2. **WorldIR is the canonical source of truth.**
   Every live artifact and every synthetic trace comes from one typed internal world model.

3. **The oracle is private.**
   The validator creates a hidden `WitnessBundle`; the human manifest never contains the exploit script.

4. **Builder is not RL-trained in V1.**
   Red and blue are trainable. Builder is a compiler/generator with validator feedback.

5. **Green is part of the environment, not decoration.**
   Green provides background work, workflow surface, and continuity pressure.

6. **Same world, separate minds.**
   Red and blue act in the same episode, but in separate sessions with separate memory.

7. **Terminal reward first, shaping second.**
   Main reward comes from objective satisfaction and validated containment. Shaping is small and event-grounded.

8. **Kind is the backend, not the paper.**
   The paper claim is about admitted mutable enterprise worlds, not Helm or Kubernetes.

---

## 5. System overview

```text
Public Manifest
    ↓
ManifestCompiler
    ↓
WorldIR (typed business graph)
    ├── Optional Sim Plane
    │      ↓
    │   cheap traces / candidate triage
    │
    └── Live Build
           ↓
      WorldSynthesizer (LLM, bounded modules only)
           ↓
      WeaknessSeeder (deterministic catalog)
           ↓
      KindRenderer
           ↓
      Candidate Live Range
           ↓
      AdmissionController
        - static checks
        - live checks
        - red witness checks
        - blue witness checks
        - necessity checks
        - shortcut probes
        - determinism checks
           ↓
Immutable Snapshot + WitnessBundle + ValidatorReport
           ↓
Episode Runtime
  - GreenScheduler
  - RedSession
  - BlueSession
  - EventBus
  - RewardEngine
           ↓
Trajectories + population stats
           ↓
MutationPolicy
           ↓
new world candidates
```

---

## 6. Public manifest

The manifest is the public, human-authored declaration of the business.

It must define:

* business archetype
* zones and service palette
* roles and user counts
* workflows
* sensitive assets
* red objective predicates
* blue objective predicates
* observability requirements
* allowed weakness families
* difficulty targets
* mutation bounds

It must not define:

* literal exploit commands
* `expect_in_stdout`
* public flag paths
* one canonical “optimal path”

### Example shape

```yaml
version: 1
world_family: enterprise_saas_v1
seed: 1337

business:
  archetype: healthcare_saas
  workflows:
    - helpdesk_ticketing
    - payroll_approval
    - document_sharing
    - internal_email

topology:
  zones: [external, dmz, corp, data, management]
  services: [web_app, email, idp, fileshare, db, siem]

users:
  roles:
    sales: 8
    engineer: 6
    finance: 2
    it_admin: 1

assets:
  - id: finance_docs
    class: crown_jewel
  - id: payroll_db
    class: crown_jewel
  - id: idp_admin_cred
    class: sensitive

objectives:
  red:
    - predicate: asset_read(finance_docs)
    - predicate: credential_obtained(idp_admin_cred)
  blue:
    - predicate: intrusion_detected(initial_access)
    - predicate: intrusion_contained(before_asset_read)
    - predicate: service_health_above(0.9)

security:
  allowed_weakness_families:
    - auth_misconfig
    - workflow_abuse
    - secret_exposure
    - input_validation
    - telemetry_blindspot
  observability:
    require_web_logs: true
    require_idp_logs: true
    require_email_logs: true
    require_siem_ingest: true

difficulty:
  target_red_path_depth: 8
  target_blue_signal_points: 4
  target_noise_density: medium

mutation_bounds:
  max_new_hosts: 2
  max_new_services: 1
  max_new_users: 5
  max_new_weaknesses: 2
```

---

## 7. WorldIR

`WorldIR` is the typed internal business graph.

It should contain:

* zones
* hosts
* services
* users
* groups
* credentials
* assets
* workflows
* network edges
* trust edges
* data edges
* telemetry edges
* weaknesses
* red/blue objectives
* green personas and workload spec
* lineage

This is the actual source of truth. The manifest is just input.

### Minimal core objects

```python
WorldIR
HostSpec
ServiceSpec
UserSpec
CredentialSpec
AssetSpec
WorkflowSpec
EdgeSpec
WeaknessSpec
ObjectiveSpec
GreenPersona
GreenWorkloadSpec
```

---

## 8. Build pipeline

### 8.1 ManifestCompiler

Validates the manifest and expands it into `WorldIR`.

Responsibilities:

* schema validation
* role expansion into users/personas
* topology construction
* workflow graph construction
* asset placement
* observability requirement expansion
* mutation envelope calculation

### 8.2 WorldSynthesizer

This is the only LLM-heavy stage.

It generates bounded artifacts:

* internal docs
* seeded emails
* tickets
* helpdesk history
* business app content
* small app modules
* fileshare contents
* persona data

It does **not** generate arbitrary cluster infra or arbitrary base images.

### 8.3 WeaknessSeeder

Deterministic weakness insertion from a catalog.

V1 families:

* `auth_misconfig`
* `workflow_abuse`
* `secret_exposure`
* `input_validation`
* `telemetry_blindspot`

Each weakness entry must ship with:

* preconditions
* expected event signatures
* at least one red witness template
* expected blue observability surfaces
* patch/remediation metadata

### 8.4 KindRenderer

Renders the admitted world into live artifacts:

* namespaces per zone
* NetworkPolicies
* Deployments / StatefulSets
* seed ConfigMaps / Secrets
* init jobs for DB/mail/file seeds
* log shipping
* sandbox pods for red and blue

### 8.5 Optional Sim Plane

The same `WorldIR` can also feed a lightweight simulation runtime that:

* parses canonical tool calls,
* emits deterministic outputs,
* emits state-change events,
* generates cheap bootstrap trajectories.

This is useful, but not required for the core live-loop claim. Worlds is the inspiration for this layer, especially the “tool call -> deterministic output + events” pattern. ([Dreadnode][3])

---

## 9. Admission controller

This is the center of gravity.

A world is trainable only if `AdmissionController` produces:

* `admitted = true`
* `Snapshot`
* `WitnessBundle`
* `ValidatorReport`

### 9.1 Public/private split

**Public**

* `ValidatorReport`
* build logs
* health info

**Private**

* `WitnessBundle`
* witness traces
* shortcut probes
* determinism probes
* necessity probes

### 9.2 Checks to keep from current code

Keep and adapt:

* `ManifestComplianceCheck`
* `GraphConsistencyCheck`
* `PathSolvabilityCheck`
* `BuildBootCheck`
* `IsolationCheck`
* `DifficultyCheck`
* `PatchabilityCheck`

### 9.3 Checks to rename or replace

Replace:

* public `golden_path` execution → **private red witness checks**
* reward grounding by literal flags → **objective grounding**
* evidence sufficiency as a hard research claim → **optional debug/advisory**
* exploitability string matching → **predicate/event validation**

### 9.4 Required admission stages

#### A. Static checks

* manifest compliance
* graph consistency
* path solvability
* objective grounding
* topology/workflow consistency

#### B. Live checks

* service health
* login/workflow smoke tests
* SIEM ingest
* isolation
* difficulty envelope

#### C. Red witness checks

Run at least one hidden red witness end-to-end.

#### D. Blue witness checks

Run at least one hidden blue witness end-to-end.

#### E. Necessity checks

Cyber analogue of SSR’s inverse-mutation idea:

* remove a claimed weakness; red witness must fail
* remove a claimed observability point; blue witness must degrade
* apply a remediation; at least one red path must break

SSR’s inverse mutation testing and consistency validation are the right inspiration here. ([arXiv][2])

#### F. Shortcut probes

Attempt:

* direct external crown-jewel access
* direct admin access
* unintended cross-zone reachability
* leaked secrets
* unlogged critical actions

#### G. Determinism checks

Replay the same witness against the same snapshot and compare:

* emitted event sequence
* terminal predicates
* service health
* final state hash

### 9.5 Fail-fast vs analysis mode

Keep fail-fast for build/admission loops.

Add a separate **analysis mode** that runs all checks and returns a full report for debugging and paper analysis.

---

## 10. WitnessBundle

The private oracle created after admission.

```python
WitnessBundle(
    red_witnesses,
    blue_witnesses,
    smoke_tests,
    shortcut_probes,
    determinism_probes,
    necessity_probes
)
```

### Red witness

A hidden trace proving at least one real attack path exists.

### Blue witness

A hidden trace proving at least one real detect/contain path exists.

### Why private?

Because the environment should validate against a hidden formal artifact, not leak one public canonical exploit script. That is the main lesson imported from SSR. ([arXiv][2])

---

## 11. Snapshots

All training runs on immutable admitted snapshots.

A snapshot contains:

* pinned image digests
* rendered manifests / chart values
* DB seed state
* mail state
* file assets
* identity seed
* validator outputs
* witness bundle
* world hash
* parent lineage

`reset(snapshot_id)` restores exactly that admitted world.

No mutation happens during an episode.

---

## 12. Runtime model

## 12.1 Same episode, separate actor sessions

Red and blue act in the **same episode** on the **same world**, but they are **not** the same live agent.

Each episode creates:

* `red_session`
* `blue_session`
* `green_scheduler`

Red and blue may share the same base checkpoint, but they must have:

* separate prompt context
* separate tool history
* separate scratchpad
* separate memory / KV cache
* separate role identity

So: **same weights is fine, same memory is not.**

## 12.2 Tick and phase semantics

The current environment is a shared state machine driven by the caller. V1 should make turn order explicit.

Each tick contains three phases:

1. **Green phase**
2. **Red phase**
3. **Blue phase**

Then `tick += 1`.

### Tick order

1. green emits due routine actions
2. world applies green actions
3. red observes and acts
4. world applies red effects, emits events/logs
5. blue observes and acts
6. world applies blue mitigations/recovery
7. rewards update
8. terminal conditions checked

This gives:

* shared world state
* separate minds
* deterministic replay
* meaningful blue reaction timing

## 12.3 Actor-specific observations

The environment must expose:

* `observe("red")`
* `observe("blue")`

Blue should never act on “the observation returned from red’s action.”
Blue gets its **own** observation after red effects and log/alert visibility update.

---

## 13. Green / NPC design

Green is an environment process, not a trainable policy in V1.

CAGE 4 is the main inspiration for making green first-class: its enterprise green agent represents normal users and blue reward is heavily tied to how blue’s actions affect green while red is present. ([Cage Challenge][4])

### 13.1 Keep from current code

Keep:

* `npc_personas` as snapshot state
* `npc_traffic` / workload config as snapshot state
* persona fields like role, department, awareness, susceptibility, routine, accounts
* proactive vs reactive distinction
* manager/executor split

### 13.2 Change from current code

Change:

* routine work should be mostly scripted, not LLM-chosen every loop
* branch LLM only triggers on stimuli
* green actions must originate from the correct host/workstation/mailbox, not a hardcoded SIEM pod
* all credentials must come from seeded world state, not hardcoded scripts
* event types must be typed, not ad hoc strings
* the current wiring gap must be fixed so live traffic actually starts on reset

### 13.3 Green architecture

#### G0: Scripted scheduler

Routine work:

* logins/logouts
* email send/receive
* file access
* app browsing
* ticket operations
* cron / service jobs

#### G1: Branch policy

Only at decision points:

* open / ignore / report suspicious email
* approve / reject workflow
* escalate to IT
* reset password
* share / refuse information

### 13.4 Why green matters

For red:

* creates workflow/social entry paths
* creates credential and approval abuse opportunities

For blue:

* creates noise
* creates false-positive risk
* creates continuity pressure

---

## 14. Event model

Blue should reason over **typed events**, not over one public attack script.

### Core event classes

* `InitialAccess`
* `CredentialObtained`
* `UnauthorizedCredentialUse`
* `PrivilegeEscalation`
* `CrossZoneTraversal`
* `SensitiveAssetRead`
* `PersistenceEstablished`
* `DetectionAlertRaised`
* `ContainmentApplied`
* `RecoveryCompleted`
* `ServiceDegraded`
* `BenignUserAction`

### Event fields

* actor
* time/tick
* source entity
* target entity
* malicious / benign
* observability surfaces
* linked objective predicates

This event bus is the bridge between:

* runtime
* validator
* blue findings
* reward grounding

---

## 15. Actions and observations

### Action model

```python
Action(
    actor_id,
    role,         # red | blue | green
    kind,         # shell | api | mail | control | submit_finding | sleep
    payload,
    timeout_s
)
```

### Observation model

```python
Observation(
    actor_id,
    tick,
    stdout="",
    stderr="",
    visible_events=(),
    alerts_delta=(),
    inbox_delta=(),
    service_health=(),
    reward_delta=0.0,
    done=False
)
```

### Notes

* `submit_flag` should not be a central mechanic in V1.
* `submit_evidence` should not drive RL reward.
* `submit_finding` stays, but becomes structured and validator-grounded.

---

## 16. Rewards

The current reward system is too heuristic-heavy. V1 should move to **terminal-first, event-grounded** rewards.

SSR’s solver reward is a good design anchor: simple, binary, verifiable. OpenRange should follow that spirit even though the domain differs. ([arXiv][2])

## 16.1 Red reward

### Primary terminal reward

* `+1` if red terminal objectives are satisfied
* `-1` otherwise

### Small shaping

* milestone predicates, paid once:

  * `InitialAccess`
  * `CredentialObtained`
  * `CrossZoneTraversal`
  * `SensitiveAssetRead`
* small tick cost
* hallucination penalty for false submissions

### Drop from current design

* evidence-as-reward
* standalone “social” bonus
* tier multipliers
* action-count stealth proxy

## 16.2 Blue reward

### Primary terminal reward

* `+1` if blue detects and contains before red terminal compromise **and** continuity stays above threshold
* `-1` otherwise

### Small shaping

* first valid detection of important malicious events
* first validated containment that breaks a remaining red path
* false-positive penalties
* continuity loss penalties

### Drop from current design

* patch reward based on command name
* availability reward if not grounded in real health state
* phishing as a separate top-level reward term

## 16.3 Stealth

Stealth should **not** be “1 - detected_actions / total_actions”.

If used explicitly at all, it should be based on **event detection latency**:

* `t_emit(e)` = when malicious event occurs
* `t_detect(e)` = when blue first makes a valid finding or validated containment tied to it

Then stealth is the delay between them.

For V1, the cleanest choice is:

* do **not** make stealth a large standalone reward
* let it matter indirectly through blue detection timing and red success

---

## 17. Terminal conditions

Episodes end when any of these happen:

1. **Red win**
   All required red terminal predicates are satisfied.

2. **Blue win**
   Blue detects and contains before red terminal compromise, with continuity above threshold.

3. **Timeout**
   `tick >= max_ticks`

4. **Environment failure**
   Snapshot/runtime invalidates.

Important:

* detection alone does **not** end the episode
* `done=True` must be enforced by the environment, not just advisory

---

## 18. What to keep / change / drop from current code

## Keep

* builder → validator → runtime → training split
* persona and traffic snapshot objects
* proactive vs reactive green structure
* live patchability logic as a seed for blue containment grounding
* fail-fast admission for production loops
* per-step reward API shape
* hallucination penalty
* false-positive penalty

## Change

* replace public `golden_path` with private `WitnessBundle`
* make `observe(actor)` actor-specific
* enforce turn order in the environment or a tandem driver
* replace global flat steps with `tick + phase`
* give blue a real terminal win condition
* ground patch reward in actual path breakage
* ground detection reward in structured findings on real events
* make green routine behavior mostly scripted
* fix NPC live-runtime wiring
* remove hardcoded green credential usage
* originate green traffic from proper user context, not SIEM

## Drop

* public answer-key semantics
* evidence-as-reward
* social bonus as a separate reward term
* tier-scaled rewards
* command-name-based patch reward
* advisory LLM realism checks as a hard gate
* shared red/blue memory

---

## 19. External interface

A thin Python-first API is enough.

### Build / admission

* `build(manifest) -> CandidateWorld`
* `admit(candidate) -> Snapshot`

### Runtime

* `reset(snapshot_id, seed) -> EpisodeHandle`
* `observe(actor) -> Observation`
* `act(actor, action) -> ActionResult`
* `state() -> EpisodeState`
* `score() -> EpisodeScore`
* `close()`

### Curriculum

* `propose_mutations(population_stats) -> list[WorldIR]`
* `admit_child(world_ir) -> Snapshot`

---

## 20. Core internal interfaces

```python
class ManifestCompiler(Protocol):
    def compile(self, manifest: dict) -> WorldIR: ...

class WorldSynthesizer(Protocol):
    def synthesize(self, world: WorldIR, outdir: Path) -> SynthArtifacts: ...

class WeaknessSeeder(Protocol):
    def apply(self, world: WorldIR, seed: int) -> WorldIR: ...

class KindRenderer(Protocol):
    def render(self, world: WorldIR, synth: SynthArtifacts, outdir: Path) -> KindArtifacts: ...

class AdmissionController(Protocol):
    def admit(self, world: WorldIR, artifacts: KindArtifacts) -> tuple[WitnessBundle, ValidatorReport]: ...

class SnapshotStore(Protocol):
    def create(self, world: WorldIR, artifacts: KindArtifacts, wb: WitnessBundle, vr: ValidatorReport) -> Snapshot: ...
    def load(self, snapshot_id: str) -> Snapshot: ...

class GreenScheduler(Protocol):
    def reset(self, snapshot: Snapshot, seed: int) -> None: ...
    def due_actions(self, tick: int) -> tuple[Action, ...]: ...

class RangeRuntime(Protocol):
    def reset(self, snapshot: Snapshot, episode_seed: int) -> EpisodeState: ...
    def observe(self, actor: str) -> Observation: ...
    def act(self, actor: str, action: Action) -> ActionResult: ...
    def score(self) -> EpisodeScore: ...
    def close(self) -> None: ...

class MutationPolicy(Protocol):
    def choose_parent(self, population: list[PopulationStats]) -> str: ...
    def mutate(self, parent: WorldIR) -> WorldIR: ...
```

---

## 21. Training loop

## 21.1 High-level training plan

### Stage A: Build an initial admitted pool

1. Write manifests
2. Compile to `WorldIR`
3. Synthesize and seed
4. Render to Kind
5. Admit
6. Store admitted snapshots

### Stage B: Offline bootstrap

Use:

* witness-derived traces
* optional sim-plane traces
* green interaction traces
* red/blue structured action data

This gives you initial SFT / preference / behavior-cloning material.

### Stage C: Online red/blue training

Run self-play or alternating-policy training on live snapshots.

### Stage D: Curriculum expansion

Use population stats to mutate worlds, re-admit, and grow the pool.

## 21.2 Explicit episode loop

```python
for epoch in range(num_epochs):
    snapshot = snapshot_pool.sample()

    env.reset(snapshot_id=snapshot.snapshot_id, seed=epoch)

    red_session = red_policy.new_session(role="red")
    blue_session = blue_policy.new_session(role="blue")

    while not env.state().done:
        # Green phase
        for a in env.green_scheduler.due_actions(env.state().tick):
            env.act("green", a)

        # Red phase
        red_obs = env.observe("red")
        red_action = red_session.act(red_obs)
        env.act("red", red_action)

        if env.state().done:
            break

        # Blue phase
        blue_obs = env.observe("blue")
        blue_action = blue_session.act(blue_obs)
        env.act("blue", blue_action)

    episode = env.score()
    replay_buffer_red.add(env.export_trace("red"))
    replay_buffer_blue.add(env.export_trace("blue"))

    red_policy.update(replay_buffer_red)
    blue_policy.update(replay_buffer_blue)

    if epoch % mutation_interval == 0:
        stats = evaluate_population(snapshot_pool, red_policy, blue_policy)
        children = mutation_policy.propose(stats)
        for child_world in children:
            candidate = build(child_world)
            admitted = admit(candidate)
            if admitted.ok:
                snapshot_pool.add(admitted.snapshot)
```

## 21.3 Important training semantics

* red and blue are in the **same episode**
* they are **different sessions**
* they may share base weights, but not memory
* builder is **not** updated by RL in V1
* mutation policy may be heuristic/frontier-based in V1

---

## 22. Mutation policy

Mutation only occurs between admitted snapshots.

### Allowed V1 mutations

* add host
* add service
* add user
* add workflow branch
* add trust edge
* add noise source
* seed weakness
* harden one path / expose another
* alter observability in bounded ways

### Parent choice

Prefer worlds that are:

* stable
* low flake
* novel
* near the red/blue frontier
* rich in blue signal
* not trivial
* not impossible

Builder itself is not trained. The mutation policy is the evolving curriculum mechanism in V1.

---

## 23. Implementation plan

## Phase 1 — freeze schemas

Deliver:

* `manifest.schema.json`
* `world_ir.py`
* `validator_report.schema.json`
* `witness_bundle.schema.json`

## Phase 2 — fixed world family

Deliver:

* `ManifestCompiler`
* `WorldIR`
* one hand-checkable `enterprise_saas_v1`

## Phase 3 — live rendering and admission

Deliver:

* `KindRenderer`
* service boot
* isolation
* smoke tests
* witness bundle generation
* deterministic admission

## Phase 4 — runtime rewrite

Deliver:

* `tick + phase` runtime
* actor-specific `observe()`
* enforced turn order
* hard `done`
* blue terminal condition

## Phase 5 — green rewrite

Deliver:

* scripted scheduler
* branch-policy hook
* correct user-origin traffic
* typed event emission
* fixed runtime wiring

## Phase 6 — reward cleanup

Deliver:

* objective/predicate-based terminal reward
* structured finding validation
* path-breakage-based containment reward
* remove evidence/social/tier reward hacks

## Phase 7 — curriculum

Deliver:

* mutation ops
* parent selection
* admitted child generation
* held-out evaluation pool

## Optional Phase 8 — sim bootstrap

Deliver:

* minimal tool/event sim plane
* cheap trace generation from `WorldIR`

---

## 24. Success criteria for V1

V1 succeeds if:

1. admitted worlds are reproducible and low-flake
2. red and blue run in the same episode with isolated memory
3. green traffic materially changes blue difficulty
4. blue can win by detect+contain, not just score shaping
5. patch/contain rewards are grounded in actual path breakage
6. agents trained here transfer better to held-out admitted worlds than static-world baselines
7. the paper can clearly show:

   * static vs mutable
   * no green vs green
   * weak validator vs full validator
   * live-only vs bootstrap+live, if sim is included

---

## 25. Final V1 position

**OpenRange V1 is a standalone, Kind-backed, red/blue/green enterprise cyber training system whose public manifest defines a business, whose hidden witness bundle defines the validator oracle, whose runtime enforces separate red and blue minds in the same shared episode, and whose admitted immutable snapshots evolve through typed mutations rather than public golden paths or LLM judgment.**

The next best artifact to write is `manifest.schema.json`, followed by `WitnessBundle` and the rewritten `RangeRuntime` API.

[1]: https://cybench.github.io/ "Cybench"
[2]: https://arxiv.org/pdf/2512.18552 "Toward Training Superintelligent Software Agents through Self-Play SWE-RL"
[3]: https://dreadnode.io/blog/worlds-a-simulation-engine-for-agentic-pentesting "Worlds: A Simulation Engine for Agentic Pentesting"
[4]: https://cage-challenge.github.io/cage-challenge-4/pages/tutorials/02_Looking_Around/2_Agents/ "Agents - CAGE Challenge 4"
