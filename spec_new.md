## OpenRange V1 Design Doc

### 1. One-line definition

**OpenRange V1 is a mutable enterprise cyber training system that builds a business from a manifest, validates it with private deterministic witnesses, runs episodes on immutable live snapshots, and trains red and blue agents against realistic green-user dynamics and operational constraints.**

---

### 2. Why this exists

Existing cyber-agent artifacts are strong at **evaluation**, **simulation**, or **human-oriented range exercises**, but they do not directly give you an open training system with all of the following at once:

* real services
* realistic blue observability
* normal user activity
* red/blue interaction
* business continuity constraints
* mutable worlds that evolve with the agents

OpenRange combines ideas from:

* **SSR**: hidden oracle, deterministic admission, necessity checks, simple verifiable reward
* **Worlds**: manifest-first world modeling, event semantics, optional cheap synthetic traces
* **enterprise defense simulators**: green users matter because blue realism requires noise, ambiguity, and continuity pressure
* **Kind**: a clean, reproducible live backend

The contribution is **not** Kubernetes itself. The contribution is a **validator-admitted, mutable, enterprise red/blue training environment**.

---

### 3. V1 scope

#### In scope

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
* green dynamics inside the same episode
* typed mutations between generations
* optional lightweight sim plane for bootstrap traces

#### Out of scope

* arbitrary company generation
* arbitrary internet access
* public answer keys
* LLM judge for reward or admission
* free-form LLM-authored infra
* mutation during an episode
* shared red/blue memory
* evidence-as-reward
* command-name-based patch reward
* trainer-stepped green actions in V1

---

### 4. Core invariants

These are the parts of the system that are **not** ablated in normal V1 use:

* **Manifest defines the business, not the answer key**
* **WorldIR is canonical**
* **Admission is required before training**
* **Snapshots are immutable**
* **Red and blue are separate sessions with separate memory**
* **Green is environment-owned at runtime**
* **Main reward is terminal and validator-grounded**
* **Builder is not RL-trained in V1**
* **Kind is the reference backend, not the research claim**

---

### 5. Feature control contract

Every non-core feature must be empirically controllable from one of two places:

#### A. `BuildConfig`

Controls world construction and admission.

Use it for:

* enabled services and workflows
* enabled weakness families
* observability surfaces
* phishing surface
* green artifacts existing or not
* topology scale
* validation strength
* witness counts

#### B. `EpisodeConfig`

Controls runtime behavior for one admitted snapshot.

Use it for:

* training mode
* runtime scheduler mode
* green on/off
* green routine/branch behavior
* green workload profile
* telemetry delay
* continuity enforcement
* reward shaping on/off
* opponent controller
* prefix start state
* episode horizon

**If a realism feature cannot be toggled or parameterized through `BuildConfig` or `EpisodeConfig`, it is not a V1 feature.**

---

### 6. System overview

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

### 7. Public manifest

The manifest is the public, human-authored declaration of the business.

It defines:

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

It does **not** define:

* exploit commands
* expected stdout
* public flag paths
* a public canonical golden path

The manifest is the **world contract**, not the **oracle**.

---

### 8. WorldIR

`WorldIR` is the typed internal business graph.

It contains:

* zones
* hosts
* services
* users and groups
* credentials
* assets
* workflows
* network edges
* trust edges
* data edges
* telemetry edges
* weaknesses
* red objectives
* blue objectives
* green personas
* green workload spec
* lineage

Everything downstream uses `WorldIR` as the source of truth.

Minimal core objects:

* `WorldIR`
* `HostSpec`
* `ServiceSpec`
* `UserSpec`
* `CredentialSpec`
* `AssetSpec`
* `WorkflowSpec`
* `EdgeSpec`
* `WeaknessSpec`
* `ObjectiveSpec`
* `GreenPersona`
* `GreenWorkloadSpec`

---

### 9. Build pipeline

#### 9.1 ManifestCompiler

Validates the manifest and expands it into `WorldIR`.

Responsibilities:

* schema validation
* role expansion into users/personas
* topology construction
* workflow graph construction
* asset placement
* observability expansion
* mutation envelope calculation

#### 9.2 WorldSynthesizer

The only LLM-heavy stage.

Generates bounded artifacts:

* internal docs
* seeded emails
* tickets
* helpdesk history
* business app content
* small app modules
* fileshare contents
* persona data

It does not generate arbitrary infra or base images.

#### 9.3 WeaknessSeeder

Deterministically inserts weaknesses from a catalog.

V1 families:

* auth misconfiguration
* workflow abuse
* secret exposure
* input validation
* telemetry blind spot

Each weakness ships with:

* preconditions
* expected event signatures
* at least one red witness template
* expected blue observability surfaces
* remediation metadata

#### 9.4 KindRenderer

Renders the world into live artifacts:

* namespaces per zone
* NetworkPolicies
* workloads
* seed jobs / ConfigMaps / Secrets
* log shipping
* red sandbox
* blue sandbox

#### 9.5 Optional Sim Plane

The same `WorldIR` may also feed a lightweight sim plane that:

* parses canonical tool calls
* emits deterministic outputs
* emits state-change events
* generates cheap bootstrap traces

This is optional in V1.

---

### 10. Admission controller

The validator is the center of gravity.

A world is trainable only if `AdmissionController` produces:

* `admitted = true`
* `Snapshot`
* `WitnessBundle`
* `ValidatorReport`

#### 10.1 Public/private split

Public:

* `ValidatorReport`
* build logs
* health info

Private:

* `WitnessBundle`
* witness traces
* shortcut probes
* determinism probes
* necessity probes

#### 10.2 What stays from current validator

Keep and adapt:

* manifest compliance
* graph consistency
* path solvability
* build boot
* isolation
* difficulty
* patchability

#### 10.3 What changes

Replace:

* public golden-path execution → private witness checks
* literal flag grounding → objective grounding
* evidence sufficiency as a core claim → optional debug/advisory
* stdout substring exploit checks → predicate/event validation

#### 10.4 Required admission stages

**Static checks**

* manifest compliance
* graph consistency
* path solvability
* objective grounding
* topology/workflow consistency

**Live checks**

* service health
* login/workflow smoke tests
* SIEM ingest
* isolation
* difficulty envelope

**Red witness checks**

* run at least one hidden red witness end-to-end

**Blue witness checks**

* run at least one hidden blue witness end-to-end

**Necessity checks**

* remove a claimed weakness; red witness must fail
* remove a claimed observability point; blue witness must degrade
* apply a remediation; at least one red path must break

**Shortcut probes**

* direct external crown-jewel access
* direct admin access
* unintended cross-zone reachability
* leaked secrets
* unlogged critical actions

**Determinism checks**

* replay the same witness against the same snapshot
* compare event sequence, predicates, service health, and final state hash

#### 10.5 Fail-fast vs analysis mode

* **Fail-fast** for build/admission loops
* **Analysis mode** for full debug/paper reports

---

### 11. WitnessBundle

`WitnessBundle` is the private oracle created after admission.

It contains:

* `red_witnesses`
* `blue_witnesses`
* `smoke_tests`
* `shortcut_probes`
* `determinism_probes`
* `necessity_probes`

A witness may internally be “golden-path-like,” but it is:

* validator-owned
* private
* not necessarily unique
* not the public environment contract

---

### 12. Snapshots

All training runs on immutable admitted snapshots.

A snapshot contains:

* pinned image digests
* rendered manifests/config
* DB/mail/file/identity seed state
* validator outputs
* witness bundle
* world hash
* parent lineage

`reset(snapshot_id)` restores exactly that admitted world.

No mutation happens during an episode.

---

### 13. Runtime model

#### 13.1 Same episode, separate actor sessions

Red and blue act in the same episode on the same world, but they are separate live sessions.

Each episode creates:

* `red_session`
* `blue_session`
* `green_scheduler`

Red and blue may share a base checkpoint, but must have:

* separate prompt context
* separate tool history
* separate scratchpad
* separate memory / KV cache
* separate role identity

Same weights is fine. Same memory is not.

#### 13.2 Final runtime choice: async simulated time

V1 uses an **asynchronous, event-driven, simulated-time runtime**, not strict red/blue turns every step.

The env advances through:

* green routine activity
* delayed reactions
* telemetry arrival
* polling intervals
* alert generation
* service changes
* red decisions
* blue decisions

This better fits:

* dwell time
* delayed detection
* periodic blue response
* workflow compromise
* spearphishing-style incidents

#### 13.3 External decision API

The trainer only controls externally exposed roles.

```python
env.reset(snapshot_id, episode_config)

while not env.done():
    decision = env.next_decision()
    action = policy[decision.actor].act(decision.obs)
    env.act(decision.actor, action)
```

If green is internal, `next_decision()` does not expose green by default.
The env advances green internally until the next external decision point.

#### 13.4 Actor-specific observations

The environment must expose actor-specific observations.

Blue never acts on “the observation returned from red’s action.”
Blue acts on its own observation after red effects and telemetry have landed.

---

### 14. Green / NPC design

Green is an environment process, not a trainer-stepped policy in V1.

#### 14.1 What stays from current code

Keep:

* `npc_personas` as snapshot state
* workload config as snapshot state
* persona fields like role, department, awareness, susceptibility, routine, accounts
* proactive vs reactive distinction
* manager/executor split

#### 14.2 What changes

Change:

* routine work is mostly scripted, not LLM-chosen every loop
* branch policy triggers only on stimuli
* green actions must originate from the correct workstation/mailbox/account
* all credentials come from seeded world state
* event types are typed, not ad hoc strings
* the live green runtime wiring must actually work on reset

#### 14.3 Green architecture

**G0: scripted scheduler**

* login/logout
* email send/receive
* file access
* app browsing
* ticket operations
* cron / service jobs

**G1: branch policy**
Only at decision points:

* open / ignore / report suspicious email
* approve / reject workflow
* escalate to IT
* reset password
* share / refuse information

Possible branch backends:

* scripted
* small LLM
* optional workflow orchestrator

#### 14.4 Green control boundary

Green is **environment-owned at runtime** but **loop-tunable at reset/curriculum time**.

Trainer may control:

* green enabled/disabled
* routine on/off
* branch on/off
* noise level
* susceptibility band
* reporting band
* workday profile
* branch backend

Trainer does **not** call `env.act("green", ...)` in V1.

---

### 15. Event model

Blue reasons over typed events, not over one public attack script.

Core event classes:

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

Event fields:

* actor
* time
* source entity
* target entity
* malicious / benign
* observability surfaces
* linked objective predicates

The event bus bridges:

* runtime
* validator
* blue findings
* reward grounding

---

### 16. Actions and observations

#### Action model

```python
Action(
    actor_id,
    role,         # red | blue
    kind,         # shell | api | mail | control | submit_finding | sleep
    payload,
    timeout_s
)
```

Green actions exist internally, but are not trainer-stepped in V1.

#### Observation model

```python
Observation(
    actor_id,
    sim_time,
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

Notes:

* `submit_flag` is not a central V1 mechanic
* `submit_evidence` does not drive RL reward
* `submit_finding` stays, but is structured and validator-grounded

---

### 17. Rewards

V1 uses terminal-first, event-grounded rewards.

#### 17.1 Red reward

Primary terminal reward:

* `+1` if red terminal objectives are satisfied
* `-1` otherwise

Small shaping:

* milestone predicates, paid once
* small time cost
* hallucination penalty for false submissions

Drop:

* evidence-as-reward
* standalone social bonus
* tier multipliers
* action-count stealth proxy

#### 17.2 Blue reward

Primary terminal reward:

* `+1` if blue detects and contains before red terminal compromise and continuity stays above threshold
* `-1` otherwise

Small shaping:

* first valid detection of important malicious events
* first validated containment that breaks a remaining red path
* false-positive penalties
* continuity-loss penalties

Drop:

* patch reward based on command name
* availability reward if not grounded in real health state
* phishing as a separate top-level reward term

#### 17.3 Stealth

If explicit at all, stealth is based on event detection latency:

* `t_emit(e)` = when the malicious event happens
* `t_detect(e)` = when blue first validly detects it

In V1, stealth should mostly remain implicit through red success and blue detection timing.

---

### 18. Terminal conditions

Episodes end when any of these happen:

**Red win**

* all required red terminal predicates are satisfied

**Blue win**

* blue detects and contains before red terminal compromise, with acceptable continuity

**Timeout**

* simulated time horizon reached

**Environment failure**

* snapshot/runtime invalidates

Important:

* detection alone does not end the episode
* `done=True` is enforced by the environment, not advisory

---

### 19. Training modes

Do not train fully joint from scratch all the time.

Use four modes.

#### `red_only`

Externally controlled:

* red

Internally controlled:

* blue
* green

#### `blue_only_live`

Externally controlled:

* blue

Internally controlled:

* red
* green

#### `blue_only_from_prefix`

Externally controlled:

* blue

Internally controlled:

* green

Starts from a compromised prefix snapshot:

* post-delivery
* post-click
* post-credential theft
* post-foothold
* during lateral movement

#### `joint_pool`

Externally controlled:

* red
* blue

Internally controlled:

* green

Opponents are sampled from frozen pools.
Builder is not RL-trained in V1.

---

### 20. External interface

A thin Python-first API is enough.

#### Build / admission

* `build(manifest, build_config) -> CandidateWorld`
* `admit(candidate) -> Snapshot`

#### Runtime

* `reset(snapshot_id, episode_config) -> EpisodeHandle`
* `next_decision() -> Decision`
* `act(actor, action) -> ActionResult`
* `state() -> EpisodeState`
* `score() -> EpisodeScore`
* `close()`

#### Curriculum

* `propose_mutations(population_stats) -> list[WorldIR]`
* `admit_child(world_ir, build_config) -> Snapshot`

---

### 21. Core internal interfaces

```python
class ManifestCompiler(Protocol):
    def compile(self, manifest: dict, build_config: BuildConfig) -> WorldIR: ...

class WorldSynthesizer(Protocol):
    def synthesize(self, world: WorldIR, outdir: Path) -> SynthArtifacts: ...

class WeaknessSeeder(Protocol):
    def apply(self, world: WorldIR, seed: int) -> WorldIR: ...

class KindRenderer(Protocol):
    def render(self, world: WorldIR, synth: SynthArtifacts, outdir: Path) -> KindArtifacts: ...

class AdmissionController(Protocol):
    def admit(self, world: WorldIR, artifacts: KindArtifacts, build_config: BuildConfig) -> tuple[WitnessBundle, ValidatorReport]: ...

class SnapshotStore(Protocol):
    def create(self, world: WorldIR, artifacts: KindArtifacts, wb: WitnessBundle, vr: ValidatorReport) -> Snapshot: ...
    def load(self, snapshot_id: str) -> Snapshot: ...

class GreenScheduler(Protocol):
    def reset(self, snapshot: Snapshot, episode_config: EpisodeConfig) -> None: ...
    def advance_until(self, sim_time: float) -> None: ...

class RangeRuntime(Protocol):
    def reset(self, snapshot: Snapshot, episode_config: EpisodeConfig) -> EpisodeState: ...
    def next_decision(self) -> Decision: ...
    def act(self, actor: str, action: Action) -> ActionResult: ...
    def score(self) -> EpisodeScore: ...
    def close(self) -> None: ...

class MutationPolicy(Protocol):
    def choose_parent(self, population: list[PopulationStats]) -> str: ...
    def mutate(self, parent: WorldIR) -> WorldIR: ...
```

---

### 22. Training loop

#### 22.1 High-level plan

**Stage A: Build initial admitted pool**

* write manifests
* compile to `WorldIR`
* synthesize and seed
* render to Kind
* admit
* store admitted snapshots

**Stage B: Offline bootstrap**
Use:

* witness-derived traces
* optional sim-plane traces
* structured red/blue action data

**Stage C: Online training**
Use:

* `red_only`
* `blue_only_live`
* `blue_only_from_prefix`
* later `joint_pool`

**Stage D: Curriculum expansion**

* collect population stats
* mutate worlds
* re-admit children
* expand the snapshot pool

#### 22.2 Explicit episode loop

```python
for epoch in range(num_epochs):
    snapshot = snapshot_pool.sample()

    env.reset(
        snapshot_id=snapshot.snapshot_id,
        episode_config=sample_episode_config()
    )

    sessions = {}
    if env.state().controls_red:
        sessions["red"] = red_policy.new_session(role="red")
    if env.state().controls_blue:
        sessions["blue"] = blue_policy.new_session(role="blue")

    while not env.state().done:
        decision = env.next_decision()   # returns only externally controlled actors
        action = sessions[decision.actor].act(decision.obs)
        env.act(decision.actor, action)

    if env.state().controls_red:
        replay_buffer_red.add(env.export_trace("red"))
        red_policy.update(replay_buffer_red)

    if env.state().controls_blue:
        replay_buffer_blue.add(env.export_trace("blue"))
        blue_policy.update(replay_buffer_blue)

    if epoch % mutation_interval == 0:
        stats = evaluate_population(snapshot_pool, red_policy, blue_policy)
        children = mutation_policy.propose(stats)
        for child_world in children:
            candidate = build(child_world, sample_build_config())
            admitted = admit(candidate)
            if admitted.ok:
                snapshot_pool.add(admitted.snapshot)
```

#### 22.3 Training semantics

* red and blue may be in the same episode
* they are always separate sessions
* green is internal
* builder is not updated by RL in V1
* mutation happens only between admitted worlds

---

### 23. Mutation policy

Mutation only occurs between admitted snapshots.

Allowed V1 mutations:

* add host
* add service
* add user
* add workflow branch
* add trust edge
* add noise source
* seed weakness
* harden one path / expose another
* alter observability in bounded ways

Parent choice should prefer worlds that are:

* stable
* low-flake
* novel
* near the red/blue frontier
* rich in blue signal
* not trivial
* not impossible

Builder itself is not trained. Mutation is the curriculum mechanism.

---

### 24. BuildConfig and EpisodeConfig

#### 24.1 BuildConfig

Used for empirical world/admission ablations.

Typical fields:

* `services_enabled`
* `workflows_enabled`
* `weakness_families_enabled`
* `observability_surfaces_enabled`
* `phishing_surface_enabled`
* `green_artifacts_enabled`
* `topology_scale`
* `validation_profile`
* `red_witness_count`
* `blue_witness_count`

#### 24.2 EpisodeConfig

Used for empirical runtime/training ablations.

Typical fields:

* `mode`
* `scheduler_mode` (`async` or strict-turn ablation)
* `green_enabled`
* `green_routine_enabled`
* `green_branch_enabled`
* `green_profile`
* `green_branch_backend`
* `telemetry_delay_enabled`
* `continuity_enforced`
* `reward_profile`
* shaping on/off flags
* `opponent_red`
* `opponent_blue`
* `start_state`
* `episode_horizon`

This is how every realism component becomes empirically testable.

---

### 25. Implementation plan

**Phase 1 — freeze schemas**

* `manifest.schema.json`
* `world_ir.py`
* `validator_report.schema.json`
* `witness_bundle.schema.json`
* `build_config.py`
* `episode_config.py`

**Phase 2 — fixed world family**

* `ManifestCompiler`
* `WorldIR`
* one hand-checkable `enterprise_saas_v1`

**Phase 3 — live rendering and admission**

* `KindRenderer`
* service boot
* isolation
* smoke tests
* witness bundle generation
* deterministic admission

**Phase 4 — runtime rewrite**

* async runtime
* actor-specific observations
* `next_decision()`
* hard `done`
* blue terminal condition

**Phase 5 — green rewrite**

* scripted scheduler
* branch-policy hook
* correct user-origin traffic
* typed event emission
* working runtime wiring

**Phase 6 — reward cleanup**

* objective/predicate-based terminal reward
* structured finding validation
* path-breakage-based containment reward
* remove evidence/social/tier reward hacks

**Phase 7 — curriculum**

* mutation ops
* parent selection
* admitted child generation
* held-out evaluation pool

**Optional Phase 8 — sim bootstrap**

* minimal sim plane
* cheap trace generation from `WorldIR`

---

### 26. Success criteria

V1 succeeds if:

* admitted worlds are reproducible and low-flake
* red and blue run with isolated memory
* green materially changes blue difficulty
* blue can win by detect+contain, not just shaping
* patch/contain rewards are grounded in actual path breakage
* every realism feature can be ablated through `BuildConfig` or `EpisodeConfig`
* agents trained here transfer better to held-out admitted worlds than static-world baselines

Minimal paper ablations:

* static vs mutable
* no green vs green
* weak validator vs full validator
* live-only vs bootstrap+live, if sim is included
* async vs strict-turn baseline
* clean start vs prefix-start blue training

---

### 27. Final V1 position

**OpenRange V1 is a standalone, Kind-backed, validator-admitted enterprise cyber training system whose public manifest defines a business, whose hidden witness bundle defines the private oracle, whose green users are environment-owned but trainer-tunable, and whose immutable snapshots support red-only, blue-only, prefix-start, and joint-pool training without public golden paths or LLM judgment.**
