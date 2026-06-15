# Contribution [#]: Multimodal social engineering surface

Contribution Number: 1
Student: Saibaba Vemula 
Issue: https://github.com/open-cybernauts/open-range
Status:Phase I  [In Progress]

---

## Why I Chose This Issue


This issue caught my attention the moment I read it  not because it looked approachable,
but because the problem it is describing is one I have been thinking about from a different
angle for the past two years. I build agentic AI pipelines in production, and the hardest
challenge in every one of them has been the same thing this issue is trying to solve: getting
agents to reason across parallel channels with independent context, where what happens in one
stream affects decisions in another. The architecture proposed here  email, voice, chat, and
document channels running as parallel event streams rather than sequential actions in a single
turn  is the right design pattern, and I have built something structurally close to it using
CrewAI and LangGraph. What I have never done is apply it in an adversarial simulation context
where the NPC evaluation has to weigh persona, memory, and procedural plausibility simultaneously.
That is the part I genuinely want to learn.

The SIEM logging layer is one of those areas I have built monitoring and audit trail systems in production but always on the defensive infrastructure
side, never generating realistic multimodal noise that a Blue agent has to reason through under
pressure. That distinction matters and I want to understand it from the inside. My plan is to
start with the email channel and the NPC evaluation logic in `src/open_range/channels/email.py`,
get that working end to end including the SIEM entry generation, validate it against the
definition of done, and then move into voice pretext once the channel pattern is established
and the community has had a chance to review the approach.



## Reproduction Process

### Environment Setup

I cloned the repo and ran `docker compose up` to get the stack running locally.
The main thing I hit early was the mail container being up but completely silent —
no NPC was talking to it, no traffic flowing through it, nothing in the logs that
suggested it was being used at all. That was actually the clearest confirmation
that this issue is real. The infrastructure exists, the channel just isn't wired up yet.

Python environment was straightforward — `pip install -e .` inside the repo root,
no dependency conflicts. Docker Desktop on Mac needed the memory limit bumped to 4GB
before the full stack would stay stable under load.

### Steps to Reproduce

1. Start the stack with `docker compose up`
2. Run a Red agent action — any shell command via `docker exec`
3. Check the mail container logs — `docker logs <mail_container_id>`
4. Try to send anything resembling an email or attachment between agents

### Observed Result

Shell commands work exactly as expected. The mail container starts cleanly and
stays up. But there is no mechanism for Red to compose an email, no NPC handler
that processes incoming messages, and nothing in the SIEM output that reflects
any email activity. The channel is structurally present and functionally absent.

### Reproduction Evidence

- **Commit showing reproduction:** https://github.com/VSAIBABA/open-range
- **My findings:** The mail container is live but receives zero traffic during a
  full Red agent run. `src/open_range/channels/` does not exist yet — the directory
  is missing entirely, which confirms this is a greenfield implementation.
  `green.py` has no multimodal event handlers. `runtime_events.py` has no
  channel-specific event types. The gap between what exists and what the issue
  describes is exactly what the issue says it is a clean starting point.