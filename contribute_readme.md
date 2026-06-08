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