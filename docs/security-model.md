# Yama Security Model

## Why it exists
Multi-agent systems turn language plans into real side-effects. Once an agent process can write files, open sockets, or call tools, temporary authority becomes permanent the moment the effect is committed. Existing controls typically check permission when a task starts or when a token is issued. They do not re-check at the instant the protected effect is created, nor do they make the agent itself incapable of performing that effect. Yama exists to close this specific gap with a portable, falsifiable property rather than another platform-specific sandbox.

## The problem it solves
An agent may begin work under a valid grant. Before the effect becomes durable the grant can be revoked, can expire, or the payload can attempt to change purpose. Without a commit-time check owned by a supervisor that does not run the agent’s code, the effect still occurs. Yama requires four conditions before any protected side-effect may exist:

1. Authorization is decided by a supervisor that does not execute the agent.
2. That authorization is re-validated immediately before the effect is committed.
3. The agent is incapable of producing the effect by itself.
4. Every cross-boundary payload carries provenance such that untagged or wrong-purpose content cannot acquire new authority.

In the Linux reference implementation these conditions already refuse revoked grants, block out-of-policy file writes and exec, and reject missing or mismatched provenance. The same property can be met by container policy, micro-VM boundaries, or platform mediators.

## Why it should be a topic of further research
The problem is structural: every regulated multi-agent deployment (payments, clinical summaries, infrastructure changes) will eventually ask “who is allowed to make this effect real, and how do we stop it after we change our mind?” Yama supplies a clear, minimal answer that separates proposal from commit and forces the decision outside the agent.

Three open questions make the topic research-worthy rather than finished:
- How small can the re-check-to-commit window be made, and what failure modes appear under real network delay and partial partitions?
- How should provenance and purpose binding compose with semantic defenses so that authorization and content safety are not conflated?
- What is the comparative cost and strength of different restraint realizations (kernel LSM, container policy, micro-VM, language sandbox) against the same four conformance tests?

Answering these questions with the same measured, residual-risk-explicit style used so far would determine whether supervisor-owned commit control becomes a baseline expectation for multi-agent systems. That is sufficient reason for further research.
