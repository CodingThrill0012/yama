# Yama Research Note

This note records the Yama control property and, in later updates, the
experiments used to test it. Claims in this document are limited to
behavior that has been measured, or are marked as still to be measured.

## The Yama Property

Yama is a system-independent control property for multi-agent systems: every protected side-effect must be authorized by a supervisor that does not execute the agent’s code; that authorization must be re-validated immediately before the effect is committed; the agent itself must be incapable of producing the protected side-effect; and every payload that crosses an agent or supervisor boundary must carry an explicit provenance tag such that untagged or insufficiently trusted content cannot acquire new authority. Authorization alone does not provide semantic safety.
