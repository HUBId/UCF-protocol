# Milestones

Milestones track execution and consolidation progress across micro, meso, and macro layers.
Each layer carries deterministic digests, hormone summaries, and bounded references to
related artifacts to keep replay and consolidation reproducible.

## Micro → Meso → Macro lifecycle

* **MicroMilestone** records a sealed span of experience IDs with a summary digest,
  hormone profile snapshot, and bounded theme/reason codes. Once SEALED, the experience
  range and digests should not change.
* **MesoMilestone** aggregates bounded references to micro milestones, preserving
  hormone stability classification and optional proof receipt references. A STABLE meso
  milestone indicates the aggregated micro set is fixed and ready for macro anchoring.
* **MacroMilestone** anchors meso references, proposed trait updates, and optional policy
  ecology references. FINALIZED macro milestones set the consistency class used by
  downstream replay/consolidation workflows and may set `identity_anchor_flag` when the
  macro is used as an identity root.

Replay plans (`ReplayPlan`) point at macro/meso/micro digests, carry the fidelity and
inject modes to use, and include bucketed stop conditions for deterministic replays.
