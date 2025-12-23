# Geist signals

`geist.proto` captures recursive self-state summaries and feedback used for replay and
consolidation decisions.

* **ConsistencyFeedback** links a recursive self-state (`rss_ref`) with bounded macro
  anchors (`ism_refs`) and a policy ecology digest (`pev_ref`). Flags highlight specific
  divergence modes (value conflict, behavior drift, risk drift, identity break) and are
  paired with a recommended noise class and consolidation eligibility outcome.
* `replay_trigger_hint` and bounded trigger reason codes are used to open replay plans when
  consistency dips (e.g., CONSISTENCY_LOW) so that simulation/execution strategies can be
  selected deterministically.
* Depth and uncertainty classes in `RecursiveSelfState` and `SelfStateVector` provide
  bounded recursion metadata without relying on maps or unbounded lists.
