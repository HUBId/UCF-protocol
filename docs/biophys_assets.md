# Biophysical asset payloads

The `biophys_assets.proto` schema defines payloads used to transmit neuron
morphologies, channel parameters, synapse parameters, and connectivity graphs.
All payloads are additive and include optional digests for integrity pipelines.

## Payload schemas

* `MorphologySetPayload` bundles `MorphNeuron` entries, each with bounded
  `Compartment` lists and optional `LabelKV` metadata.
* `ChannelParamsSetPayload` stores per-neuron, per-compartment conductance
  parameters, with optional calcium conductance and leak reversal potential.
* `SynapseParamsSetPayload` describes synapse parameter sets, including
  quantized maximum conductance, time constants, and optional modulation channel
  selection.
* `ConnectivityGraphPayload` encodes directed edges with per-edge delays and
  synapse parameter references.

Determinism requirements are encoded in the protobuf comments. Producers must
sort neurons by `neuron_id`, compartments by `comp_id`, labels by `(k, v)`,
synapse params by `syn_param_id`, and edges by
`(pre, post, post_compartment, syn_param_id, delay_steps)` before encoding.

## Scaling conventions

* Lengths (`length_um`, `diameter_um`) are integer micrometers.
* Conductance fields (`leak_g`, `na_g`, `k_g`, `ca_g`) are scaled integers
  (`Q16.16` unless otherwise documented per chip).
* `g_max_q` and `stp_u_q` are `Q16.16` fixed-point values.
* `e_rev_mv` and `e_rev_leak` are signed millivolts.
* `tau_*_steps` and `delay_steps` are integer timesteps in model step units.

## Label keys

Standard label keys are:

* `pool`: logical pool or population tag (`alpha`, `beta`, ...).
* `type`: cell or compartment type (`pyramidal`, `interneuron`, ...).
* `region`: anatomical region or layer (`L2/3`, `CA1`, ...).

Additional labels may be added as needed, but producers should keep label sets
stable and sorted for deterministic encoding.
