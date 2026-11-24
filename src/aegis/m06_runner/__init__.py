"""M06 — ContainerRunner, collector and parser isolation (owner: G1.3a).

Modules:

    denyset     platform egress deny set + inet_aton literal normalization (R-5)
    netpolicy   the allow/deny decision engine of one job (stdlib only)
    broker      the per-job egress broker container entrypoint (stdlib only)
    podman      rootless PodmanRunner: hardened run, per-job network, reconcile
    collector   hostile-output collection with caps and SHA-256
    parser_host isolated parser subprocess (+ parser_child, the child side)
    spec        ContainerSpec from ApprovedTask + pinned manifest (OI-12, P3c, E-1)
    envelope    ResultEnvelope assembly and the ingestion POST (dedup_key job:<id>:envelope)
    job         the flow that ties the steps together

`denyset`, `netpolicy` and `broker` are standard-library only on purpose: the broker runs as a
container built from those three files, so they must not import the contract DTOs.
"""
