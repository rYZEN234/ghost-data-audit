"""Ghost Data Still Exists - deletion audit agent.

Deterministic pipeline that audits whether a deletion request was really
completed.  Modules:

    util       - small helpers (time, regexes, normalisation)
    model      - Obs / Step / Case data classes and vocabulary constants
    data       - CSV loaders, identity index, activity index
    parsers/   - one parser per evidence format -> normalised observations
    store      - evidence store (all observations + scopes) with time queries
    intent     - deletion-intent classification of request_text
    linker     - activity-stream linking (account events, policy chains)
    resolve    - per-case reconstruction of the resource states at audit_at
    plan       - policy engine + ordered step generation
"""
