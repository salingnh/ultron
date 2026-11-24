"""AEGIS–Vanguard backend package (G1 foundation skeleton).

Layout is fixed by the G1.1a card so later tasks never share files:

    src/aegis/contracts_gen/  generated Pydantic v2 DTOs of contracts/ (do not edit)
    src/aegis/common/         shared ports, repository paths, cross-module helpers
    src/aegis/mNN_<name>/     one package per architectural module (M01..M28)
    adapters/m08/<tool>/      adapter packages (manifest + parser), outside the core
    tests/fakes/              in-memory fakes of the six module interfaces
"""

__all__ = ["contracts_gen"]
