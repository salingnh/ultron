"""Image references used by the integration tests.

Product images are digest-pinned in ``pins/pin-table.json`` (G0.2 requirement).
The two test-only base images are digest-pinned here as well so a rerun cannot
silently pick up a new base image.
"""

ALPINE = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
PYTHON_312 = "docker.io/library/python@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"

PRODUCT = {
    "subfinder": "docker.io/projectdiscovery/subfinder@sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf",
    "dnsx": "docker.io/projectdiscovery/dnsx@sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec",
    "naabu": "docker.io/projectdiscovery/naabu@sha256:67c120a669954b768354197fc04328e08027898dc821bc8f276b3e26cd21f6aa",
    "bbot": "docker.io/blacklanternsecurity/bbot@sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e",
}
