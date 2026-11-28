"""The artifact adapters' package identity must be the key M27 stores (G2-D).

An adapter writes `purl:pkg:...@<version>` itself (it may not import the core), and M27 re-derives
every canonical key with `aegis-norm/1` and refuses one it would rewrite (`non_canonical_key`). A
round-trip mismatch here is not cosmetic: the package asset is quarantined and every finding about
it becomes `unknown_subject_asset` - the lab image showed 258 such findings before the rule below
matched the normalizer. This suite pins the two implementations together.
"""

from __future__ import annotations

import pytest

from adapters.artifact.purl import normalize_package_purl, purl_without_version
from aegis.m27_ingestion.normalize import validate_key

PURLS = [
    # Debian revisions and epochs are where Trivy's own fields disagree with the purl.
    "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u2?arch=amd64&distro=debian-10.10",
    "pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64&distro=debian-10.10&epoch=1",
    "pkg:deb/debian/libssl1.1@1.1.1d-0%2Bdeb10u7?arch=amd64&distro=debian-10.10",
    "pkg:apk/alpine/krb5-libs@1.22.2-r1?arch=x86_64&distro=3.24.4",
    "pkg:apk/alpine/.python-rundeps@20261105.193119?arch=noarch&distro=3.24.4",
    "pkg:pypi/pip@25.0.1",
    "pkg:pypi/typing_extensions@4.12.2",
    "pkg:npm/%40babel/core@7.24.0",
    "pkg:npm/lodash@4.17.20",
    "pkg:rpm/redhat/openssl@1.1.1k-12.el8?arch=x86_64&distro=rhel-8.9",
    "pkg:golang/github.com%2Fgin-gonic%2Fgin@v1.9.1",
]


@pytest.mark.parametrize("purl", PURLS)
def test_the_adapter_purl_is_the_canonical_key_m27_stores(purl: str) -> None:
    normalized = normalize_package_purl(purl)
    assert normalized.startswith("pkg:")
    key = "purl:" + normalized
    # This is the gate: M27 refuses a key it would rewrite, and quarantines the asset and every
    # finding whose subject it is.
    validate_key(key, "package")
    assert normalize_package_purl(normalized) == normalized, "normalization is not idempotent"


def test_the_epoch_is_folded_into_the_version() -> None:
    assert (
        normalize_package_purl("pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64&epoch=1")
        == "pkg:deb/debian/bsdutils@1%3A2.33.1-0.1"
    )


def test_a_purl_without_a_version_has_no_identity() -> None:
    assert normalize_package_purl("pkg:deb/debian/adduser?arch=all") == ""
    assert normalize_package_purl("pkg:deb/debian/adduser@") == ""


def test_fingerprint_context_drops_the_version() -> None:
    assert (
        purl_without_version("pkg:deb/debian/bsdutils@1%3A2.33.1-0.1?arch=amd64")
        == "pkg:deb/debian/bsdutils"
    )
