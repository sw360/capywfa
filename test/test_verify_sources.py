# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
#
# SPDX-License-Identifier: MIT

from capywfa.verify_sources import verify_sources
from capywfa.cdx_support import set_cdx, get_cdx, remove_cdx
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import ExternalReference, ExternalReferenceType, HashType, HashAlgorithm, XsUri
from capycli.common.capycli_bom_support import CaPyCliBom
from packageurl import PackageURL
import vcr
import os
import shutil
import pytest


def vcr_test(fixture):
    return vcr.use_cassette(
        "test/fixtures/vcr/verify_sources_" + fixture,
        filter_headers=["Authorization", "User-Agent"]
        )


def create_test_bom():
    bom = Bom(components=[Component(
        name="efibootguard", type=ComponentType.LIBRARY,
        version="0.13+cip.debian", purl=PackageURL(
            "deb", "debian", "efibootguard",
            "0.13+cip.debian", {"arch": "source"}))])
    set_cdx(bom.components[0], "Sw360Id", "123")
    return bom


def add_test_bom_ext_ref(bom):
    bom.components[0].external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri("efibootguard-0.13.zip")
        )
    )


@pytest.fixture(autouse=True)
def no_proxy():
    os.environ['NO_PROXY'] = 'example.com'
    os.environ['no_proxy'] = 'example.com'


@pytest.fixture()
def verify():
    if os.path.exists("verify"):
        if len(os.listdir("verify")) != 0:
            assert False, "Test aborted, verify directory exists!"
    else:
        os.mkdir("verify")

    yield "verify"

    shutil.rmtree("verify")


@vcr_test("base.yaml")
def test_verify_sources_no_sw360id(capsys):
    bom = create_test_bom()
    remove_cdx(bom.components[0], "Sw360Id")
    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir="pkgs")
    captured = capsys.readouterr()
    assert "no sw360id in BOM" in captured.out


@vcr_test("base.yaml")
def test_verify_sources_no_source(capsys):
    bom = create_test_bom()
    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir="pkgs")
    captured = capsys.readouterr()
    assert "no sources available" in captured.out


def test_verify_sources_extract_match(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)
    # sources will be downloaded and unpacked as BOM doesn't specify hash

    # force it to not accept attachment (will break in 54 yrs ;) )
    os.environ["DAYS_BEFORE_SRC_ACCEPT"] = "20000"
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], "test/fixtures")
        assert cassette.play_count == 4

    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "efibootguard-0.13.zip identical to efibootguard-0.13.zip" in captured.out
    assert "checkStatus set to ACCEPTED" not in captured.out

    set_cdx(bom.components[0], "Sw360SourceFileCheck", "failed")

    # now let it accept attachment
    del os.environ["DAYS_BEFORE_SRC_ACCEPT"]
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], "test/fixtures")
        assert cassette.play_count == 5

    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "efibootguard-0.13.zip identical to efibootguard-0.13.zip" in captured.out
    assert "checkStatus set to ACCEPTED" in captured.out


def test_verify_sources_sha1_match(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)
    bom.components[0].external_references[0].hashes.add(HashType(
        alg=HashAlgorithm.SHA_1,
        content="f8ed764424ee04dac8298bdc1feed2e356f3d2cd"
        )
    )

    # force it to not accept attachment (will break in 54 yrs ;) )
    os.environ["DAYS_BEFORE_SRC_ACCEPT"] = "20000"
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], "test/fixtures")
        assert cassette.play_count == 3
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "Hash match" in captured.out
    assert "checkStatus set to ACCEPTED" not in captured.out

    set_cdx(bom.components[0], "Sw360SourceFileCheck", "failed")

    # now let it accept attachment
    del os.environ["DAYS_BEFORE_SRC_ACCEPT"]
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], "test/fixtures")
        assert cassette.play_count == 4
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "Hash match" in captured.out
    assert "checkStatus set to ACCEPTED" in captured.out


@vcr_test("download_failed.yaml")
def test_verify_sources_sw360_download_failed(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)

    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir="test/fixtures")
    captured = capsys.readouterr()
    assert "ERROR during SW360 download" in captured.out


@vcr_test("base.yaml")
def test_verify_sources_debian_download_missing(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)

    # use an invalid pkg directory to simulate missing file...
    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir=".")
    captured = capsys.readouterr()
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "failed"
    assert "local Debian source ./efibootguard-0.13.zip missing" in captured.out


@vcr_test("base.yaml")
def test_verify_sources_debian_download_failed(capsys, verify):
    bom = create_test_bom()
    set_cdx(bom.components[0], "SourceFileDownload", "failed")
    add_test_bom_ext_ref(bom)

    # use an invalid pkg directory to simulate missing file...
    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir=".")
    captured = capsys.readouterr()
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "failed"
    assert "Skipping efibootguard 0.13+cip.debian - Debian download failed" in captured.out
