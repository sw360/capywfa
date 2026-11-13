# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
#
# SPDX-License-Identifier: MIT

from capywfa.verify_sources import verify_sources, split_verifiers, compare_trees, compare_files
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

SHA1 = "f8ed764424ee04dac8298bdc1feed2e356f3d2cd"
FIXTURES = "test/fixtures"


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
    """Spec-compliant relative path, no `file:` scheme."""
    bom.components[0].external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri(f"sources/{SHA1}/efibootguard-0.13.zip")
        )
    )


def add_test_bom_ext_ref_file_uri(bom):
    """Spec-compliant URL using the `file:///` scheme."""
    bom.components[0].external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri(f"file:///sources/{SHA1}/efibootguard-0.13.zip")
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


def test_split_verifiers():
    assert split_verifiers(["foo@bar.com alice@example.com", "carol@x.org"]) == [
        "foo@bar.com", "alice@example.com", "carol@x.org"]
    assert split_verifiers([]) == []


def test_compare_trees_symlink_loop(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "loop").symlink_to(".")
    assert list(compare_trees(str(a), str(b))) == []
    (b / "loop").unlink()
    (b / "loop").mkdir()
    assert list(compare_trees(str(a), str(b))) == [f"Symlinks {a / 'loop'} and {b / 'loop'} differ"]


def test_compare_trees(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "same.c").write_text("int x;\n")
    (b / "same.c").write_text("int x;\n")
    assert list(compare_trees(str(a), str(b))) == []

    (a / "changed.c").write_text("int x;\n")
    (b / "changed.c").write_text("int y;\n")
    st = os.stat(a / "changed.c")
    os.utime(b / "changed.c", ns=(st.st_atime_ns, st.st_mtime_ns))
    (a / "only_a.c").write_text("")
    (a / ".git").mkdir()
    (a / "logo.bin").write_bytes(b"\0\1")
    (b / "logo.bin").write_bytes(b"\0\2")
    out = "\n".join(compare_trees(str(a), str(b)))
    assert "-int x;" in out and "+int y;" in out
    assert f"Only in {a}: only_a.c" in out
    assert f"Binary files {a / 'logo.bin'} and {b / 'logo.bin'} differ" in out
    assert f"Only in {a}: .git" in out


def test_compare_files_too_big(tmp_path, monkeypatch):
    monkeypatch.setattr("capywfa.verify_sources.MAX_DIFF_SIZE", 4)
    (tmp_path / "a.c").write_text("int x;\n")
    (tmp_path / "b.c").write_text("int y;\n")
    out = "\n".join(compare_files(str(tmp_path / "a.c"), str(tmp_path / "b.c")))
    assert out == f"Files {tmp_path / 'a.c'} and {tmp_path / 'b.c'} differ (too big to diff)"


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
    """Extract-and-diff using the file:/// URL form; resolved via pkg_dir."""
    bom = create_test_bom()
    add_test_bom_ext_ref_file_uri(bom)
    # sources will be downloaded and unpacked as BOM doesn't specify hash

    # force it to not accept attachment (will break in 54 yrs ;) )
    os.environ["DAYS_BEFORE_SRC_ACCEPT"] = "20000"
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [],
                             pkg_dir=FIXTURES)
        assert cassette.play_count == 4

    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "efibootguard-0.13.zip identical to efibootguard-0.13.zip" in captured.out
    assert "checkStatus set to ACCEPTED" not in captured.out

    set_cdx(bom.components[0], "Sw360SourceFileCheck", "failed")

    # now let it accept attachment
    del os.environ["DAYS_BEFORE_SRC_ACCEPT"]
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [],
                             pkg_dir=FIXTURES)
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
        content=SHA1
        )
    )

    # force it to not accept attachment (will break in 54 yrs ;) )
    os.environ["DAYS_BEFORE_SRC_ACCEPT"] = "20000"
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], FIXTURES)
        assert cassette.play_count == 3
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "Hash match" in captured.out
    assert "checkStatus set to ACCEPTED" not in captured.out

    set_cdx(bom.components[0], "Sw360SourceFileCheck", "failed")

    # now let it accept attachment
    del os.environ["DAYS_BEFORE_SRC_ACCEPT"]
    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], FIXTURES)
        assert cassette.play_count == 4
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "Hash match" in captured.out
    assert "checkStatus set to ACCEPTED" in captured.out


def test_verify_sources_set_accepted_disabled(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)
    bom.components[0].external_references[0].hashes.add(HashType(
        alg=HashAlgorithm.SHA_1,
        content=SHA1
        )
    )

    with vcr_test("base.yaml") as cassette:
        bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [],
                             sbom_dir=FIXTURES, set_accepted=False)
        assert cassette.play_count == 3
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    captured = capsys.readouterr()
    assert "checkStatus update disabled" in captured.out
    assert "checkStatus set to ACCEPTED" not in captured.out


@vcr_test("download_failed.yaml")
def test_verify_sources_sw360_download_failed(capsys, verify):
    bom = create_test_bom()
    add_test_bom_ext_ref(bom)

    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [], pkg_dir=FIXTURES)
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
    assert "local source" in captured.out and "missing" in captured.out


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


@vcr_test("base.yaml")
def test_verify_sources_spec_compliant_pkg_dir_fallback(capsys, verify):
    """file:/// URL resolved via pkg_dir when sbom_dir doesn't contain the file.
    No SHA-1 on the BOM ext ref forces the extract-and-diff path.
    """
    bom = create_test_bom()
    # No hash so we bypass the hash-match fast path
    bom.components[0].external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri(f"file:///sources/{SHA1}/efibootguard-0.13.zip"),
    ))

    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [],
                         pkg_dir=FIXTURES, sbom_dir="/nonexistent")
    captured = capsys.readouterr()
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "passed"
    assert "efibootguard-0.13.zip identical to efibootguard-0.13.zip" in captured.out


@vcr_test("base.yaml")
def test_verify_sources_spec_compliant_not_found(capsys, verify):
    """file:/// URL where file is absent from both sbom_dir and pkg_dir.
    No SHA-1 on the BOM ext ref forces the extract-and-diff path where the
    file-resolution failure is detected.
    """
    bom = create_test_bom()
    # No hash so we bypass the hash-match fast path
    bom.components[0].external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri(f"file:///sources/{SHA1}/efibootguard-0.13.zip"),
    ))

    bom = verify_sources(bom, "https://sw360.example.com", "mytoken", [],
                         pkg_dir="/nonexistent", sbom_dir="/nonexistent")
    captured = capsys.readouterr()
    assert get_cdx(bom.components[0], "Sw360SourceFileCheck") == "failed"
    assert "local source" in captured.out and "missing" in captured.out
