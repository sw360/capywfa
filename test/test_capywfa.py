# SPDX-FileCopyrightText: 2019-2026 Siemens
# SPDX-FileCopyrightText: 2019-2026 Siemens Healthineers
#
# SPDX-License-Identifier: MIT

from capywfa.capywfa import pass3_download_sources
from capywfa.cdx_support import get_cdx, set_cdx
from capycli.common.map_result import MapResult
from capycli.common.capycli_bom_support import CaPyCliBom
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import ExternalReference, ExternalReferenceType, HashType, HashAlgorithm, XsUri
from packageurl import PackageURL

SHA1 = "f8ed764424ee04dac8298bdc1feed2e356f3d2cd"
FIXTURES = "test/fixtures"


def make_component(name="pkg", map_result=MapResult.FULL_MATCH_BY_ID,
                   source_check="passed"):
    comp = Component(
        name=name, type=ComponentType.LIBRARY,
        version="1.0", purl=PackageURL("deb", "debian", name, "1.0",
                                       {"arch": "source"}))
    set_cdx(comp, "MapResult", map_result)
    if source_check:
        set_cdx(comp, "Sw360SourceFileCheck", source_check)
    return comp


def make_bom(*components):
    return Bom(components=list(components))


def test_pass3_good_match_verified_gets_skip():
    """Good SW360 match with verified source → SourceFileDownload=skip, not missing."""
    bom = make_bom(make_component(map_result=MapResult.FULL_MATCH_BY_ID,
                                  source_check="passed"))
    bom, missing = pass3_download_sources(bom, "", "")
    assert get_cdx(bom.components[0], "SourceFileDownload") == "skip"
    assert missing == []


def test_pass3_no_match_no_source_goes_missing():
    """NO_MATCH with no local source → item in missing list, no SourceFileDownload set."""
    bom = make_bom(make_component(map_result=MapResult.NO_MATCH, source_check=""))
    bom, missing = pass3_download_sources(bom, "", "")
    assert get_cdx(bom.components[0], "SourceFileDownload") == ""
    assert len(missing) == 1
    assert missing[0].name == "pkg"


def test_pass3_no_match_with_valid_source_not_missing():
    """NO_MATCH but downloader provided a valid local source → not missing, not skip."""
    comp = make_component(map_result=MapResult.NO_MATCH, source_check="")
    comp.external_references.add(ExternalReference(
        type=ExternalReferenceType.DISTRIBUTION,
        comment=CaPyCliBom.SOURCE_FILE_COMMENT,
        url=XsUri(f"sources/{SHA1}/efibootguard-0.13.zip"),
        hashes={HashType(alg=HashAlgorithm.SHA_1, content=SHA1)},
    ))
    bom = make_bom(comp)
    # sbom_dir points at test/fixtures so the file is found at
    # test/fixtures/sources/<sha1>/efibootguard-0.13.zip
    bom, missing = pass3_download_sources(bom, FIXTURES, "")
    assert missing == []
    assert get_cdx(bom.components[0], "SourceFileDownload") != "failed"


def test_pass3_sources_downloaded_still_missing_gets_failed():
    """Re-entry with --sources-downloaded: item still missing → SourceFileDownload=failed."""
    bom = make_bom(make_component(map_result=MapResult.NO_MATCH, source_check=""))
    bom, missing = pass3_download_sources(bom, "", "", sources_downloaded=True)
    assert get_cdx(bom.components[0], "SourceFileDownload") == "failed"
    assert missing == []
