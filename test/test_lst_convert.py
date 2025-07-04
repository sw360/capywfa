# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
#
# SPDX-License-Identifier: MIT

from capywfa.lst_to_sbom import map_signed_packages, lst_to_sbom


def test_map_signed_packages():
    assert (map_signed_packages("grub-efi-amd64-signed", "1+2.02+dfsg1+20")
            == ("grub2", "2.02+dfsg1-20"))

    assert (map_signed_packages("shim-helpers-amd64-signed",
                                "1+15+153.3beb9+7")
            == ("shim", "15+153.3beb9-7"))

    assert (map_signed_packages("linux-signed-amd64", "4.19.171+2")
            == ("linux", "4.19.171-2"))


def test_map_signed_packages_shim_deb10u1():
    assert (map_signed_packages("shim-helpers-amd64-signed",
                                "1+15+1533136590.3beb971+7+deb10u1")
            == ("shim", "15+1533136590.3beb971-7+deb10u1"))


def test_lst_to_sbom_alpine_3_20_apk():
    bom = lst_to_sbom("apk", "test/fixtures/alpine-3.20-apk-list.txt")

    assert bom.metadata.component.pedigree.ancestors[0].name == "Alpine Linux"
    assert bom.metadata.component.pedigree.ancestors[0].version == "3.20"
    assert bom.components[0].purl.to_string().startswith("pkg:apk/alpine/"
                                                         "alpine-baselayout@3.6.5-r0")
    assert bom.components[1].purl.to_string().startswith("pkg:apk/alpine/alpine-keys@2.4-r1")
    assert len(bom.components) == 4
    for component in bom.components:
        assert "distro=alpine-3.20" in component.purl.to_string()


def test_lst_to_sbom_alpine_3_20_manifest():
    bom = lst_to_sbom("apk", "test/fixtures/alpine-3.20-manifest.lst")
    assert bom.metadata.component.pedigree.ancestors[0].name == "Alpine Linux"
    assert bom.metadata.component.pedigree.ancestors[0].version == "3.20"
    assert bom.components[0].purl.to_string().startswith("pkg:apk/alpine/"
                                                         "alpine-baselayout@3.6.5-r0")
    assert bom.components[1].purl.to_string().startswith("pkg:apk/alpine/alpine-keys@2.4-r1")
    assert len(bom.components) == 4
    for component in bom.components:
        assert "distro=alpine-3.20" in component.purl.to_string()
