# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
#
# SPDX-License-Identifier: MIT

from capywfa.lst_to_sbom import map_signed_packages


def test_signed_packages():
    assert (map_signed_packages("grub-efi-amd64-signed", "1+2.02+dfsg1+20")
            == ("grub2", "2.02+dfsg1-20"))

    assert (map_signed_packages("shim-helpers-amd64-signed",
                                "1+15+153.3beb9+7")
            == ("shim", "15+153.3beb9-7"))

    assert (map_signed_packages("linux-signed-amd64", "4.19.171+2")
            == ("linux", "4.19.171-2"))


def test_signed_packages_shim_deb10u1():
    assert (map_signed_packages("shim-helpers-amd64-signed",
                                "1+15+1533136590.3beb971+7+deb10u1")
            == ("shim", "15+1533136590.3beb971-7+deb10u1"))
