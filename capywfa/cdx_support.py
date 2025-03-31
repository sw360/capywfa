#!/usr/bin/python3

# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
# SPDX-FileContributor: Gernot Hillier <gernot.hillier@siemens.com>
#
# SPDX-License-Identifier: MIT

from capycli.common.capycli_bom_support import CycloneDxSupport

legacy_to_cdx_prop = {
    "ComponentId": CycloneDxSupport.CDX_PROP_COMPONENT_ID,
    "MapResult": CycloneDxSupport.CDX_PROP_MAPRESULT,
    "Sw360Id": CycloneDxSupport.CDX_PROP_SW360ID,
    "Categories": CycloneDxSupport.CDX_PROP_CATEGORIES,
    "Sw360SourceFileChecked": "distroclearing:Sw360SourceFileChecked",
    "SourceFileDownload": "distroclearing:SourceFileDownload",
    "SourceFileType": CycloneDxSupport.CDX_PROP_SRC_FILE_TYPE,
    "SourceFileComment": CycloneDxSupport.CDX_PROP_SRC_FILE_COMMENT,
    "Comment": "distroclearing:Comment"
}


def get_cdx(item, key, default=""):
    # use prefix "distroclearing:" for our own properties
    key = legacy_to_cdx_prop[key]
    value = CycloneDxSupport.get_property_value(
        item, key)
    if value == "":
        value = default
    return value


def set_cdx(item, key, value):
    CycloneDxSupport.update_or_set_property(
        item, legacy_to_cdx_prop[key], value)


def remove_cdx(item, key):
    CycloneDxSupport.remove_property(item, legacy_to_cdx_prop[key])
