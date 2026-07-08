#!/usr/bin/python3

# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
# SPDX-FileContributor: Gernot Hillier <gernot.hillier@siemens.com>
#
# SPDX-License-Identifier: MIT

import os
from capycli.common.capycli_bom_support import CycloneDxSupport

legacy_to_cdx_prop = {
    "ComponentId": CycloneDxSupport.CDX_PROP_COMPONENT_ID,
    "MapResult": CycloneDxSupport.CDX_PROP_MAPRESULT,
    "MapResultById": CycloneDxSupport.CDX_PROP_MAPRESULT_BY_ID,
    "Sw360Id": CycloneDxSupport.CDX_PROP_SW360ID,
    "Categories": CycloneDxSupport.CDX_PROP_CATEGORIES,
    "Sw360SourceFileCheck": "capywfa:Sw360SourceFileCheck",
    "SourceFileDownload": "capywfa:SourceFileDownload",
    "SourceFileType": CycloneDxSupport.CDX_PROP_SRC_FILE_TYPE,
    "SourceFileComment": CycloneDxSupport.CDX_PROP_SRC_FILE_COMMENT,
    "Comment": "capywfa:Comment"
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


def resolve_local_source_url(url: str, sbom_dir: str, pkg_dir: str) -> str | None:
    """Resolve a Standard-BOM `source archive (local copy)` URL to a path.

    Per the Siemens Standard BOM spec, file:/// URLs have to be relative to
    the SBOM document's directory.  The `file:` scheme prefix and any leading
    slashes are thus just stripped to normalise all valid URL forms:

        file:///sources/x/y.tar  ->  sources/x/y.tar
        file://sources/x/y.tar   ->  sources/x/y.tar
        sources/x/y.tar          ->  sources/x/y.tar  (bare path, legacy)

    Resolution is attempted in order:
        1. Relative to sbom_dir (spec-correct, SBOM parent directory).
        2. Relative to pkg_dir  (legacy fallback, --sources argument).

    Returns:
        path - the resolved absolute path if the file exists, else None.
    """
    rel = url.removeprefix("file:").lstrip("/")
    for base in (sbom_dir, pkg_dir):
        candidate = os.path.join(base, rel)
        if os.path.isfile(candidate):
            return candidate
    return None
