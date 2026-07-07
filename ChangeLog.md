<!--
SPDX-FileCopyrightText: 2019-2025 Siemens
SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers

SPDX-License-Identifier: MIT
-->

# CaPyWfa - Clearing workflow automation for SW360

## NEXT

* lst_to_sbom: restore `.debian` / `.alpine` suffix on component version that
  was inadvertently dropped in the Alpine `distro` qualifier refactor (99778a6).
  The PURL keeps the clean package version; the SBOM component's `version`
  carries the suffix so SW360 releases are named e.g. `3.1.23-1.debian`.
* update poetry.lock, including idna fix for CVE-2026-45409 and urllib3 fix for
  CVE-2026-44431 and CVE-2026-44432. When talking to a trusted SW360 server, the
  CVEs shouldn't be critical, though.
* capywfa: preserve CycloneDX file extension `.cdx.json` for output SBOMs
  (`<bom-stem>-1-map.cdx.json` instead of `<bom-stem>.cdx-1-map.json`)
* capywfa: [debsbom](https://github.com/siemens/debsbom/) can now be used for
  downloading Debian sources: capywfa writes a file with missing sources' PURLs
  to `<bom-stem>-3-download.lst` and checks for existence of files afterwards.
  The old downloader interface (`SourceFileDownload` == `skip`) is still
  supported. See the new README section on source downloaders for details.

## 0.11.0

* drop support for Python 3.9 and 3.10 as CaPyCli don't support them any more.
* update dependencies to fix some CVEs in Python requests and pyjwt
* lst_to_sbom: produces valid CycloneDX 1.6 documents (metadata.tools changes)

## 0.10.0

major changes:

* respect PURL qualifiers during mapping, if PURLs don't match, source attachments
  are checked and the user is informed about the result
* SBOM properties for workflow control renamed from `distroclearing:*` to `capywfa:*`
  Additionally, our property Sw360SourceFileChecked was renamed to Sw360SourceFileCheck
* deprecate Python 3.9 so we can update urllib3 to 2.5 to fix CVE-2025-50181/-50182

new features:

* lst_to_sbom: add support for guessing Alpine Linux 3.22
* lst_to_sbom: create valid CycloneDX BOMs using the CycloneDX Python library
* update requests to 2.32.4 to fix CVE-2024-47081

## 0.9.3

* update CaPyCli to 2.8.0 including better PackageURL handling and release
  verification, watch out for "No unique release/component match" in the output!

## 0.9.2

* capywfa: fix crash in pass 2 when calling verify_sources

## 0.9.1

* switch to latest CaPyCli 2.7.0 stable
* first (consistent) PyPI release

## 0.9

* first public release, based on the Siemens-internal tool distro-clearing 2.0.8rc1
* lst_to_sbom: add distro qualifier for Alpine
