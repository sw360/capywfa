<!--
SPDX-FileCopyrightText: 2019-2025 Siemens
SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers

SPDX-License-Identifier: MIT
-->

# CaPyWfa - Clearing workflow automation for SW360

## UNRELEASED

* lst_to_sbom: add support for guessing Alpine Linux 3.22
* update requests to 2.32.4 to fix CVE-2024-47081
* deprecate Python 3.9 so we can update urllib3 to 2.5 to fix CVE-2025-50181/-50182

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
