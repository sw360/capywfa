<!--
SPDX-FileCopyrightText: 2019-2025 Siemens
SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers

SPDX-License-Identifier: MIT
-->

# CaPyWfa - Clearing workflow automation for SW360

Main goal of this project is to automate submission of Open Source packages
to the [SW360](https://github.com/eclipse-sw360/sw360) component catalogue,
e.g. for license clearing. It is based on [CaPyCli](https://github.com/sw360/capycli).

For now, this is mainly used for Debian and Alpine Linux packages, but most of
our building blocks might be helpful for clearing of large collections of
(linux) packages in general.

## Clearing tools

**Please refer to [ChangeLog.md](ChangeLog.md) for latest changes.

These tools are designed to provide full automation e.g. for integration in CI
pipelines, but at the same time we stay a friendly neighbour to users creating SW360
entries interactively. Major design decisions:

* We rely on [Package URLs](https://github.com/package-url/purl-spec/) to
  identify software components and versions. We mostly avoid heuristics.
* We try hard to not create duplicates. Existing components, releases and
  attachments will be re-used if they can be identified by Package URLs.
* If no matching component is found, the SBOM item will be skipped and
  the user is asked to manually identify existing components, add package
  URLs and re-run the tool.
* New components can be created if the user adds additional meta-data to
  the SBOM e.g. to specify the component name, homepage and description. Please
  use upstream names like e.g. "Perl::Critic" instead of Debian's
  "libperl-critic-perl".
* Existing attachments are verified. If the hash doesn't match, the scripts try
  to automatically download, extract and compare existing attachments.

Also note that for now, the scripts will only handle source packages. No
entries, package URLs etc. will be added for binary packages. In other words:
we only create SW360 releases, but don't support the
[SW360 package portlet](https://github.com/eclipse-sw360/sw360/pull/1999) yet.

## Overview

Your main entry point is `capywfa/capywfa.py`. This section explains the general
workflow. For details how to install and run the tools, see the next sections!

CaPyWfa will perform the following tasks:

1. Identify existing components (packages) and releases (versions) in SW360.
2. Ask user to download missing sources.
3. Verify existing SW360 sources are correct (using the `verify_sources.py`
   script internally -- which can also be called separately).
4. Create missing components and releases in SW360 and upload sources.
5. Link SW360 releases to your SW360 project.
6. Show you a summary if packages couldn't be processed automatically,
   exit code for incomplete uploads: 81

`capywfa.py` expects a [CycloneDX SBOM](https://cyclonedx.org/), so
you have to convert your package list first:

```shell
# convert Debian or Alpine package list to Standard BOM format:
$ lst_to_sbom.py <deb|apk> <package-list> package-list.json
```

Now, check `capywfa.py --help` for the necessary parameters. The tool will guide
you through the process. Note that it will write an updated BOM after each step.
In general, it should be safe to interrupt the tool and re-run it at any time.
Using the output BOM from the last step will save some time in repeated runs.

If not all components can be identified automatically, you need to manually
search the components in SW360 and add their component Id to the BOM or add the
PackageURL to SW360. The tool will offer to download a list of all components if
you prefer offline search.

Components which do not exist in SW360 can be created by capywfa
-- this requires you to add some meta information to the BOM (Homepage,
Categories, Description).

## Running directly on a Linux system

You can clone this repository and run the scripts directly.

CaPyWfa should run on any recent system with Python >= 3.8.

To run the scripts in a Python "virtual environment" with all needed
dependencies, we use [Poetry](https://python-poetry.org/docs/)

```shell
poetry install
poetry run python3 ./capywfa/capywfa.py ...
```

## Installing as Python package (experimental)

TODO: Not available on Github/PyPI yet.

## SW360 project verification

With the help of the `capycli` command and small helper scripts which are
part of the Poetry and Docker environments, you can verify that the upload
succeeded and already existing releases have correct sources and meta data:

```shell
$ python3 -m capycli bom Map --nocache -i packages-list.json -t <sw360-token> -oa -o packages-mapped.json
[...]
Mapping result:
  Full match by id, at, 3.1.23-1.debian => at daemon, 3.1.23-1.debian, b0667b7334c070cd2f05b071265ce7b3
[...]
$ python3 -m capycli project Prerequisites -id <project-id> -i packages-mapped.json -t <token> -oa
[...]
  Components:
    software-properties, 0.96.20.2-2.debian: OPEN
      Download URL: http://deb.debian.org/debian/pool/main/s/software-properties_0.96.20.2-2.dsc
      SHA1 for source software-properties_0.96.20.2-2-debian-combined.tar.bz2 doesn't match!
      1 source file(s) available.
      component management id: {'package-url': 'pkg:deb/debian/software-properties@0.96.20.2-2?arch=source'}
[...]
```

## Credits

These tools were developed by Siemens AG, with primary funding from Siemens Healthineers AG.
