#!/usr/bin/python3

# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
# SPDX-FileContributor: Gernot Hillier <gernot.hillier@siemens.com>
#
# SPDX-License-Identifier: MIT

import os
import re
import sys
import json
import argparse
import importlib.metadata
from packageurl import PackageURL

DEB_SIGNED_MAP = {
    "grub-efi-amd64-signed": "grub2",  # 1+2.02+dfsg1+20 -> 2.02+dfsg1-20
    "grub-efi-arm64-signed": "grub2",
    "grub-efi-ia32-signed": "grub2",
    "shim-helpers-amd64-signed": "shim",  # 1+15+153.3beb9+7 -> 15+153.3beb9-7
    "shim-helpers-arm64-signed": "shim",
    "shim-helpers-i386-signed": "shim",
    "linux-signed-amd64": "linux",  # 4.19.171+2 -> 4.19.171-2
    "linux-signed-arm64": "linux",
    "linux-signed-i386": "linux",
}


def map_signed_packages(pkg, version):
    if pkg in DEB_SIGNED_MAP:
        print("WARNING: Signed source found, mapping", pkg, version, end=" ")
        pkg = DEB_SIGNED_MAP[pkg]
        if version.startswith("1+"):
            version = version[2:]
        if "+deb" in version:
            version, deb_suffix = version.rsplit("+deb")
            deb_suffix = "+deb" + deb_suffix
        else:
            deb_suffix = ""
        version = "-".join(version.rsplit("+", 1)) + deb_suffix
        print("to", pkg, version)
    return (pkg, version)


ALPINE_MATCH_TABLE = (
    (r"3\.1\.2-r0", "3.10"),
    (r"3\.2\.0-r3", "3.11"),
    (r"3\.2\.0-r[67]", "3.12"),
    (r"3\.2\.0-r8", "3.13"),
    (r"3\.2\.0-r1[56]", "3.14"),
    (r"3\.2\.0-r18", "3.15"),
    (r"3\.2\.0-r2[0-3]", "3.16"),
    (r"3\.4\.0-r0", "3.17"),
    (r"3\.4\.3-r1", "3.18"),
    (r"3\.4\.3-r2", "3.19"),
    (r"3\.6\.5-r0", "3.20"),
    (r"3\.6\.8-r[01]", "3.21"))


def guess_alpine_version(pkg, version):
    if pkg == "alpine-baselayout":
        for pattern, alpine_version in ALPINE_MATCH_TABLE:
            if re.match(pattern, version):
                return ("Alpine Linux", alpine_version)


def lst_to_sbom(format, package_list, output_file):
    packages = open(package_list)
    data = []
    ancestor = None

    pwd = os.getcwd()

    for line in packages:
        if line.strip() == "" or line.strip().startswith("#"):
            continue

        if format == "apk" and "{" in line and "|" not in line:
            bin_pkg, _, src_pkg, _ = line.split(maxsplit=3)
            _, version, rel = bin_pkg.rsplit("-", 2)
            src_version = version + "-" + rel
            src_pkg = src_pkg.strip("{}")
        else:
            src_pkg, src_version, _, _ = line.split("|")

        if format == "deb" and "signed" in src_pkg:
            src_pkg, src_version = map_signed_packages(src_pkg, src_version)

        os_version = None
        if format == "apk" and src_pkg == "alpine-baselayout":
            os_version = guess_alpine_version(src_pkg, src_version)
        if format == "deb" and src_pkg == "base-files":
            os_version = ("Debian", src_version[0:2])
        if os_version:
            print("Detected", " ".join(os_version))
            if ancestor and os_version != ancestor:
                print("WARNING: Detected multiple OS versions.")
            ancestor = os_version

        if format == "deb":
            namespace = "debian"
        elif format == "apk":
            namespace = "alpine"
        else:
            print("Unknown format", format)
            sys.exit(1)

        purl = PackageURL(type=format, namespace=namespace,
                          name=src_pkg, version=src_version,
                          qualifiers={'arch': 'source'})
        entry = {
            "type": "library",
            "name": src_pkg,
            "version": src_version + "." + namespace,
            "purl": purl.to_string()}
        if entry not in data:
            data.append(entry)

    os.chdir(pwd)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "operating-system",
                "name": os.path.basename(package_list)},
            "tools": [
                {
                    "vendor": "Siemens AG",
                    "name": "capywfa",
                    "version": importlib.metadata.version("capywfa"),
                    "externalReferences": [{
                        "type": "website",
                        "url": "https://github.com/sw360/capywfa"}]
                }]},
        "components": data}

    if ancestor:
        bom["metadata"]["component"]["pedigree"] = {
            "ancestors": [{
                "type": "operating-system",
                "name": ancestor[0],
                "version": ancestor[1]}]}

    bom_file = open(output_file, "w")
    json.dump(bom, bom_file, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="convert Linux package list to CycloneDX format",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("format", help="Can be 'deb' or 'apk'")
    parser.add_argument("package_list", help="Linux package_list")
    parser.add_argument("output_file", help="SBOM output file")
    args = parser.parse_args()

    lst_to_sbom(format=args.format, package_list=args.package_list,
                output_file=args.output_file)


if __name__ == "__main__":
    main()
