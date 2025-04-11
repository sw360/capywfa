#!/usr/bin/python3

# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
# SPDX-FileContributor: Gernot Hillier <gernot.hillier@siemens.com>
#
# SPDX-License-Identifier: MIT

import argparse
import textwrap
import sys
import os
import datetime
import logging  # otherwise CaPyCli functions will print all HTTP requests
import urllib3

from capycli.bom.map_bom import MapBom
from capycli.common.capycli_bom_support import (CaPyCliBom, CycloneDxSupport,
                                                SbomWriter)
from capycli.common.json_support import write_json_to_file
from capycli.common.map_result import MapResult
from capywfa.verify_sources import verify_sources
from capycli.bom.create_components import BomCreateComponents
from capycli.project.create_project import CreateProject
from cyclonedx.model import ExternalReferenceType
from capywfa.cdx_support import get_cdx, set_cdx, legacy_to_cdx_prop

args = None


def write_bom(bom, outputname, check_length=True):
    prefix = datetime.datetime.now(tz=None).isoformat(timespec="seconds")
    prefix = prefix.replace(":", "-")[:19]
    outputdirname, outputfilename = os.path.split(outputname)
    if (outputfilename.startswith("20") and outputfilename[10] == "T"
            and outputfilename[19] == "_"):
        outputfilename = outputfilename[20:]  # strip old timestamp
    outputfilename = prefix + "_" + outputfilename
    outputname = os.path.join(outputdirname, outputfilename)
    print("Writing result to", outputname)

    bom.dependencies = None
    SbomWriter.write_to_json(bom, outputname, pretty_print=True)

    if check_length and len(bom.components) != nr_components:
        print(file=sys.stderr)
        print("ERROR: SBOM length has changed from", nr_components,
              "to", len(bom.components), file=sys.stderr)
        sys.exit(1)

    return outputname


def confirm(text):
    if args.noninteractive:
        return None
    else:
        return input(text)


def get_all_components(sw360_client):
    filename = "sw360-components.json"
    if os.path.exists(filename):
        print(filename, "exists. To update, please delete and press ENTER.")
        if confirm() is None:
            return

    if os.path.exists(filename):
        return
    components = sw360_client.get_all_components()
    for comp in components:
        href = comp["_links"]["self"]["href"]
        comp['ComponentId'] = sw360_client.get_id_from_href(href)

    write_json_to_file(components, filename)
    print(filename, "written.")


def pass1_map_bom(bom, sw360_url, sw360_token):
    mapper = MapBom()
    # we don't want relaxed_debian_parsing here as capycli would then ignore
    # Debian suffices (SW360 release 1.3.4 matches Debian version 1.3.4-2)
    mapper.relaxed_debian_parsing = False
    mapper.login(token=sw360_token, url=sw360_url,
                 oauth2=(len(sw360_token) > 100))
    result = mapper.map_bom_to_releases(bom, check_similar=False,
                                        result_required=False, nocache=True)
    result = mapper.create_updated_bom(bom, result)
    # filter out version candidates
    result.components = [
        item for item in result.components
        if get_cdx(item, "MapResult") not in (
            MapResult.MATCH_BY_NAME, MapResult.SIMILAR_COMPONENT_FOUND)]
    return result


def pass3_download_sources(bom):
    for item in bom.components:
        if not (get_cdx(item, "MapResult") == MapResult.NO_MATCH
                or (MapBom.is_good_match(get_cdx(item, "MapResult"))
                    and get_cdx(item, "Sw360SourceFileChecked") != "true")):
            set_cdx(item, "SourceFileDownload", "skip")
    return bom


def pass4_create_releases(bom, sw360_url, sw360_token, pkg_dir,
                          only_releases=True):
    # note that BomCreateComponents will modify bom!
    creator = BomCreateComponents(onlyCreateReleases=only_releases)
    creator.relaxed_debian_parsing = True
    creator.download = False
    creator.source_folder = pkg_dir

    creator.login(token=sw360_token, url=sw360_url,
                  oauth2=(len(sw360_token) > 100))

    todo_bom = bom
    if only_releases:
        todo_bom.components = [
            item for item in bom.components
            if get_cdx(item, "SourceFileDownload") != "failed"]
    else:
        todo_bom.components = [
            item for item in bom.components
            if get_cdx(item, "MapResult") == MapResult.NO_MATCH
            and get_cdx(item, "SourceFileDownload") != "failed"
            and get_cdx(item, "ComponentId", "") == ""
            and get_cdx(item, "Categories")
            and CycloneDxSupport.get_ext_ref_website(item)
            and item.description]

    try:
        creator.create_items(todo_bom)
    except SystemExit as e:
        print("WARNING: capycli called sys.exit():", e)
    return creator.client, todo_bom


def pass4_update_bom(bom, todo_bom, what):
    # merge Ids from updated entries
    print()
    count = 0
    for item in bom.components:
        if item.purl and (
                get_cdx(item, "MapResult") != MapResult.FULL_MATCH_BY_ID
                or get_cdx(item, "Sw360Id", "") == ""):
            for i2 in todo_bom.components:
                if (i2.purl == item.purl
                        and get_cdx(i2, "Sw360Id")):
                    if item.version != i2.version:
                        print("ERROR:", item.name, "SW360 data mismatch")
                        print("- SW360 version", i2.version)
                        print("- BOM version  ", item.version)
                        print("Please check",
                              args.url
                              + "/group/guest/components/-/component/release/"
                              + "detailRelease/" + get_cdx(i2, "Sw360Id"))
                        print()
                        continue

                    set_cdx(item, "Sw360Id", get_cdx(i2, "Sw360Id"))
                    set_cdx(item, "MapResult", MapResult.FULL_MATCH_BY_ID)
                    set_cdx(item, "Comment", "new_" + what)
                    count += 1
                    break
    print(count, "new", what + "s.")
    return bom


def pass6_link_releases(bom, sw360_url, sw360_token, project_id, minus_id):
    linker = CreateProject(onlyUpdateProject=True)
    linker.login(token=sw360_token, url=sw360_url,
                 oauth2=(len(sw360_token) > 100))
    linker.project_id = project_id

    todo_bom = bom
    todo_bom.components = [
        item for item in bom.components
        if get_cdx(item, "Sw360Id")
        and (get_cdx(item, "MapResult") == MapResult.NO_MATCH
             or MapBom.is_good_match(get_cdx(item, "MapResult")))
        and get_cdx(item, "Sw360SourceFileChecked") == "true"]
    print("Found", len(todo_bom.components), "releases to link.")

    if minus_id is not None:
        minus_proj = linker.client.get_project(minus_id)
        minus_releases = minus_proj["_embedded"].get("sw360:releases", [])
        minus_releases = [r["_links"]["self"]["href"]
                          for r in minus_releases]
        minus_releases = [linker.client.get_id_from_href(r)
                          for r in minus_releases]
        print("Loaded", len(minus_releases), "releases from minus project:",
              minus_proj["name"], minus_proj["version"])
        todo_bom.components = [
            item for item in todo_bom.components
            if get_cdx(item, "Sw360Id") not in minus_releases]
        print(len(todo_bom.components), "releases left to link.")

    if project_id is not None:
        project = linker.client.get_project(project_id)
        print("Target project:", project["name"], project["version"])
        filename = "project-backup-"+project_id+".json"
        write_json_to_file(project, filename)
        print("-> saved project backup to", filename)
        linker.update_project(project_id, project, todo_bom, project_info=None)
    else:
        print("WARNING: no target project given, not linking anything.")
    return todo_bom


# avoid urllib3 warnings
class SuppressFilter(logging.Filter):
    def filter(self, record):
        return 'NoBoundaryInMultipartDefect' not in record.getMessage()


def main():
    global args, nr_components
    urllib3.connectionpool.log.addFilter(SuppressFilter())
    parser = argparse.ArgumentParser(
            description="CaPyWfa - Clearing Automation WorkFlow Acccelerator for SW360",
            formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "-i", "--input", required=True, help=textwrap.dedent(
            """package list in CycloneDX format"""))
    parser.add_argument(
        "-s", "--sources", required=True, help=textwrap.dedent(
            """directory containing source archives."""))
    parser.add_argument(
        "-u", "--url", default="https://sw360.siemens.com",
        help=textwrap.dedent(
            """SW360 instance to use"""))
    parser.add_argument(
        "-t", "--token", required=True, help=textwrap.dedent(
            """SW360 auth token string. If the token is longer than 100
            characters, it's regarded as OAuth token."""))
    parser.add_argument(
        "-vf", "--trusted-verifiers", metavar="EMAIL", nargs="+", required=True,
        help=textwrap.dedent(
            """Attachments approved by these users will be trusted without
            content checks.""")),
    parser.add_argument(
        "--id", help=textwrap.dedent(
            """SW360 id of the target project."""))
    parser.add_argument(
        "--minus_id", help=textwrap.dedent(
            """SW360 id of a reference project. Only releases NOT in the
            project MINUS_ID will be linked to target project ID."""))
    parser.add_argument(
        "--noninteractive", action="store_true", help=textwrap.dedent(
            """Don't wait for user confirmation after each step. This shall
            only be used for well-tested workloads, e.g. in CI pipelines.
            You have been warned."""))
    parser.add_argument(
        "--remap", action="store_true", help=textwrap.dedent(
            """Force complete remapping (pass 1) for a BOM which already
            contains `MapResult`s."""))

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print("ERROR: inputfile not found:", args.input)
        sys.exit(1)

    filename, extension = os.path.splitext(args.input)
    bom = CaPyCliBom.read_sbom(args.input)
    print()
    print("Read", len(bom.components), "entries from", args.input+".")
    bom.components = [
        item for item in bom.components
        if get_cdx(item, "MapResult") not in (
            MapResult.MATCH_BY_NAME, MapResult.SIMILAR_COMPONENT_FOUND)]
    nr_components = len(bom.components)
    print(nr_components, "entries after filtering out version candidates.")
    if nr_components < 1:
        print("ERROR: empty BOM")
        sys.exit(1)

    print(textwrap.dedent("""
        Upload will happen in six steps. The output is halted after each step,
        so you can check results and interrupt if you want to fix any issues.

        After each step, an updated BOM will be written which stores the
        current state and can be used as input file for the next run.

        Alternatively, you can proceed through all steps and the tool will
        continue with those BOM items which can be handled automatically. A
        summary with all unresolved issues will be presented at the end -
        however, it might be a good idea to log the full output.
        """))
    confirm("Press ENTER to continue or CTRL-C to interrupt.")
    print()
    print("== Pass 1: Mapping BOM to SW360 ==")
    print()
    if get_cdx(bom.components[0], "MapResult") and not args.remap:
        print("BOM seems to contain MapResults, skipping...")
    else:
        bom = pass1_map_bom(bom, args.url, args.token)
        write_bom(bom, filename+"-1-map"+extension)

    print()

    print("Release matches in SW360:",
          len([item for item in bom.components
               if MapBom.is_good_match(get_cdx(item, "MapResult"))]))
    print("Component (purl) matches in SW360:",
          len([item for item in bom.components
               if get_cdx(item, "MapResult") == MapResult.NO_MATCH
               and get_cdx(item, "ComponentId")]))
    print("Packages not found in SW360:",
          len([item for item in bom.components
               if get_cdx(item, "MapResult") == MapResult.NO_MATCH
               and get_cdx(item, "ComponentId", "") == ""]))

    print()
    print("== Pass 2: Verify SW360 sources (quick) ==")
    print()

    if get_cdx(bom.components[0], "Sw360SourceFileChecked") and not args.remap:
        print("BOM seems to contain check results, skipping...")
    else:
        # without pkg_dir, it will only verify SW360's attachment `checkStatus`
        confirm("Press ENTER to continue or CTRL-C to interrupt.")
        bom = verify_sources(bom, args.url, args.token,
                             trusted_verifiers=args.trusted_verifiers, pkg_dir=None)
        write_bom(bom, filename+"-2-sourceverify-quick"+extension)

    print()
    print("Verified sources:",
          len([item for item in bom.components
              if get_cdx(item, "Sw360SourceFileChecked") == "true"]))

    print()
    print("== Pass 3: Download missing and unchecked sources ==")
    print()

    bom = pass3_download_sources(bom)
    outputbom = write_bom(bom, filename+"-3-download"+extension)
    missing_source_count = len(
        [item for item in bom.components
         if not get_cdx(item, "SourceFileComment")
         and get_cdx(item, "SourceFileDownload") not in ("skip", "failed")])
    if missing_source_count > 0:
        print("Please download", missing_source_count, "missing sources")
        sys.exit(80)
    else:
        print("All missing sources downloaded.")

    print()
    print("== Pass 4a: Create releases ==")
    print()
    confirm("Press ENTER to continue or CTRL-C to interrupt.")

    _, p4_bom = pass4_create_releases(bom, args.url, args.token,
                                      args.sources, only_releases=True)

    # read previous bom and merge creation results into it
    bom = CaPyCliBom.read_sbom(outputbom)
    bom = pass4_update_bom(bom, p4_bom, "release")
    outputbom = write_bom(bom, filename+"-4a-createreleases"+extension)

    print("== Pass 4b: Create components ==")
    print()
    confirm("Press ENTER to continue or CTRL-C to interrupt.")

    sw360_client, p4_bom = pass4_create_releases(bom, args.url, args.token,
                                                 args.sources,
                                                 only_releases=False)
    # read previous bom and merge creation results into it
    bom = CaPyCliBom.read_sbom(outputbom)
    bom = pass4_update_bom(bom, p4_bom, "component")
    outputbom = write_bom(bom, filename+"-4b-createcomponents"+extension)

    print()
    print("== Pass 5: Verify SW360 sources (complete) ==")
    print()

    missing_verification_count = len(
        [item for item in bom.components
         if MapBom.is_good_match(get_cdx(item, "MapResult"))
         and get_cdx(item, "Sw360SourceFileChecked") != "true"])

    if missing_verification_count == 0:
        print("Verified all existing sources.")
    else:
        if os.path.exists("verify"):
            print(textwrap.dedent("""
                WARNING: verify/ subdirectory exists, please delete to verify
                SW360 sources or just press Enter to skip verification.
                """))

        confirm("Press ENTER to continue or CTRL-C to interrupt.")

        if not os.path.exists("verify"):
            os.mkdir("verify")

            bom = verify_sources(bom, args.url, args.token, pkg_dir=args.sources,
                                 trusted_verifiers=args.trusted_verifiers)
            outputbom = write_bom(bom, filename+"-5-sourceverify"+extension)

    print()
    print("Verified sources:",
          len([item for item in bom.components
              if get_cdx(item, "Sw360SourceFileChecked") == "true"]))
    print("Invalid sources:",
          len([item for item in bom.components
              if MapBom.is_good_match(get_cdx(item, "MapResult"))
              and get_cdx(item, "Sw360SourceFileChecked") != "true"]))

    print()
    print("== Pass 6: Link releases ==")
    print()

    if args.id is None and args.minus_id is None:
        print("No project id given, skipping linking step.")
    else:
        confirm("Press ENTER to continue or CTRL-C to interrupt.")
        linked_bom = pass6_link_releases(bom, args.url, args.token,
                                         args.id, args.minus_id)
        write_bom(linked_bom, filename+"-6-linked"+extension, check_length=False)
        # restore full bom as pass6 will modify bom
        bom = CaPyCliBom.read_sbom(outputbom)
        print()
    if args.id is not None:
        print(len(linked_bom.components),
              "releases ready and linked to project.")

    print()
    print("== Summary ==")
    print()

    problem = False
    todo_unmapped = [item for item in bom.components
                     if get_cdx(item, "MapResult") == MapResult.NO_MATCH
                     and not get_cdx(item, "Sw360Id")
                     and not get_cdx(item, "ComponentId")]
    if len(todo_unmapped) > 0:
        print(len(todo_unmapped), "components couldn't be found in SW360.")
        print(textwrap.dedent("""
            Please check the following entries in BOM or in SW360 and:
            - add property %s of existing SW360 component in latest full BOM
            - OR add `package-url` in SW360 and re-run with `--remap`
            - OR add `description`, ext ref %s, and property %s to BOM to
              create new SW360 component
            """ % (
                legacy_to_cdx_prop["ComponentId"],
                ExternalReferenceType.WEBSITE,
                legacy_to_cdx_prop["Categories"]
                )))
        print("Unmapped BOM components:")
        for item in todo_unmapped:
            print("-", item.name, item.version)
        print()
        choice = confirm("Download list of all SW360 components (y=yes)? ")
        if choice == "y":
            get_all_components(sw360_client)
        problem = True

    todo_download = [item for item in bom.components
                     if get_cdx(item, "SourceFileDownload") == "failed"]
    if len(todo_download) > 0:
        print(len(todo_download), "sources couldn't be downloaded.")
        print(textwrap.dedent("""
            Please check the BOM items and re-run download script.
            """))
        print("BOM items with download failures:")
        for item in todo_download:
            print("-", item.name, item.version)
        print()
        problem = True

    todo_unmapped = [item for item in bom.components
                     if not MapBom.is_good_match(get_cdx(item, "MapResult"))
                     and get_cdx(item, "ComponentId")
                     and get_cdx(item, "SourceFileDownload") != "failed"]
    if len(todo_unmapped) > 0:
        print(len(todo_unmapped), "releases couldn't be mapped in SW360.")
        print(textwrap.dedent("""
            This might happen if a release exists, but differs in purl or
            version. Check output above for more information.
            """))
        print("Unmapped releases:")
        for item in todo_unmapped:
            print("-", item.name, item.version)
        print()
        problem = True

    todo_unchecked = [item for item in bom.components
                      if MapBom.is_good_match(get_cdx(item, "MapResult"))
                      and get_cdx(item, "Sw360SourceFileChecked") != "true"
                      and get_cdx(item, "SourceFileDownload") != "failed"]
    if len(todo_unchecked) > 0:
        print(len(todo_unchecked), "SW360 sources couldn't be verified.")
        print(textwrap.dedent("""
            Please check the differences in `verify` folder and set attachment
            to DENIED or ACCEPTED in SW360, then re-run.
            """))
        print("BOM items with attachment differences:")
        for item in todo_unchecked:
            print("-", item.name, item.version,
                  args.url + "/group/guest/components/-/component/release/"
                  "detailRelease/"
                  + get_cdx(item, "Sw360Id")+"#/tab-Attachments")
        print()
        problem = True

    if problem:
        print(textwrap.dedent("""
            After fixing the issues, please re-run this tool. If you modified
            releases or purls in SW360, use `--remap`.

            Please use latest full BOM for the next run:

            """)+sys.argv[0]+' -i "'+outputbom+'" ...')
        sys.exit(81)
    else:
        print("Congratulations, BOM completely uploaded to SW360!")


if __name__ == "__main__":
    main()
