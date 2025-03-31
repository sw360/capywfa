#!/usr/bin/python3

# SPDX-FileCopyrightText: 2019-2025 Siemens
# SPDX-FileCopyrightText: 2019-2025 Siemens Healthineers
# SPDX-FileContributor: Gernot Hillier <gernot.hillier@siemens.com>
#
# SPDX-License-Identifier: MIT
# See top-level LICENSE file for details.
#
# Verify uploaded sources in SW360 are identical to local ones.
#
# Note this is vulnerable against archives with absolute or relative ../../
# paths. Use in virtual environments only (at your own risk).

import os
import subprocess
import shutil
import glob
import requests
import argparse
from datetime import datetime
from sw360 import SW360, SW360Error
from capywfa.cdx_support import get_cdx, set_cdx
from capycli.common.capycli_bom_support import CaPyCliBom, CycloneDxSupport
from capycli.common.map_result import MapResult


def unpack(archive, target_dir):
    # TODO: inspect content to avoid overwriting files outside target_dir
    if archive.endswith(".gem"):
        shutil.unpack_archive(archive, target_dir, "tar")
        data_tar = os.path.join(target_dir, "data.tar.gz")
        all_tars = glob.glob(target_dir+"/*")
        data_target_dir = os.path.join(target_dir, "data")
        shutil.unpack_archive(data_tar, data_target_dir)
        for tar in all_tars:
            os.remove(tar)
    else:
        shutil.unpack_archive(archive, target_dir)


def set_check_status(sw360, release_id, source, attachment_id):
    min_days = int(os.environ.get("DAYS_BEFORE_SRC_ACCEPT", "14"))
    try:
        created_on = datetime.strptime(source['createdOn'], "%Y-%m-%d")
    except ValueError:
        print("-> Couldn't set checkStatus (error parsing createdOn).")
        return

    if (datetime.now() - created_on).days < min_days:
        print("-> New upload by", source['createdBy'],
              "on", source['createdOn'],
              "- won't set checkStatus yet.")
        return

    # workaround for https://github.com/sw360/sw360python/issues/1
    r = requests.patch(
            sw360.url+"/resource/api/releases/"
            + release_id + "/attachment/" + attachment_id,
            headers=sw360.api_headers,
            json={"checkStatus": "ACCEPTED"})
    if not r.ok:
        print("Error in setting checkStatus:", r.text)
    else:
        print("-> checkStatus set to ACCEPTED.")


def verify_sources(bom, sw360_url, sw360_token, trusted_verifiers,
                   pkg_dir=None):
    if len(sw360_token) > 100:
        oauth2 = True
    else:
        oauth2 = False
    sw360 = SW360(sw360_url, sw360_token, oauth2=oauth2)

    sw360.login_api()

    for item in bom.components:
        print()
        if get_cdx(item, "Sw360SourceFileChecked") == "true":
            print("Skipping", item.name, item.version,
                  "- already checked")
            continue

        set_cdx(item, "Sw360SourceFileChecked", "false")

        if get_cdx(item, "MapResult") in (MapResult.MATCH_BY_NAME,
                                          MapResult.NO_MATCH):
            print("Skipping", item.name, item.version,
                  "- MapResult is", get_cdx(item, "MapResult"))
            continue

        if get_cdx(item, "SourceFileDownload") == "failed":
            print("Skipping", item.name, item.version,
                  "- Debian download failed")
            continue

        sw360id = get_cdx(item, "Sw360Id")
        if not sw360id:
            print("ERROR: no sw360id in BOM!")
            continue
        release = sw360.get_release(sw360id)

        attachments = release.get("_embedded", {}).get("sw360:attachments", [])
        sources = []
        for ata in attachments:
            if ata["attachmentType"] not in ("SOURCE", "SOURCE_SELF"):
                continue
            info = sw360.get_attachment_by_url(ata["_links"]["self"]["href"])
            if info.get("checkStatus", "") != "REJECTED":
                sources.append(info)

        if len(sources) != 1:
            print("ERROR:", len(sources), "sources found")
            set_cdx(item, "Sw360SourceFileChecked", "multiple sources")
            continue

        attachment_id = sources[0]['_links']['self']['href']
        attachment_id = sw360.get_id_from_href(attachment_id)

        print("checking", item.name, "release", sw360id,
              "- attachment", attachment_id)
        # print("createdBy:", sources[0]['createdBy'],
        #       "on", sources[0]['createdOn'])
        checkedby = sources[0].get('checkedBy', "")
        # print("checkStatus:", sources[0]['checkStatus'], "by", checkedby)
        if (sources[0]['checkStatus'] == 'ACCEPTED'
                and checkedby in trusted_verifiers):
            set_cdx(item, "Sw360SourceFileChecked", "true")
            print("OK: Trusted verifier", checkedby,
                  "approved on", sources[0].get('checkedOn'))
            continue

        source_ext_ref = CycloneDxSupport.get_ext_ref_source_file(item)
        if (not source_ext_ref or pkg_dir is None):
            print("WARNING: no sources available, skipping check")
            continue

        if sources[0]['sha1'] == CycloneDxSupport.get_source_file_hash(item):
            set_cdx(item, "Sw360SourceFileChecked", "true")
            print("OK: Hash match.")
            set_check_status(sw360, sw360id, sources[0], attachment_id)
            continue

        sw360_file = sources[0]['filename']
        sw360_path = os.path.join("verify", sw360_file)
        try:
            sw360.download_attachment(
                sw360_path,
                sources[0]['_links']['sw360:downloadLink']['href'])
        except SW360Error as err:
            print("ERROR during SW360 download", err)
            continue
        sw360_unpack_path = "verify/sw360-"+sw360_file+"-unzip"
        os.mkdir(sw360_unpack_path)
        unpack(sw360_path, sw360_unpack_path)
        found = glob.glob(os.path.join(sw360_unpack_path, "*"))
        while len(found) == 1:
            sw360_unpack_path = found[0]
            found = glob.glob(os.path.join(sw360_unpack_path, "*"))

        our_file = str(source_ext_ref)
        our_path = os.path.join(pkg_dir, our_file)
        if not os.path.exists(our_path):
            print("ERROR - local Debian source missing!")
            continue
        our_unpack_path = "verify/local-" + our_file + "-unzip"
        os.mkdir(our_unpack_path)
        unpack(our_path, our_unpack_path)
        found = glob.glob(os.path.join(our_unpack_path, "*"))
        while len(found) == 1:
            our_unpack_path = found[0]
            found = glob.glob(os.path.join(our_unpack_path, "*"))

        ret = subprocess.call(
            "diff -qur "+our_unpack_path+" "+sw360_unpack_path,
            shell=True)
        if ret == 0:
            print("OK:", sw360_file, "identical to", our_file)
            set_cdx(item, "Sw360SourceFileChecked", "true")
            shutil.rmtree("verify/local-"+our_file+"-unzip")
            shutil.rmtree("verify/sw360-"+sw360_file+"-unzip")
            os.remove("verify/"+sw360_file)
            set_check_status(sw360, sw360id, sources[0], attachment_id)

    return bom


def main():
    parser = argparse.ArgumentParser(
        description="Verify uploaded sources in SW360 are identical to local ones.")
    parser.add_argument("-u", "--sw360-url", help="SW360 URL", required=True)
    parser.add_argument("-t", "--sw360_token", help="SW360 token", required=True)
    parser.add_argument("-i", "--input", help="SBOM file in CycloneDX format", required=True)
    parser.add_argument("-s", "--sources", help="package directory containing sources")
    parser.add_argument("-vf", "--trusted-verifiers", help="Trusted attachment verifiers",
                        metavar="EMAIL", nargs="+", required=True)
    args = parser.parse_args()

    bom = CaPyCliBom.read_sbom(args.input)

    os.mkdir("verify")
    verify_sources(bom,
                   sw360_url=args.sw360_url,
                   sw360_token=args.sw360_token,
                   trusted_verifiers=args.trusted_verifiers,
                   pkg_dir=args.sources)


if __name__ == "__main__":
    main()
