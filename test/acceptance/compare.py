#!/usr/bin/env python3
import sys
import json
import collections

Metadata = collections.namedtuple("Metadata", "metadata sources")
Package = collections.namedtuple("Package", "name type version")
Vulnerability = collections.namedtuple("Vulnerability", "cve package")


class ImgBom:
    def __init__(self, report_path):
        self.report_path = report_path

    def _enumerate_section(self, section):
        with open(self.report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    def packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(section="artifacts"):
            package = Package(
                name=entry["name"], type=entry["type"], version=entry["version"]
            )

            packages.add(package)
            metadata[package.type][package] = Metadata(
                metadata=repr(entry["metadata"]), sources=repr(entry["sources"])
            )
        return packages, metadata


def main(baseline_report, new_report):
    report1_obj = ImgBom(report_path=baseline_report)
    report1_packages, report1_metadata = report1_obj.packages()

    report2_obj = ImgBom(report_path=new_report)
    report2_packages, report2_metadata = report2_obj.packages()

    if len(report2_packages) == 0 and len(report1_packages) == 0:
        print("nobody found any packages")
        return 0

    same_packages = report2_packages & report1_packages
    percent_overlap_packages = (
        float(len(same_packages)) / float(len(report1_packages))
    ) * 100.0

    extra_packages = report2_packages - report1_packages
    missing_pacakges = report1_packages - report2_packages

    report1_metadata_set = set()
    for package in report1_packages:
        metadata = report1_metadata[package.type][package]
        report1_metadata_set.add((package, metadata))

    report2_metadata_set = set()
    for package in report2_packages:
        metadata = report2_metadata[package.type][package]
        report2_metadata_set.add((package, metadata))

    same_metadata = report2_metadata_set & report1_metadata_set
    percent_overlap_metadata = 0
    if len(report1_metadata_set) > 0:
        percent_overlap_metadata = (
            float(len(same_metadata)) / float(len(report1_metadata_set))
        ) * 100.0

    if len(extra_packages) > 0:
        print("Extra packages:")
        for package in sorted(list(extra_packages)):
            print("    " + repr(package))
        print()

    if len(missing_pacakges) > 0:
        print("Missing packages:")
        for package in sorted(list(missing_pacakges)):
            print("    " + repr(package))
        print()

    print("Baseline Packages: %d" % len(report1_packages))
    print("New Packages:      %d" % len(report2_packages))
    print()
    print(
        "Baseline Packages Matched: %.2f %% (%d/%d packages)"
        % (percent_overlap_packages, len(same_packages), len(report1_packages))
    )
    print(
        "Baseline Metadata Matched: %.2f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(report1_metadata_set))
    )

    if len(report1_packages) != len(report2_packages):
        print("failed quality gate: requires exact name & version match")
        return 1

    return 0


if __name__ == "__main__":
    print("\nComparing two imgbom reports...\n")
    if len(sys.argv) != 3:
        sys.exit("please provide two imgbom json files")

    rc = main(sys.argv[1], sys.argv[2])
    sys.exit(rc)
