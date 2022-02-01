#!/usr/bin/env python3
import sys
import json
import collections

INDENT = "    "


Metadata = collections.namedtuple("Metadata", "metadata sources")
Package = collections.namedtuple("Package", "name type version")


class Syft:
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
                # note: the metadata entry is optional
                metadata=repr(entry.get("metadata", "")), sources=repr(entry["locations"])
            )
        return packages, metadata


def print_rows(rows):
    if not rows:
        return
    widths = []
    for col, _ in enumerate(rows[0]):
        width = max(len(row[col]) for row in rows) + 2  # padding
        widths.append(width)
    for row in rows:
        print("".join(word.ljust(widths[col_idx]) for col_idx, word in enumerate(row)))


def main(baseline_report, new_report):
    report1_obj = Syft(report_path=baseline_report)
    report1_packages, report1_metadata = report1_obj.packages()

    report2_obj = Syft(report_path=new_report)
    report2_packages, report2_metadata = report2_obj.packages()

    if len(report2_packages) == 0 or len(report1_packages) == 0:
        # we are purposefully selecting test images that are guaranteed to have packages, so this should never happen
        print(colors.bold + colors.fg.red + "no packages found!", colors.reset)
        return 1

    same_packages = report2_packages & report1_packages
    percent_overlap_packages = (
        float(len(same_packages)) / float(len(report1_packages))
    ) * 100.0

    extra_packages = report2_packages - report1_packages
    missing_packages = report1_packages - report2_packages

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

    if extra_packages:
        rows = []
        print(colors.bold + "Extra packages:", colors.reset)
        for package in sorted(list(extra_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    if missing_packages:
        rows = []
        print(colors.bold + "Missing packages:", colors.reset)
        for package in sorted(list(missing_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    print(colors.bold+"Summary:", colors.reset)
    print("   Baseline Packages: %d" % len(report1_packages))
    print("   New Packages:      %d" % len(report2_packages))
    print(
        "   Baseline Packages Matched: %.2f %% (%d/%d packages)"
        % (percent_overlap_packages, len(same_packages), len(report1_packages))
    )
    print(
        "   Baseline Metadata Matched: %.2f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(report1_metadata_set))
    )

    if len(report1_packages) != len(report2_packages):
        print(colors.bold + "   Quality Gate: " + colors.fg.red + "FAILED (requires exact name & version match)\n", colors.reset)
        return 1
    else:
        print(colors.bold + "   Quality Gate: " + colors.fg.green + "pass\n", colors.reset)
    return 0


class colors:
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'


if __name__ == "__main__":
    print("\nComparing two Syft reports...\n")
    if len(sys.argv) != 3:
        sys.exit("please provide two Syft json files")

    rc = main(sys.argv[1], sys.argv[2])
    sys.exit(rc)
