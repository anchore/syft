#!/usr/bin/env python3
import os
import sys
import json
import collections

QUALITY_GATE_THRESHOLD = 0.95
INDENT = "    "
IMAGE_QUALITY_GATE = collections.defaultdict(lambda: QUALITY_GATE_THRESHOLD, **{

})

# We additionally fail if an image is above a particular threshold. Why? We expect the lower threshold to be 90%,
# however additional functionality in grype is still being implemented, so this threshold may not be able to be met.
# In these cases the IMAGE_QUALITY_GATE is set to a lower value to allow the test to pass for known issues. Once these
# issues/enhancements are done we want to ensure that the lower threshold is bumped up to catch regression. The only way
# to do this is to select an upper threshold for images with known threshold values, so we have a failure that
# loudly indicates the lower threshold should be bumped.
IMAGE_UPPER_THRESHOLD = collections.defaultdict(lambda: 1, **{

})
Metadata = collections.namedtuple("Metadata", "version")
Package = collections.namedtuple("Package", "name type")


class InlineScan:

    report_tmpl = "{image}-{report}.json"

    def __init__(self, image, report_dir="./"):
        self.report_dir = report_dir
        self.image = image

    def packages(self):
        python_packages, python_metadata = self._python_packages()
        gem_packages, gem_metadata = self._gem_packages()
        os_packages, os_metadata = self._os_packages()
        return python_packages | os_packages | gem_packages , {**python_metadata, **os_metadata, **gem_metadata}

    def _report_path(self, report):
        return os.path.join(
            self.report_dir,
            self.report_tmpl.format(image=self.image.replace(":", "_"), report=report),
        )

    def _enumerate_section(self, report, section):
        report_path = self._report_path(report=report)
        os_report_path = self._report_path(report="content-os")

        if os.path.exists(os_report_path) and not os.path.exists(report_path):
            # if the OS report is there but the target report is not, that is engine's way of saying "no findings"
            return

        with open(report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    def _python_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(
            report="content-python", section="content"
        ):
            package = Package(name=entry["package"], type=entry["type"].lower(),)
            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])

        return packages, metadata

    def _gem_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(
                report="content-gem", section="content"
        ):
            package = Package(name=entry["package"], type=entry["type"].lower(),)
            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])

        return packages, metadata

    def _os_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-os", section="content"):
            package = Package(name=entry["package"], type=entry["type"].lower())
            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])

        return packages, metadata


class Syft:

    report_tmpl = "{image}.json"

    def __init__(self, image, report_dir="./"):
        self.report_path = os.path.join(
            report_dir, self.report_tmpl.format(image=image.replace(":", "_"))
        )

    def _enumerate_section(self, section):
        with open(self.report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    def packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(section="artifacts"):

            # normalize to inline
            pkg_type = entry["type"].lower()
            if pkg_type in ("wheel", "egg"):
                pkg_type = "python"
            elif pkg_type in ("deb",):
                pkg_type = "dpkg"
            elif pkg_type in ("java-archive",):
                pkg_type = "java"
            elif pkg_type in ("apk",):
                pkg_type = "apkg"

            package = Package(name=entry["name"], type=pkg_type,)

            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])
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


def main(image):
    print(colors.bold+"Image:", image, colors.reset)

    inline = InlineScan(image=image, report_dir="inline-reports")
    inline_packages, inline_metadata = inline.packages()

    syft = Syft(image=image, report_dir="syft-reports")
    syft_packages, syft_metadata = syft.packages()

    if len(inline_packages) == 0:
        # we are purposefully selecting test images that are guaranteed to have packages, so this should never happen
        print(colors.bold + colors.fg.red + "inline found no packages!", colors.reset)
        return 1

    if len(syft_packages) == 0 and len(inline_packages) == 0:
        print("nobody found any packages")
        return 0

    same_packages = syft_packages & inline_packages
    percent_overlap_packages = (
        float(len(same_packages)) / float(len(inline_packages))
    ) * 100.0

    bonus_packages = syft_packages - inline_packages
    missing_packages = inline_packages - syft_packages

    inline_metadata_set = set()
    for package in inline_packages:
        metadata = inline_metadata[package.type][package]
        inline_metadata_set.add((package, metadata))

    syft_overlap_metadata_set = set()
    for package in syft_packages:
        metadata = syft_metadata[package.type][package]
        # we only want to really count mismatched metadata for packages that are at least found by inline
        if package in inline_metadata.get(package.type, []):
            syft_overlap_metadata_set.add((package, metadata))

    same_metadata = syft_overlap_metadata_set & inline_metadata_set
    percent_overlap_metadata = (
        float(len(same_metadata)) / float(len(inline_metadata_set))
    ) * 100.0
    missing_metadata = inline_metadata_set - same_metadata

    if bonus_packages:
        rows = []
        print(colors.bold + "Syft found extra packages:", colors.reset)
        for package in sorted(list(bonus_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    if missing_packages:
        rows = []
        print(colors.bold + "Syft missed packages:", colors.reset)
        for package in sorted(list(missing_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    if missing_metadata:
        rows = []
        print(colors.bold + "Syft mismatched metadata:", colors.reset)
        for inline_metadata_pair in sorted(list(missing_metadata)):
            pkg, metadata = inline_metadata_pair
            if pkg in syft_metadata[pkg.type]:
                syft_metadata_item = syft_metadata[pkg.type][pkg]
            else:
                syft_metadata_item = "--- MISSING ---"
            rows.append([INDENT, "for:", repr(pkg), ":", repr(syft_metadata_item), "!=", repr(metadata)])
        print_rows(rows)
        print()

    print(colors.bold+"Summary:", colors.reset)
    print("   Image: %s" % image)
    print("   Inline Packages : %d" % len(inline_packages))
    print("   Syft Packages   : %d" % len(syft_packages))
    print("         (extra)   : %d" % len(bonus_packages))
    print("       (missing)   : %d" % len(missing_packages))
    print(
        "   Baseline Packages Matched: %2.3f %% (%d/%d packages)"
        % (percent_overlap_packages, len(same_packages), len(inline_packages))
    )
    print(
        "   Baseline Metadata Matched: %2.3f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(inline_metadata_set))
    )

    overall_score = (percent_overlap_packages + percent_overlap_metadata) / 2.0

    print(colors.bold + "   Overall Score: %2.1f %%" % overall_score, colors.reset)

    upper_gate_value = IMAGE_UPPER_THRESHOLD[image] * 100
    lower_gate_value = IMAGE_QUALITY_GATE[image] * 100
    if overall_score < lower_gate_value:
        print(colors.bold + "   Quality Gate: " + colors.fg.red + "FAILED (is not >= %d %%)\n" % lower_gate_value, colors.reset)
        return 1
    elif overall_score > upper_gate_value:
        print(colors.bold + "   Quality Gate: " + colors.fg.orange + "FAILED (lower threshold is artificially low and should be updated)\n", colors.reset)
        return 1
    else:
        print(colors.bold + "   Quality Gate: " + colors.fg.green + "pass (>= %d %%)\n" % lower_gate_value, colors.reset)

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
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
