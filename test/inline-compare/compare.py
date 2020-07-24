#!/usr/bin/env python3
import os
import sys
import json
import functools
import collections

QUALITY_GATE_THRESHOLD = 0.9

Metadata = collections.namedtuple("Metadata", "version")
Package = collections.namedtuple("Package", "name type")
Vulnerability = collections.namedtuple("Vulnerability", "cve package")


class InlineScan:

    report_tmpl = "{image}-{report}.json"

    def __init__(self, image, report_dir="./"):
        self.report_dir = report_dir
        self.image = image

    def packages(self):
        python_packages, python_metadata = self._python_packages()
        os_pacakges, os_metadata = self._os_packages()
        return python_packages | os_pacakges, {**python_metadata, **os_metadata}

    def _report_path(self, report):
        return os.path.join(
            self.report_dir,
            self.report_tmpl.format(image=self.image.replace(":", "_"), report=report),
        )

    def _enumerate_section(self, report, section):
        report_path = self._report_path(report=report)
        with open(report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    @functools.lru_cache
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

    @functools.lru_cache
    def _os_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-os", section="content"):
            package = Package(name=entry["package"], type=entry["type"].lower())
            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])

        return packages, metadata


class syft:

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

    @functools.lru_cache
    def packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(section="artifacts"):

            # normalize to inline
            pType = entry["type"].lower()
            if pType in ("wheel", "egg"):
                pType = "python"

            package = Package(name=entry["name"], type=pType,)

            packages.add(package)
            metadata[package.type][package] = Metadata(version=entry["version"])
        return packages, metadata


def main(image):
    inline = InlineScan(image=image, report_dir="inline-reports")
    inline_packages, inline_metadata = inline.packages()

    syft = syft(image=image, report_dir="syft-reports")
    syft_packages, syft_metadata = syft.packages()

    if len(syft_packages) == 0 and len(inline_packages) == 0:
        print("nobody found any packages")
        return 0

    same_packages = syft_packages & inline_packages
    percent_overlap_packages = (
        float(len(same_packages)) / float(len(inline_packages))
    ) * 100.0

    bonus_packages = syft_packages - inline_packages
    missing_pacakges = inline_packages - syft_packages

    inline_metadata_set = set()
    for package in inline_packages:
        metadata = inline_metadata[package.type][package]
        inline_metadata_set.add((package, metadata))

    syft_metadata_set = set()
    for package in syft_packages:
        metadata = syft_metadata[package.type][package]
        syft_metadata_set.add((package, metadata))

    same_metadata = syft_metadata_set & inline_metadata_set
    percent_overlap_metadata = (
        float(len(same_metadata)) / float(len(inline_metadata_set))
    ) * 100.0

    if len(bonus_packages) > 0:
        print("syft Bonus packages:")
        for package in sorted(list(bonus_packages)):
            print("    " + repr(package))
        print()

    if len(missing_pacakges) > 0:
        print("syft Missing packages:")
        for package in sorted(list(missing_pacakges)):
            print("    " + repr(package))
        print()

    print("Inline Packages: %d" % len(inline_packages))
    print("syft Packages: %d" % len(syft_packages))
    print()
    print(
        "Baseline Packages Matched: %2.3f %% (%d/%d packages)"
        % (percent_overlap_packages, len(same_packages), len(inline_packages))
    )
    print(
        "Baseline Metadata Matched: %2.3f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(inline_metadata_set))
    )

    overall_score = (percent_overlap_packages + percent_overlap_metadata) / 2.0

    print("Overall Score: %2.3f %%" % overall_score)

    if overall_score < (QUALITY_GATE_THRESHOLD * 100):
        print("failed quality gate (>= %d %%)" % (QUALITY_GATE_THRESHOLD * 100))
        return 1

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
