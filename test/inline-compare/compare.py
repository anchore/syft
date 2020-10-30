#!/usr/bin/env python3
import os
import sys
import difflib
import collections

import utils.package
from utils.format import Colors, print_rows
from utils.inline import InlineScan
from utils.syft import Syft

DEFAULT_QUALITY_GATE_THRESHOLD = 0.95
INDENT = "    "

PACKAGE_QUALITY_GATE = collections.defaultdict(lambda: DEFAULT_QUALITY_GATE_THRESHOLD, **{})
METADATA_QUALITY_GATE = collections.defaultdict(lambda: DEFAULT_QUALITY_GATE_THRESHOLD, **{
    # syft is better at detecting package versions in specific cases, leading to a drop in matching metadata
    "anchore/test_images:java": 0.61,
    "jenkins/jenkins:2.249.2-lts-jdk11": 0.82,
})

# We additionally fail if an image is above a particular threshold. Why? We expect the lower threshold to be 90%,
# however additional functionality in grype is still being implemented, so this threshold may not be able to be met.
# In these cases the IMAGE_QUALITY_GATE is set to a lower value to allow the test to pass for known issues. Once these
# issues/enhancements are done we want to ensure that the lower threshold is bumped up to catch regression. The only way
# to do this is to select an upper threshold for images with known threshold values, so we have a failure that
# loudly indicates the lower threshold should be bumped.
PACKAGE_UPPER_THRESHOLD = collections.defaultdict(lambda: 1, **{})
METADATA_UPPER_THRESHOLD = collections.defaultdict(lambda: 1, **{
    # syft is better at detecting package versions in specific cases, leading to a drop in matching metadata
    "anchore/test_images:java": 0.65,
    "jenkins/jenkins:2.249.2-lts-jdk11": 0.84,
})


def report(image, analysis):
    if analysis.extra_packages:
        rows = []
        print(
            Colors.bold + "Syft found extra packages:",
            Colors.reset,
            "Syft discovered packages that Inline did not",
        )
        for package in sorted(list(analysis.extra_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    if analysis.missing_packages:
        rows = []
        print(
            Colors.bold + "Syft missed packages:",
            Colors.reset,
            "Inline discovered packages that Syft did not",
        )
        for package in sorted(list(analysis.missing_packages)):
            rows.append([INDENT, repr(package)])
        print_rows(rows)
        print()

    if analysis.missing_metadata:
        print(
            Colors.bold + "Syft mismatched metadata:",
            Colors.reset,
            "the packages between Syft and Inline are the same, the metadata is not",
        )
        for inline_metadata_pair in sorted(list(analysis.missing_metadata)):
            pkg, metadata = inline_metadata_pair
            if pkg not in analysis.syft_data.metadata[pkg.type]:
                continue
            syft_metadata_item = analysis.syft_data.metadata[pkg.type][pkg]

            diffs = difflib.ndiff([repr(syft_metadata_item)], [repr(metadata)])

            print(INDENT + "for: " + repr(pkg), "(top is syft, bottom is inline)")
            print(INDENT+INDENT+("\n"+INDENT+INDENT).join(list(diffs)))

        if not analysis.missing_metadata:
            print(
                INDENT,
                "There are mismatches, but only due to packages Syft did not find (but inline did).\n",
            )

    if analysis.similar_missing_packages:
        rows = []
        print(
            Colors.bold + "Probably pairings of missing/extra packages:",
            Colors.reset,
            "to aid in troubleshooting missed/extra packages",
        )
        for similar_packages in analysis.similar_missing_packages:
            rows.append(
                [
                    INDENT,
                    repr(similar_packages.pkg),
                    "--->",
                    repr(similar_packages.missed),
                ]
            )
        print_rows(rows)
        print()

    show_probable_mismatches = analysis.unmatched_missing_packages and analysis.extra_packages and len(analysis.unmatched_missing_packages) != len(analysis.missing_packages)

    if show_probable_mismatches:
        rows = []
        print(
            Colors.bold + "Probably missed packages:",
            Colors.reset,
            "a probable pair was not found",
        )
        for p in analysis.unmatched_missing_packages:
            rows.append([INDENT, repr(p)])
        print_rows(rows)
        print()

    print(Colors.bold + "Summary:", Colors.reset, image)
    print("   Inline Packages : %d" % len(analysis.inline_data.packages))
    print("   Syft Packages   : %d" % len(analysis.syft_data.packages))
    print(
        "         (extra)   : %d (note: this is ignored by the quality gate!)"
        % len(analysis.extra_packages)
    )
    print("       (missing)   : %d" % len(analysis.missing_packages))
    print()

    if show_probable_mismatches:
        print(
            "   Probable Package Matches  : %d (matches not made, but were probably found by both Inline and Syft)"
            % len(analysis.similar_missing_packages)
        )
        print(
            "   Probable Packages Matched : %2.3f %% (%d/%d packages)"
            % (
                analysis.percent_probable_overlapping_packages,
                len(analysis.overlapping_packages)
                + len(analysis.similar_missing_packages),
                len(analysis.inline_data.packages),
            )
        )
        print(
            "   Probable Packages Missing : %d "
            % len(analysis.unmatched_missing_packages)
        )
        print()
    print(
        "   Baseline Packages Matched : %2.3f %% (%d/%d packages)"
        % (
            analysis.percent_overlapping_packages,
            len(analysis.overlapping_packages),
            len(analysis.inline_data.packages),
        )
    )
    print(
        "   Baseline Metadata Matched : %2.3f %% (%d/%d metadata)"
        % (
            analysis.percent_overlapping_metadata,
            len(analysis.overlapping_metadata),
            len(analysis.inline_metadata),
        )
    )


def enforce_quality_gate(title, actual_value, lower_gate_value, upper_gate_value):

    if actual_value < lower_gate_value:
        print(
            Colors.bold
            + "   %s Quality Gate:\t" % title
            + Colors.FG.red
            + "FAIL (is not >= %d %%)" % lower_gate_value,
            Colors.reset,
            )
        return False
    elif actual_value > upper_gate_value:
        print(
            Colors.bold
            + "   %s Quality Gate:\t" % title
            + Colors.FG.orange
            + "FAIL (lower threshold is artificially low and should be updated)",
            Colors.reset,
            )
        return False

    print(
        Colors.bold
        + "   %s Quality Gate:\t" % title
        + Colors.FG.green
        + "Pass (>= %d %%)" % lower_gate_value,
        Colors.reset,
        )

    return True

def main(image):
    cwd = os.path.dirname(os.path.abspath(__file__))

    # parse the inline-scan and syft reports on disk
    inline = InlineScan(image=image, report_dir=os.path.join(cwd, "inline-reports"))
    syft = Syft(image=image, report_dir=os.path.join(cwd, "syft-reports"))

    # analyze the raw data to generate all derivative data for the report and quality gate
    analysis = utils.package.Analysis(
        syft_data=syft.packages(), inline_data=inline.packages()
    )

    # show some useful report data for debugging / warm fuzzies
    report(image, analysis)

    # enforce a quality gate based on the comparison of package values and metadata values
    success = True
    success &= enforce_quality_gate(
        title="Package",
        actual_value=analysis.percent_overlapping_packages,
        lower_gate_value=PACKAGE_QUALITY_GATE[image] * 100,
        upper_gate_value=PACKAGE_UPPER_THRESHOLD[image] * 100
    )
    success &= enforce_quality_gate(
        title="Metadata",
        actual_value=analysis.percent_overlapping_metadata,
        lower_gate_value=METADATA_QUALITY_GATE[image] * 100,
        upper_gate_value=METADATA_UPPER_THRESHOLD[image] * 100
    )

    if not success:
        return 1
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
