#!/usr/bin/env python3
import os
import sys
import collections

import utils.package
from utils.format import Colors, print_rows
from utils.inline import InlineScan
from utils.syft import Syft

QUALITY_GATE_THRESHOLD = 0.95
INDENT = "    "
IMAGE_QUALITY_GATE = collections.defaultdict(lambda: QUALITY_GATE_THRESHOLD, **{})

# We additionally fail if an image is above a particular threshold. Why? We expect the lower threshold to be 90%,
# however additional functionality in grype is still being implemented, so this threshold may not be able to be met.
# In these cases the IMAGE_QUALITY_GATE is set to a lower value to allow the test to pass for known issues. Once these
# issues/enhancements are done we want to ensure that the lower threshold is bumped up to catch regression. The only way
# to do this is to select an upper threshold for images with known threshold values, so we have a failure that
# loudly indicates the lower threshold should be bumped.
IMAGE_UPPER_THRESHOLD = collections.defaultdict(lambda: 1, **{})


def report(analysis):
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
        rows = []
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
            rows.append(
                [
                    INDENT,
                    "for:",
                    repr(pkg),
                    ":",
                    repr(syft_metadata_item),
                    "!=",
                    repr(metadata),
                ]
            )
        if rows:
            print_rows(rows)
        else:
            print(
                INDENT,
                "There are mismatches, but only due to packages Syft did not find (but inline did).",
            )
        print()

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

    if analysis.unmatched_missing_packages and analysis.extra_packages:
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

    print(Colors.bold + "Summary:", Colors.reset)
    print("   Inline Packages : %d" % len(analysis.inline_data.packages))
    print("   Syft Packages   : %d" % len(analysis.syft_data.packages))
    print(
        "         (extra)   : %d (note: this is ignored in the analysis!)"
        % len(analysis.extra_packages)
    )
    print("       (missing)   : %d" % len(analysis.missing_packages))
    print()

    if analysis.unmatched_missing_packages and analysis.extra_packages:
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

    overall_score = (
        analysis.percent_overlapping_packages + analysis.percent_overlapping_metadata
    ) / 2.0

    print(Colors.bold + "   Overall Score: %2.1f %%" % overall_score, Colors.reset)


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
    report(analysis)

    # enforce a quality gate based on the comparison of package values and metadata values
    upper_gate_value = IMAGE_UPPER_THRESHOLD[image] * 100
    lower_gate_value = IMAGE_QUALITY_GATE[image] * 100
    if analysis.quality_gate_score < lower_gate_value:
        print(
            Colors.bold
            + "   Quality Gate: "
            + Colors.FG.red
            + "FAILED (is not >= %d %%)\n" % lower_gate_value,
            Colors.reset,
        )
        return 1
    elif analysis.quality_gate_score > upper_gate_value:
        print(
            Colors.bold
            + "   Quality Gate: "
            + Colors.FG.orange
            + "FAILED (lower threshold is artificially low and should be updated)\n",
            Colors.reset,
        )
        return 1
    else:
        print(
            Colors.bold
            + "   Quality Gate: "
            + Colors.FG.green
            + "pass (>= %d %%)\n" % lower_gate_value,
            Colors.reset,
        )

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
