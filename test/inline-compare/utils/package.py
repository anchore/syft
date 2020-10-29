import difflib
import collections
import dataclasses
from typing import Set, FrozenSet, Tuple, Any, List

Metadata = collections.namedtuple("Metadata", "version extra")
Package = collections.namedtuple("Package", "name type")
Info = collections.namedtuple("Info", "packages metadata")

SimilarPackages = collections.namedtuple("SimilarPackages", "pkg missed")
ProbableMatch = collections.namedtuple("ProbableMatch", "pkg ratio")


@dataclasses.dataclass()
class Analysis:
    """
    A package metadata analysis class. When given the raw syft and inline data, all necessary derivative information
    needed to do a comparison of package and metadata is performed, allowing callers to interpret the results
    """

    # all raw data from the inline scan and syft reports
    syft_data: Info
    inline_data: Info

    # all derivative information (derived from the raw data above)
    overlapping_packages: FrozenSet[Package] = dataclasses.field(init=False)
    extra_packages: FrozenSet[Package] = dataclasses.field(init=False)
    missing_packages: FrozenSet[Package] = dataclasses.field(init=False)

    inline_metadata: Set[Tuple[Any, Any]] = dataclasses.field(init=False)
    missing_metadata: Set[Tuple[Any, Any]] = dataclasses.field(init=False)
    overlapping_metadata: Set[Tuple[Any, Any]] = dataclasses.field(init=False)

    similar_missing_packages: List[Package] = dataclasses.field(init=False)
    unmatched_missing_packages: List[Package] = dataclasses.field(init=False)

    def __post_init__(self):
        if not self.valid():
            raise RuntimeError("invalid data given")

        # basic sets derived from package information
        self.overlapping_packages = self.syft_data.packages & self.inline_data.packages
        self.extra_packages = self.syft_data.packages - self.inline_data.packages
        self.missing_packages = self.inline_data.packages - self.syft_data.packages

        # basic sets derived from metadata information
        self.inline_metadata = self._inline_metadata()
        self.overlapping_metadata = self._overlapping_metadata()
        self.missing_metadata = self.inline_metadata - self.overlapping_metadata

        # try to account for potential false negatives by pairing extra packages discovered only by syft with missing
        # packages discovered only by inline scan.
        (
            similar_missing_packages,
            unmatched_missing_packages,
        ) = self._pair_similar_packages(self.extra_packages, self.missing_packages)
        self.similar_missing_packages = similar_missing_packages
        self.unmatched_missing_packages = unmatched_missing_packages

    def valid(self) -> bool:
        # we are purposefully selecting test images that are guaranteed to have packages (this should never happen).
        # ... if it does, then this analysis is not valid!
        return bool(self.inline_data.packages)

    def _inline_metadata(self):
        """
        Returns the set of inline scan metadata paired with the corresponding package info.
        """
        inline_metadata_set = set()
        for package in self.inline_data.packages:
            metadata = self.inline_data.metadata[package.type][package]
            inline_metadata_set.add((package, metadata))
        return inline_metadata_set

    def _overlapping_metadata(self):
        """
        Returns the metadata which has been found similar between both syft and inline scan.
        """
        syft_overlap_metadata_set = set()
        for package in self.syft_data.packages:
            metadata = self.syft_data.metadata[package.type][package]
            # we only want to really count mismatched metadata for packages that are at least found by inline
            if package in self.inline_data.metadata.get(package.type, []):
                syft_overlap_metadata_set.add((package, metadata))

        return syft_overlap_metadata_set & self.inline_metadata

    @staticmethod
    def _pair_similar_packages(extra_packages, missing_packages, similar_threshold=0.7):
        """
        Try to account for potential false negatives by pairing extra packages discovered only by syft with missing
        packages discovered only by inline scan.
        """
        matches = collections.defaultdict(set)
        found = {}
        for s in extra_packages:
            for i in missing_packages:
                ratio = difflib.SequenceMatcher(None, s.name, i.name).ratio()
                if ratio >= similar_threshold:
                    if i in found:
                        # only allow for an inline package to be paired once
                        if ratio < found[i]:
                            continue
                        else:
                            matches[s].discard(i)

                    # persist the result
                    found[i] = ratio
                    matches[s].add(i)

        results = []
        for s, i_set in matches.items():
            missed = tuple([ProbableMatch(pkg=i, ratio=found[i]) for i in i_set])
            results.append(SimilarPackages(pkg=s, missed=missed))

        not_found = [i for i in missing_packages if i not in found]

        return sorted(results, key=lambda x: x.pkg), sorted(
            not_found, key=lambda x: x.name
        )

    @property
    def percent_overlapping_packages(self):
        """Returns a percentage representing how many packages that were found relative to the number of expected"""
        return (
            float(len(self.overlapping_packages))
            / float(len(self.inline_data.packages))
        ) * 100.0

    @property
    def percent_overlapping_metadata(self):
        """Returns a percentage representing how many matching metdata that were found relative to the number of expected"""
        return (
            float(len(self.overlapping_metadata)) / float(len(self.inline_metadata))
        ) * 100.0

    @property
    def percent_probable_overlapping_packages(self):
        """
        Returns a percentage representing how many packages that were found relative to the number of expected after
        considering pairing of missing packages with extra packages in a fuzzy match.
        """
        return (
            float(len(self.overlapping_packages) + len(self.similar_missing_packages))
            / float(len(self.inline_data.packages))
        ) * 100.0
