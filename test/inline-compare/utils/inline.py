import os
import json
import collections

import utils.package
import utils.image


class InlineScan:
    """
    Class for parsing inlnie-scan output files into a set of packages and package metadata.
    """
    report_tmpl = "{image}-{report}.json"

    def __init__(self, image, report_dir):
        self.report_dir = report_dir
        self.image = image

    def packages(self):
        python_packages, python_metadata = self._python_packages()
        gem_packages, gem_metadata = self._gem_packages()
        java_packages, java_metadata = self._java_packages()
        npm_packages, npm_metadata = self._npm_packages()
        os_packages, os_metadata = self._os_packages()

        packages = (
            python_packages | os_packages | gem_packages | java_packages | npm_packages
        )
        metadata = {
            **python_metadata,
            **os_metadata,
            **gem_metadata,
            **java_metadata,
            **npm_metadata,
        }

        return utils.package.Info(packages=frozenset(packages), metadata=metadata)

    def _report_path(self, report):
        return os.path.join(
            self.report_dir,
            self.report_tmpl.format(image=utils.image.clean(self.image), report=report),
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

    def _java_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-java", section="content"):
            # normalize to pseudo-inline
            pkg_type = entry["type"].lower()
            if pkg_type in ("java-jar", "java-war", "java-ear"):
                pkg_type = "java-?ar"
            elif pkg_type in ("java-jpi", "java-hpi"):
                pkg_type = "java-?pi"

            pkg = utils.package.Package(
                name=entry["package"],
                type=pkg_type,
            )
            packages.add(pkg)

            extra = dict(entry)
            extra.pop('type')
            extra.pop('maven-version')
            for k, v in dict(extra).items():
                if v in ("", "N/A"):
                    extra[k] = None

            # temp temp temp
            extra.pop("location")

            metadata[pkg.type][pkg] = utils.package.Metadata(
                version=entry["maven-version"],
                extra=tuple(sorted(extra.items())),
            )

        return packages, metadata

    def _npm_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-npm", section="content"):
            pkg = utils.package.Package(
                name=entry["package"],
                type=entry["type"].lower(),
            )
            packages.add(pkg)
            metadata[pkg.type][pkg] = utils.package.Metadata(version=entry["version"], extra=tuple())

        return packages, metadata

    def _python_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(
            report="content-python", section="content"
        ):
            pkg = utils.package.Package(
                name=entry["package"],
                type=entry["type"].lower(),
            )
            packages.add(pkg)
            metadata[pkg.type][pkg] = utils.package.Metadata(version=entry["version"], extra=tuple())

        return packages, metadata

    def _gem_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-gem", section="content"):
            pkg = utils.package.Package(
                name=entry["package"],
                type=entry["type"].lower(),
            )
            packages.add(pkg)
            metadata[pkg.type][pkg] = utils.package.Metadata(version=entry["version"], extra=tuple())

        return packages, metadata

    def _os_packages(self):
        packages = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="content-os", section="content"):
            pkg = utils.package.Package(
                name=entry["package"], type=entry["type"].lower()
            )
            packages.add(pkg)
            metadata[pkg.type][pkg] = utils.package.Metadata(version=entry["version"], extra=tuple())

        return packages, metadata
