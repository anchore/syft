import os
import json
import collections

import utils.package
import utils.image
from utils.traverse import dig


class Syft:
    """
    Class for parsing syft output into a set of packages and package metadata.
    """
    report_tmpl = "{image}.json"

    def __init__(self, image, report_dir):
        self.report_path = os.path.join(
            report_dir, self.report_tmpl.format(image=utils.image.clean(image))
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

            extra = {}

            # normalize to inline
            pkg_type = entry["type"].lower()
            if pkg_type in ("wheel", "egg", "python"):
                pkg_type = "python"
            elif pkg_type in ("deb",):
                pkg_type = "dpkg"
            elif pkg_type in ("java-archive",):
                # normalize to pseudo-inline
                pkg_type = "java-?ar"
            elif pkg_type in ("jenkins-plugin",):
                # normalize to pseudo-inline
                pkg_type = "java-?pi"
            elif pkg_type in ("apk",):
                pkg_type = "apkg"

            name = entry["name"]
            version = entry["version"]

            if "java" in pkg_type:
                # lets match what inline scan expects to output

                # specVersion = dig(entry, "metadata", "manifest", "specificationVersion") or None
                # implVersion = dig(entry, "metadata", "manifest", "implementationVersion") or None
                virtualPath = dig(entry, "metadata", "virtualPath")

                # package = dig(entry, "metadata", "pomProperties", "artifactId")
                # if not package:
                #     package = "%s-%s" % (dig(entry, "name"), dig(entry, "version"))
                #
                # extra = {
                #     "implementation-version": implVersion,
                #     "specification-version": specVersion,
                #     "location": virtualPath,
                #     "package": package,
                # }

                # we need to use the virtual path instead of the name to account for nested dependencies with the same
                # package name (but potentially different metadata)
                name = virtualPath

            elif pkg_type == "apkg":
                version = entry["version"].split("-")[0]

            pkg = utils.package.Package(
                name=name,
                type=pkg_type,
            )

            packages.add(pkg)

            metadata[pkg.type][pkg] = utils.package.Metadata(version=version, extra=tuple(sorted(extra.items())))

        return utils.package.Info(packages=frozenset(packages), metadata=metadata)
