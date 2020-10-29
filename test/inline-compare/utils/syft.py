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

            pkg = utils.package.Package(
                name=entry["name"],
                type=pkg_type,
            )

            packages.add(pkg)

            if "java" in pkg_type:
                # lets match what inline scan expects to output

                path = dig(entry, "locations", 0, "path")
                specVendor = dig(entry, "metadata", "manifest", "specificationVendor")
                implVendor = dig(entry, "metadata", "manifest", "implementationVendor")

                specVersion = dig(entry, "metadata", "manifest", "specificationVersion") or None
                implVersion = dig(entry, "metadata", "manifest", "implementationVersion") or None

                extra = {
                    "implementation-version": implVersion,
                    "specification-version": specVersion,
                    "origin": dig(entry, "metadata", "pomProperties", "groupId"),
                    "location": path,
                    "package": dig(entry, "metadata", "pomProperties", "artifactId"),
                }

                if dig(entry, "metadata", "parentPackage"):
                    extra['origin'] = dig(entry, "metadata", "pomProperties", "groupId")
                else:
                    # this is a nested package...
                    if specVendor:
                        extra['origin'] = specVendor
                    elif implVendor:
                        extra['origin'] = implVendor

                pomPath = dig(entry, "metadata", "pomProperties", "Path")
                if path and pomPath:
                   extra["location"] = "%s:%s" % (path, pomPath),

                # temp temp temp
                extra.pop("location")

            elif pkg_type == "apkg":
                entry["version"] = entry["version"].split("-")[0]

            metadata[pkg.type][pkg] = utils.package.Metadata(version=entry["version"], extra=tuple(sorted(extra.items())))

        return utils.package.Info(packages=frozenset(packages), metadata=metadata)
