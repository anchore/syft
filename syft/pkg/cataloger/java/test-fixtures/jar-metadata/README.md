# Jar-Metadata test fixtures

Each directory is the name of a jar to be created (simply a zip) based on the contents of the directory.
This prevents us from having to create real jars by hand or keep binaries in the repo. This also means we dont need the
entire jar, only the necessary metadata for testing.

### api-all-2.0.0-sources
This fixture is built to simulate the case where we have a jar with multiple pom files discovered when trying to determine the parent.
This is a valid case, but not one that we covered before [PR 2231](https://github.com/anchore/syft/pull/2231)

### jackson-core-2.15.2
These two fixtures are built to simulate the case where we would have a duplicate jar 
regression as seen in [issue #2130](https://github.com/anchore/syft/issues/2130)