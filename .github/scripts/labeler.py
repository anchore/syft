#!/usr/bin/env python3

from __future__ import annotations

import sys
import glob
import subprocess
import os
import re

DRY_RUN = False

JSON_SCHEMA_LABEL = "json-schema"

# note: we can't use "breaking-change" as the label since that might be applied manually by a user. This is a
# distinct label that we can use to indicate that the label was applied (or removed) by automation.
BREAKING_CHANGE_LABEL = "detected-breaking-change"


def main(changed_files: str | None = None, merge_base_schema_files: str | None = None):
    global DRY_RUN

    pr_number = os.environ.get("GITHUB_PR_NUMBER")
    comment_file_path = os.environ.get("CI_COMMENT_FILE")

    if not comment_file_path:
        print("CI_COMMENT_FILE not set")
        sys.exit(1)

    if not pr_number:
        DRY_RUN = True

    if changed_files:
        DRY_RUN = True

        # read lines from file... this is useful for local testing
        with open(changed_files) as f:
            pr_changed_files = f.read().splitlines()

        with open(merge_base_schema_files) as f:
            og_json_schema_files = sort_json_schema_files(f.read().splitlines())

    else:
        if not is_ci():
            print("Not in CI")
            sys.exit(1)

        if not pr_number:
            print("Not a PR")
            sys.exit(1)

        pr_changed_files = get_pr_changed_files(pr_number)
        # since we are running this in the context of the pull_request_target, the checkout is the merge base..
        # that is the main branch of the original repo, NOT the branch in the forked repo (or branch in the target 
        # repo for non-forked PRs). This means we just need to list the current checkedout files to get a sense of
        # the changes before a merge.
        og_json_schema_files = list_json_schema_files()

    pr_json_schema_files = filter_to_schema_files(pr_changed_files)

    pr_labels = get_pr_labels(pr_number)

    # print("schema files in pr:   ", summarize_schema_files(pr_json_schema_files))
    # print("og schema files:      ", summarize_schema_files(og_json_schema_files))

    if not og_json_schema_files:
        print("No schema files found in merge base")
        sys.exit(1)

    # pr_json_schema_files = set of PR files are added, removed, and changed files
    new_schema_files = set(pr_json_schema_files) - set(og_json_schema_files)
    removed_or_modified_schema_files = set(pr_json_schema_files) - set(new_schema_files)

    print("new schemas:                ", summarize_schema_files(new_schema_files))
    print("removed or modified schemas:", summarize_schema_files(removed_or_modified_schema_files))

    # if there is a new or modified schema, we should add the "json-schema" label to the PR...
    if new_schema_files or removed_or_modified_schema_files:
        print("\nAdding json-schema label...")
        add_label(pr_number, JSON_SCHEMA_LABEL)

    else:
        if JSON_SCHEMA_LABEL in pr_labels:
            remove_label(pr_number, JSON_SCHEMA_LABEL)

    # new schema files should be scrutinized, comparing the latest and added versions to see if it's a breaking
    # change (major version bump). Warn about it on the PR via adding a breaking-change label...
    if is_breaking_change(new_schema_files, og_json_schema_files[-1]):
        print("\nBreaking change detected...")
        add_label(pr_number, BREAKING_CHANGE_LABEL)
    else:
        if BREAKING_CHANGE_LABEL in pr_labels:        
            remove_label(pr_number, BREAKING_CHANGE_LABEL)

    # modifying an existing schema could be a breaking change, we should warn about it on the PR via a comment...
    # removing schema files should never be allowed, we should warn about it on the PR via a comment...
    if removed_or_modified_schema_files:
        print("\nRemoved or modified schema detected...")
        schemas = sort_json_schema_files(list(removed_or_modified_schema_files))
        schemas_str = "\n".join([f" - {schema}" for schema in schemas])
        add_comment(comment_file_path, f"Detected modification or removal of existing json schemas:\n{schemas_str}", warning=True)


def add_comment(comment_file_path: str, comment: str, warning: bool = False, important: bool = False):
    if warning or important:
        comment_lines = comment.splitlines()
        comment = "\n".join([f"> {line}" for line in comment_lines])

    if warning:
        comment = f"> [!WARNING]\n{comment}"    
    elif important:
        comment = f"> [!IMPORTANT]\n{comment}"

    # create any parent directories if they don't exist
    os.makedirs(os.path.dirname(comment_file_path), exist_ok=True)

    with open(comment_file_path, "w") as f:
        f.write(comment)

    print(f"Comment file contents: {comment_file_path}")
    print(comment)


def add_label(pr_number: str, label: str):
    # run "gh pr edit --add-label <label>"
    result = run(f"gh pr edit {pr_number} --add-label {label}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"Unable to add '{label!r}' label to PR, error:")
        print(str(result.stderr))
        sys.exit(1)


def remove_label(pr_number: str, label: str):
    # run "gh pr edit --remove-label <label>"
    result = run(f"gh pr edit {pr_number} --remove-label {label}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"Unable to remove '{label!r}' label from PR, error:")
        print(str(result.stderr))
        sys.exit(1)


def major_version(semver: str) -> int:
    return int(semver.split(".")[0])


def is_breaking_change(new_schema_files: set[str], latest_schema_file: str) -> bool:
    latest_major_version = major_version(get_semver(latest_schema_file))
    for file in new_schema_files:
        change_major_version = major_version(get_semver(file))
        if change_major_version > latest_major_version:
            return True
    return False


def summarize_schema_files(files: list[str]) -> list[str]:
    return [get_semver(file) for file in files]


def is_ci() -> bool:
    return "CI" in os.environ


def get_pr_changed_files(pr_number: str) -> list[str]:
    result = run(f"gh pr view {pr_number} --json files --jq '.files.[].path'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("Unable to get list of changed files in PR")
        print(str(result.stderr))
        sys.exit(1)
    
    list_of_files = result.stdout.splitlines()
    return list_of_files


def get_pr_labels(pr_number: str) -> list[str]:
    result = run(f"gh pr view {pr_number} --json labels --jq '.labels[].name'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("Unable to get list of labels on PR")
        print(str(result.stderr))
        sys.exit(1)
    
    list_of_labels = result.stdout.splitlines()
    return list_of_labels


def filter_to_schema_files(list_of_files: list[str]) -> list[str]:
    # get files matching "schema/json/schema-*.json"
    files = []
    for file in list_of_files:
        if re.match(r"^schema/json/schema-\d+\.\d+\.\d+\.json$", file):
            files.append(file)
    return sort_json_schema_files(files)


def list_json_schema_files() -> list[str]:
    # list files in "schema/json" directory matching the pattern of "schema-*.json"
    # special case: always ignore the "latest" schema file
    return sort_json_schema_files([f for f in glob.glob("schema/json/schema-*.json") if "latest" not in f])


def run(command: str,  **kwargs) -> subprocess.CompletedProcess:
    if DRY_RUN:
        print(f"[DRY RUN] {command}")
        return subprocess.CompletedProcess(args=[command], returncode=0)
    print(f"[RUN] {command}")
    return subprocess.run(command, **kwargs)


def get_semver(input_file: str) -> str:
    return input_file.split("-")[1].split(".json")[0]


def sort_json_schema_files(files: list[str]) -> list[str]:
    # sort files by schema version, where the input looks like "schema/json/schema-1.12.1.json"
    # we should sort by the semantic version embedded within the basename, not the string
    # so that "schema/json/schema-1.2.1.json" comes before "schema/json/schema-1.12.1.json".
    versions = [get_semver(file) for file in files if file]
    
    versions = sorted(versions, key=lambda s: [int(u) for u in s.split('.') if "." in s])

    return [f"schema/json/schema-{version}.json" for version in versions]


# allow for test files that have line-by-line list of files:

# .binny.yaml
# .github/actions/bootstrap/action.yaml
# .github/scripts/goreleaser-install.sh
# .github/workflows/release.yaml
# .github/workflows/update-bootstrap-tools.yml
# .github/workflows/update-cpe-dictionary-index.yml
# .github/workflows/update-stereoscope-release.yml
# .github/workflows/validations.yaml
# .gitignore
# .goreleaser.yaml
# Makefile
# Taskfile.yaml
# schema/cyclonedx/Makefile

if __name__ == "__main__":
    # these are variables for a single file name that contains a list of files (line separated)
    changed_files = None
    merge_base_schema_files = None

    if len(sys.argv) > 2:
        changed_files = sys.argv[1]
        merge_base_schema_files = sys.argv[2]

    main(changed_files, merge_base_schema_files)

