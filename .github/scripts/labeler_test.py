#!/usr/bin/env python3

import unittest
from unittest.mock import patch
import subprocess

import labeler

class Labeler(unittest.TestCase):

    def test_major_version(self):
        self.assertEqual(labeler.major_version("1.2.3"), 1)
        self.assertEqual(labeler.major_version("2.0.0"), 2)

    def test_is_breaking_change(self):
        new_schema_files = ["schema/json/schema-2.0.0.json"]
        latest_schema_file = "schema/json/schema-1.2.0.json"
        self.assertTrue(labeler.is_breaking_change(new_schema_files, latest_schema_file))

        new_schema_files = ["schema/json/schema-1.3.0.json"]
        latest_schema_file = "schema/json/schema-1.2.0.json"
        self.assertFalse(labeler.is_breaking_change(new_schema_files, latest_schema_file))

    def test_summarize_schema_files(self):
        files = ["schema/json/schema-1.0.0.json", "schema/json/schema-2.0.0.json"]
        expected = ["1.0.0", "2.0.0"]
        self.assertEqual(labeler.summarize_schema_files(files), expected)

    def test_is_ci(self):
        # Mock os.environ to simulate CI environment
        with patch.dict("os.environ", {"CI": "true"}):
            self.assertTrue(labeler.is_ci())

    def test_get_pr_changed_files(self):
        expected_command = "gh pr view 123 --json files --jq '.files.[].path'"
        expected_output = "file1.json\nfile2.json\n"

        subprocess.CompletedProcess.returncode = 0
        subprocess.CompletedProcess.stdout = expected_output
        with patch("labeler.run", return_value=subprocess.CompletedProcess) as mock_run:
            result = labeler.get_pr_changed_files("123")
            mock_run.assert_called_with(expected_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result, ["file1.json", "file2.json"])

    def test_filter_to_schema_files(self):
        input_files = ["schema/json/schema-1.0.0.json", "not_schema.txt", "schema/json/schema-2.0.0.json"]
        expected_files = ["schema/json/schema-1.0.0.json", "schema/json/schema-2.0.0.json"]
        self.assertEqual(labeler.filter_to_schema_files(input_files), expected_files)

        # we should be strict about what files are allowed to be processed
        input_files = ["schema/json/schema-1.0.0extracontent.json", "schema/json/schema-1.0.0.md", "schema/json/schema-1.0.0.json.extracontent"]
        expected_files = []
        self.assertEqual(labeler.filter_to_schema_files(input_files), expected_files)

    def test_get_semver(self):
        input_file = "schema/json/schema-1.0.0.json"
        expected_semver = "1.0.0"
        self.assertEqual(labeler.get_semver(input_file), expected_semver)

    def test_sort_json_schema_files(self):
        files = ["schema/json/schema-1.12.1.json", "schema/json/schema-1.2.1.json"]
        expected_sorted_files = ["schema/json/schema-1.2.1.json", "schema/json/schema-1.12.1.json"]
        self.assertEqual(labeler.sort_json_schema_files(files), expected_sorted_files)

        # ensure that "latest" doesn't cause a problem and is ultimately ignored
        files = ["schema/json/schema-1.12.1.json", "schema/json/schema-_bogus.json"]
        expected_sorted_files = ["schema/json/schema-_bogus.json", "schema/json/schema-1.12.1.json"]
        self.assertEqual(labeler.sort_json_schema_files(files), expected_sorted_files)


if __name__ == "__main__":
    unittest.main()
