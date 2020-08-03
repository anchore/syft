#!/usr/env/bin python3
import os
import glob
import json

from genson import SchemaBuilder

EXAMPLES_DIR = "examples/"
OUTPUT = "schema.json"


def main():
    builder = SchemaBuilder()

    print("Generating new Syft json schema...")
    for filepath in glob.glob(os.path.join(EXAMPLES_DIR, '*.json')):
        with open(filepath, 'r') as f:
            print(f"  adding {filepath}")
            builder.add_object(json.loads(f.read()))

    print("Building schema...")
    new_schema = builder.to_schema()
    with open(OUTPUT, 'w') as f:
        f.write(json.dumps(new_schema, sort_keys=True, indent=4))

    print(f"New schema written to '{OUTPUT}'")


if __name__ == "__main__":
    main()