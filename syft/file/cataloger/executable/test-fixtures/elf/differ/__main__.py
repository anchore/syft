import json
import sys


def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


def diff_json(json1, json2):
    differences_found = False

    for key in json1:
        if key not in json2:
            print(f'missing key "{key}"')
            continue

        differences = []
        for subkey in json1[key]:
            if subkey not in json2[key]:
                differences.append(f'  - "{subkey}": expected "{json1[key][subkey]}" but was MISSING')
                continue

            if subkey in json2[key] and json1[key][subkey] != json2[key][subkey]:
                differences.append(f'  - "{subkey}": expected "{json1[key][subkey]}" got "{json2[key][subkey]}"')

        if differences:
            differences_found = True
            print(f'{key}')
            for diff in differences:
                print(diff)
            print()

    return differences_found


def main():
    if len(sys.argv) != 3:
        print("Usage: python ./differ file1.json file2.json")
        sys.exit(1)

    json1 = load_json(sys.argv[1])
    json2 = load_json(sys.argv[2])

    if diff_json(json1, json2):
        print("FAIL: unexpected security feature differences")
        sys.exit(1)
    else:
        print("PASS: all security features accounted for")
        sys.exit(0)


main()
