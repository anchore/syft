#!/bin/bash

# Default values for length and prefix length
LENGTH=100
PREFIX_LENGTH=20
SEARCH_FOR=''
GROUP_NAME=''

# Function to show usage
usage() {
    echo "Usage: $0 <path-to-binary> <version> [--search-for <pattern>] [--length <length>] [--prefix-length <prefix_length>] [--group <name>]"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
	--search-for)
	    SEARCH_FOR="$2"
	    shift # past argument
            shift # past value
	    ;;
        --length)
            LENGTH="$2"
            shift # past argument
            shift # past value
            ;;
        --group)
            GROUP_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        --prefix-length)
            PREFIX_LENGTH="$2"
            shift # past argument
            shift # past value
            ;;
        *)
            if [ -z "$BINARY_FILE" ]; then
                BINARY_FILE="$1"
            elif [ -z "$VERSION" ]; then
                VERSION="$1"
            else
                echo "Unknown option: $1"
                usage
            fi
            shift # past argument
            ;;
    esac
done

# check if binary file and pattern are provided
if [ -z "$BINARY_FILE" ] || [ -z "$VERSION" ]; then
    usage
fi

# if group name is empty use the binary filename
if [ -z "$GROUP_NAME" ]; then
    GROUP_NAME=$(basename "$BINARY_FILE")
fi

# check if xxd is even installed
if ! command -v xxd &> /dev/null; then
    echo "xxd not found. Please install xxd."
    exit 1
fi


PATTERN=${SEARCH_FOR:-$VERSION}

PATTERN_RESULTS=$(strings -t d "$BINARY_FILE" | grep "$PATTERN")

# if there are multiple matches, prompt the user to select one
if [ $(echo "$PATTERN_RESULTS" | wc -l) -gt 1 ]; then
    echo "Multiple string matches found in the binary:"
    echo ""

    # show result lines one at a time (in a numbered list)
    # but only show everything after the first field (not the offset)
    echo "$PATTERN_RESULTS" | cut -d ' ' -f 2- | nl -w 1 -s ') '


    echo ""
    read -p "Please select a match: " SELECTION

    # if the selection is not a number, exit
    if ! [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
        echo "Invalid selection."
        exit 1
    fi

    # if the selection is out of bounds, exit
    if [ "$SELECTION" -gt $(echo "$PATTERN_RESULTS" | wc -l) ]; then
        echo "Invalid selection."
        exit 1
    fi

    # select the line from the results
    PATTERN_RESULTS=$(echo "$PATTERN_RESULTS" | sed -n "${SELECTION}p")
fi

# search for the pattern in the binary file and capture the offset
OFFSET=$(echo "${PATTERN_RESULTS}" | cut -d ' ' -f 1)

if [ -z "$OFFSET" ]; then
    echo "Pattern not found."
    exit 1
fi

# adjust the offset to capture prefix length before the match
OFFSET=$(expr "$OFFSET" - "$PREFIX_LENGTH")

# use xxd to capture the specified length from the calculated offset
SNIPPET=$(xxd -l "$LENGTH" -s "$OFFSET" "$BINARY_FILE")

# display the output and prompt the user
echo ""
echo "$SNIPPET"
echo ""
read -p "Does this snippet capture what you need? (Y/n) " RESPONSE
RESPONSE=${RESPONSE:-y}

if [ "$RESPONSE" != "y" ]; then
    echo "Exiting with no action taken."
    exit 1
fi

go run ./manager write-snippet "$BINARY_FILE" --offset "$OFFSET" --length "$LENGTH" --name "$GROUP_NAME" --version "$VERSION"
