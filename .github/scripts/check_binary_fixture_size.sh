#!/bin/bash

# Check if a directory is provided as an argument
if [ $# -eq 0 ]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

directory="$1"

# Check if the directory exists
if [ ! -d "$directory" ]; then
  echo "Directory not found: $directory"
  exit 1
fi

# Use find to locate all files in the directory and its subdirectories
found_large_files=0
while IFS= read -r -d '' file; do
  # Check if the file size is greater than 100 bytes
  if [ $(wc -c < "$file") -gt 100 ]; then
    echo "File $file is greater than 100 bytes."
    found_large_files=1
  fi
done < <(find "$directory" -type f -print0)

# Check if any large files were found
if [ "$found_large_files" -eq 1 ]; then
  echo "Script failed: Some files are greater than 100 bytes."
  exit 1
else
  echo "All files in $directory and its subdirectories are 100 bytes or smaller. Script passed."
  exit 0
fi

