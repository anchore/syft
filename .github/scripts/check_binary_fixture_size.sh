#!/bin/bash

# current limit for fixture size
size=1000

if [ $# -eq 0 ]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

directory="$1"

# Remove trailing slash using parameter expansion
directory="${directory%/}"

if [ ! -d "$directory" ]; then
  echo "Directory not found: $directory"
  exit 1
fi

found_large_files=0
while IFS= read -r -d '' file; do
  if [ $(wc -c < "$file") -gt $size ]; then
    echo "File $file is greater than ${size} bytes."
    found_large_files=1
  fi
done < <(find "$directory" -type f -print0)

if [ "$found_large_files" -eq 1 ]; then
  echo "Script failed: Some files are greater than ${size} bytes."
  exit 1
else
  echo "All files in $directory and its subdirectories are ${size} bytes or smaller. Check passed."
  exit 0
fi

