#!/bin/bash

# Check if a filename is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <input_file>"
  echo "  <input_file>: A text file containing a list of URLs, one per line."
  exit 1
fi

input_file="$1"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
  echo "Error: Input file '$input_file' not found."
  exit 1
fi

# Read URLs from the input file and process each one
while IFS= read -r url; do
  if [[ -n "$url" ]]; then # Skip empty lines
    echo "Downloading: $url"
    wget --mirror --convert-links --no-parent "$url"
    if [ $? -ne 0 ]; then
      echo "Error downloading: $url"
    fi
  fi
done < "$input_file"

echo "Finished processing URLs from $input_file"
