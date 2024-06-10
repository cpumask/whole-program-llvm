#!/bin/bash
# Input: $1: a folder containig bcs, $2: a variable name
# What it does: lookup the variable name in all bcs within the folder, report which bc contains it.

# Directory containing the .bc files
BC_DIR=$(realpath $1)

# Symbol to search for
SYMBOL=$2

# Iterate over .bc files in the directory
for bc_file in "$BC_DIR"/{,.}*.bc; do
    # Use llvm-nm to check for the symbol
    if llvm-nm "$bc_file" | grep -q "$SYMBOL"; then
        echo "$SYMBOL found in $bc_file"
    fi
done
