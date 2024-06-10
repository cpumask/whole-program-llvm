#!/bin/bash
# Input: a list of bc files
# What it does: check whether there are any global variables that are defined in more than one input bc files,
# if any, rename the gc in each input bc (each bc will get its own name for that gv), so that these bcs can
# be linked together w/o the "symbol mutiply defined" errors geenrated by llvm-link.
# Concern: this can help resolve the pure name conflicts, i.e., those are indeed different global variables
# but happen to have the same name. But what if a same global variable is actually defined in multiple bcs?
# In that situation, the program logic will be wrongly altered since we create different insatnces of the
# same gv.
# TODO: this can be resolved with a post-processing, by rename back the multiple instances and remove
# the unncessary instances in the linked bc.

# Check if llvm tools are installed
if ! command -v llvm-nm &> /dev/null || ! command -v llvm-extract &> /dev/null || ! command -v llvm-link &> /dev/null
then
    echo "llvm tools are required but not installed. Please install llvm-nm, llvm-extract, and llvm-link."
    exit 1
fi

# Create backups of original .bc files
for file in "$@"; do
    cp "$file" "$file.bak"
done

# Function to escape special characters for use in sed
escape_special_chars() {
    echo "$1" | sed -e 's/[]\/$*.^|[]/\\&/g'
}

# Function to rename all conflicting symbols in text IR at once
rename_conflicts() {
    file=$1
    renames=$2

    # Convert to LLVM IR
    llvm-dis "$file" -o temp.ll

    # Rename the global symbols using specific word boundaries
    IFS=' ' read -r -a rename_pairs <<< "$renames"
    for pair in "${rename_pairs[@]}"; do
        IFS=':' read -r old_name new_name <<< "$pair"
        old_name_escaped=$(escape_special_chars "$old_name")
        new_name_escaped=$(escape_special_chars "$new_name")
        # sed -i -E "s/@${old_name_escaped}([ ,])/@${new_name_escaped}\1/g" temp.ll
        sed -i -E "s/@${old_name_escaped}([^a-zA-Z0-9_.-]|$)/@${new_name_escaped}\1/g" temp.ll
    done

    # Convert back to LLVM bitcode
    llvm-as temp.ll -o "$file"
    rm temp.ll
}

# Collect all global symbols and their occurrences
declare -A symbol_counts
declare -A files_with_symbol

for file in "$@"; do
    while read -r line; do
        symbol=$(echo $line | awk '{print $3}')
        if [ -z "$symbol" ]; then
            continue
        fi
        symbol_counts[$symbol]=$((symbol_counts[$symbol]+1))
        files_with_symbol[$symbol]+=" $file"
    done < <(llvm-nm --defined-only -g "$file")
done

# Print collected symbols with counts greater than 1 for debugging
echo "Conflicting symbols and their counts:"
for symbol in "${!symbol_counts[@]}"; do
    if [ ${symbol_counts[$symbol]} -gt 1 ]; then
        echo "$symbol: ${symbol_counts[$symbol]}"
    fi
done

# Collect renames for each file
declare -A file_renames

for symbol in "${!symbol_counts[@]}"; do
    if [ ${symbol_counts[$symbol]} -gt 1 ]; then
        count=1
        for file in ${files_with_symbol[$symbol]}; do
            timestamp=$(date +%s | tail -c 5)  # Use the last 4 digits of the seconds timestamp
            new_name="${symbol}_${timestamp}_${count}"
            echo "Preparing to rename ${symbol} in ${file} to ${new_name}"
            if [ -z "${file_renames[$file]+isset}" ]; then
                file_renames[$file]=""
            fi
            file_renames[$file]+="$symbol:$new_name "
            count=$((count+1))
        done
    fi
done

# Print file_renames for debugging
echo "Renames for each file:"
for file in "${!file_renames[@]}"; do
    echo "File: $file"
    IFS=' ' read -r -a renames <<< "${file_renames[$file]}"
    for rename in "${renames[@]}"; do
        echo "  $rename"
    done
done

# Rename all symbols in each file
for file in "$@"; do
    if [ ! -z "${file_renames[$file]+isset}" ]; then
        rename_conflicts "$file" "${file_renames[$file]}"
    fi
done

# Link the modified files
# llvm-link "$@" -o output.bc

# echo "Linked output is in output.bc"
