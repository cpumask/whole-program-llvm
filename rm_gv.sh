#!/bin/bash
# Input: $1: a bc, $2: a gv name to be removed
# What it does: remove that gv from the bc 

# Array of global variables to be removed
globals_to_remove=(
    "__cfi_jt_init_module"
    "__cfi_jt_cleanup_module"
)

# Array of functions to be removed
functions_to_remove=(
    "init_module"
    "cleanup_module"
)

# Function to remove unwanted globals from a bitcode file
remove_globals() {
    input_bc=$1
    output_bc=$2
    temp_bc=$input_bc

    for global in "${globals_to_remove[@]}"; do
        llvm-extract --delete --glob=$global $temp_bc -o temp.bc
        mv temp.bc $output_bc
        temp_bc=$output_bc
    done

    for func in "${functions_to_remove[@]}"; do
        llvm-extract --delete --func=$func $temp_bc -o temp.bc
        mv temp.bc $output_bc
        temp_bc=$output_bc
    done
}

# Ensure temporary files are cleaned up on exit
trap 'rm -f temp.bc' EXIT

# Process each input bitcode file
ifp=$(realpath $1)
remove_globals $ifp $2
