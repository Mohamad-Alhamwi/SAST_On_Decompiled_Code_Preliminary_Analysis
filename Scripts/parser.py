#!/usr/bin/python3

import re
import argparse
import os

## Color coding for terminal output
GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
RESET = "\033[0m"

## Handle struct redefinition block: comments out from `struct ... {` to `};`.
def struct_redefinition_block(lines, start_idx, already_commented):

    count = 0
    counter = start_idx
    lines[counter] = '// --- BEGIN AUTO COMMENTING:\n' + lines[counter]

    while counter < len(lines):

        if not lines[counter].lstrip().startswith('//'):
            lines[counter] = '// ' + lines[counter]
            count += 1
            already_commented.add(counter + 1)

        if lines[counter].strip().endswith('};'):
            break
        counter += 1

    lines[counter] += '// --- END AUTO COMMENTING.\n'

    return count

## Comments out redefined standard structs/types/function lines in the source file based on GCC error log.
def comment_out_redefinitions(src_path, out_path, error_log_path):

    print(f"[{BLUE}*{RESET}] Reading the error log ...")
    with open(error_log_path, 'r') as log_file:
        error_lines = log_file.readlines()

    print(f"[{BLUE}*{RESET}] Searching for redefinition errors ...")
    redefine_entries = []
    pattern = r'^.*?:(\d+):\d+: error: redefinition of[ \t]+‘?(\w+)’?'

    for line in error_lines:

        match = re.match(pattern, line)
        if match:
            line_num = int(match.group(1))
            is_struct = 'struct' in line
            redefine_entries.append((line_num, is_struct))

    ## Read the source file.
    with open(src_path, 'r') as src_file:
        lines = src_file.readlines()

    ## Comment out the lines with redefinitions.
    total_count = 0
    already_commented = set()

    print(f"    [{BLUE}*{RESET}] Searching for struct redefinition errors ...")
    for line_num, is_struct in redefine_entries:

        if 0 < line_num <= len(lines) and line_num not in already_commented:
            idx = line_num - 1

            if is_struct:
                total_count += struct_redefinition_block(lines, idx, already_commented)
    
    ## Write the modified lines back to a new output file.
    with open(out_path, 'w') as out_file:
        out_file.writelines(lines)
    
    print(f"    [{GREEN}+{RESET}] Commented out {GREEN}{total_count}{RESET} redefinition lines.")
    print(f"[{BLUE}*{RESET}] Done.")

def main():
    parser = argparse.ArgumentParser(description='Comment out redefinition errors from a C source file.')
    parser.add_argument('--src', required=True, help='Path to the input C source file.')
    parser.add_argument('--log', required=True, help='Path to the GCC error log file.')
    args = parser.parse_args()

    ## Automatically set output file path as "recompilable.c" in the same directory.
    src_dir = os.path.dirname(os.path.abspath(args.src))
    out_path = os.path.join(src_dir, 'recompilable.c')

    comment_out_redefinitions(args.src, out_path, args.log)

if __name__ == '__main__':
	main()
