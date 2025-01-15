#!/usr/bin/env bash

# Script: docgen.sh
# Purpose: Automates the generation of README files for vulnerability detection validation.
# Usage: ./docgen.sh
# Dependencies:
#   - jq: Command-line JSON processor.
# Notes:
#   - This script processes JSON files in test directories to generate Markdown documentation.
#   - Ensure the input file structure matches the expected JSON schema.

# GLOBAL DEFINITIONS
FILENAME=Readme.md
BASE_DIR=.github/vdscanner_efficacy_test/
CATEGORY_PLACEHOLDER=REPLACE_CATEGORY
NAME_PADING=6
VERSION_PADING=9
CVE_PADDING=13
MAX_SOURCE_LENGTH=31

# Write to destination file a common text description.
function print_desc_to_file() {
    local readme_filepath=$1
    {
        echo "# Description"
        echo
        echo "Vulnerability detection validation for ${CATEGORY_PLACEHOLDER}".
        echo
        echo "# Events"
    } >>"${readme_filepath}"
}

# Returns the maximum string lenght for a given `field`.
function max_string_length() {
    local field=$1
    local input_filepath=$2
    echo $(jq -r ".packages[].${field}" "${input_filepath}" | awk '{ print length, $0 }' | sort -n -r | cut -d ' ' -f 1 | head -n 1)
}

# Repeats `times` times a `character`. Used for padding fields in the markdown table.
function print_repeated_character() {
    local character=$1
    local times=$2
    for index in $(seq 1 $((times))); do
        echo -n "${character}"
    done
}

# Writes PKGS vulnerabilities in markdown table.
#
# Brief: Iterates over the CVE ID and vulnerability source pair for each package data (name and version)
# and writes them in the destination file with the right padding.
#
function _pkg_vulnerabilities() {
    local longest_name=$1
    local longest_version=$2
    local readme_filepath=$3
    local pkg_name=$4
    local pkg_version=$5
    shift 5
    local vuln_info=("$@")
    for cve_source in "${vuln_info[@]}"; do
        read -r cve source <<<$(echo $cve_source | sed "s/'//g")
        {
            echo -n "|${pkg_name}"
            print_repeated_character " " $((longest_name - ${#pkg_name}))
            echo -n "|${pkg_version}"
            print_repeated_character " " $((longest_version - ${#pkg_version}))
            if [ ${#cve} -eq ${CVE_PADDING} ]; then
                cve=$cve" "
            fi
            if [[ $readme_filepath =~ "positive" ]]; then
                echo "|$cve"
            else
                echo -n "|$cve|"
                echo $source
            fi
        } >>"${readme_filepath}"
    done
}

# Writes PKGS vulnerabilities in markdown table.
#
# Brief: Writes to destination file the skeleton of the markdown table with the right padding,
# iterates over the item_ids from expected files and for each item_id extracts: name, version and
# an array of pairs with the CVE ID and the vulnerability source and calls a helper function.
#
function pkgs_vulnerabilities() {
    local longest_name=$1
    local longest_version=$2
    local readme_filepath=$3
    local test_case=$4
    local file_id=$5
    shift 5
    local item_ids=("$@")
    {
        echo "### Vulnerabilities"
        echo
        echo -n "| Name "
        print_repeated_character " " $((longest_name - ${NAME_PADING}))
        echo -n "| Version "
        print_repeated_character " " $((longest_version - ${VERSION_PADING}))
        if [[ $readme_filepath =~ "positive" ]]; then
            echo "| CVE IDs      "
        else
            echo -n "| CVE IDs      "
            echo "| Feed"
        fi
        echo -n "|"
        print_repeated_character "-" $((longest_name))
        echo -n "|"
        print_repeated_character "-" $((longest_version))
        if [[ $readme_filepath =~ "positive" ]]; then
            echo "|--------------"
        else
            echo -n "|--------------|"
            print_repeated_character "-" ${MAX_SOURCE_LENGTH}
            echo
        fi
    } >>"${readme_filepath}"
    for item_id in ${item_ids[@]}; do
        IFS=$'\t' read -r name version < <(jq -r ".packages[]|select(.item_id == ${item_id})|[.name, .version]|@tsv" "${input_filepath}" | sed "s/'//g")
        unset IFS
        # Get CVEs for packages
        readarray -t vuln_info < <(jq -r ".[]|select(.item_id == ${item_id})|[.id, .source]|@sh" "${test_case}/expected_${file_id}.json")
        if [ ${#vuln_info[@]} -eq 0 ]; then
            readarray -t vuln_info < <(jq -r ".[]|[.id, .source]|@sh" "${test_case}/expected_${file_id}.json")
        fi
        # Print pkg vulnerabilities information for each input.
        _pkg_vulnerabilities "$longest_name" "$longest_version" "$readme_filepath" "$name" "$version" "${vuln_info[@]}"
    done
}

# Writes OS vulnerabilities in markdown table.
#
# Brief: Extract from expected files the CVE ids and Vulnerability source information
# as an array of pairs. Then iterates over them to write the information to the destination file.
#
function os_vulnerabilities() {
    local readme_filepath=$1
    local test_case=$2
    local file_id=$3
    readarray -t vuln_info < <(jq -r ".[]|[.id, .source]|@sh" "${test_case}/expected_${file_id}.json")
    {
        echo
        echo "### Vulnerabilities"
        echo
        if [[ $readme_filepath =~ "positive" ]]; then
            echo "| CVE IDs      "
            echo "|--------------"
        else
            echo "| CVE IDs      | Feed"
            echo -n "|--------------|"
            print_repeated_character "-" ${MAX_SOURCE_LENGTH}
            echo
        fi
    } >>"${readme_filepath}"
    for cve_source in "${vuln_info[@]}"; do
        read -r cve source <<<$(echo $cve_source | sed "s/'//g")
        {
            if [ ${#cve} -eq ${CVE_PADDING} ]; then
                cve=$cve" "
            fi
            if [[ $readme_filepath =~ "positive" ]]; then
                echo "|$cve"
            else
                echo -n "|$cve|"
                echo $source
            fi
        } >>"${readme_filepath}"
    done
}

function run_directory() {
    local folder=$1
    local cases=$2
    if [[ ${cases} =~ "," ]]; then
        cases="{${cases}}"
    fi
    for test_case in $(eval echo ${BASE_DIR}${folder}/${cases}); do
        if [ -d "$test_case" ]; then
            # Clean previous file, and generate description and event title.
            readme_filepath="${test_case}/${FILENAME}"
            rm "${readme_filepath}"
            print_desc_to_file "${readme_filepath}"
            # Iterate all inputs for each test case folder.
            for input_filepath in ${test_case}/input*; do
                # Get the input ID.
                file_id=$(echo "$input_filepath" | cut -d '.' -f 2 | cut -d '_' -f 7)
                # Print event ID title.
                echo >>"${readme_filepath}"
                echo "## Event ID: ${file_id}" >>"${readme_filepath}"
                # Get OS name, version and type.
                IFS=$'\t' read -r os_name os_version <<<$(jq -r '[.os.name, .os.version]|@tsv' "${input_filepath}" | sed "s/'//g")
                unset IFS
                type=$(jq -r '.type' "${input_filepath}")
                # Set complete OS name including its version.
                complete_os=${os_name}
                if [[ ! "$os_name" =~ "Microsoft" ]] && [[ ! "$os_name" =~ "Arch" ]]; then
                    complete_os="${os_name} ${os_version}"
                fi
                # Check if packagelist or fullscan.
                if [[ "${type}" =~ "packagelist" ]]; then
                    # Replace category
                    sed -i "s/${CATEGORY_PLACEHOLDER}/package\/s/" "${readme_filepath}"
                    sed -i "s/OS\./OS and packages\/s./" "${readme_filepath}"
                    # Get all packages per input, print them in column.
                    pkgs=$(jq -cr '.packages[].name' "${input_filepath}" | LC_ALL=C sort -u | sed 's/^/- /')
                    echo "### Packages" >>"${readme_filepath}"
                    echo "${pkgs}" >>"${readme_filepath}"
                    # Get longest package name and version
                    longest_name=$(max_string_length "name" ${input_filepath})
                    longest_version=$(max_string_length "version" ${input_filepath})
                    # Name lenght cannot be less than "name" lenght plus 2 (trailing and leading space)
                    if [ ${longest_name} -lt ${NAME_PADING} ]; then
                        longest_name=$NAME_PADING
                    fi
                    # Version lenght cannot be less than "version" lenght plus 2 (trailing and leading space)
                    if [ ${longest_version} -lt ${VERSION_PADING} ]; then
                        longest_version=${VERSION_PADING}
                    fi
                    readarray -t item_ids < <(jq '.packages[].item_id' "${input_filepath}")
                    pkgs_vulnerabilities "$longest_name" "$longest_version" "$readme_filepath" "$test_case" "$file_id" ${item_ids[@]}
                else
                    # Replace category OS.
                    sed -i "s/${CATEGORY_PLACEHOLDER}/OS/" "${readme_filepath}"
                    sed -i "s/packages\/s./OS and packages\/s./" "${readme_filepath}"
                    # Print complete OS name.
                    echo "### OS" >>"${readme_filepath}"
                    echo "- ${complete_os}" >>"${readme_filepath}"
                    # Print table for each input.
                    os_vulnerabilities "$readme_filepath" "$test_case" "$file_id"
                fi
            done
        echo "Doc generation for test case: ${test_case} completed"
        fi
    done
}

# Starting point
##################################################################

# Expected format:
# N=001,002,003 P=002,004 bash <script.sh>
FOLDERS=()

# Get false negative cases
if [ ! -z "$N" ]; then
    FOLDERS+=("test_false_negative_data")
fi

# Get false positive cases
if [ ! -z "$P" ]; then
    FOLDERS+=("test_false_positive_data")
fi

# If no test cases were set, run all
if [ ${#FOLDERS[@]} -eq 0 ]; then
    FOLDERS=("test_false_negative_data" "test_false_positive_data")
    N="*"
    P="*"
fi

# Iterate data directories.
for folder in ${FOLDERS[@]}; do
    if [ $folder == "test_false_negative_data" ]; then
        run_directory "$folder" "$N"
    elif [ $folder == "test_false_positive_data" ]; then
        run_directory "$folder" "$P"
    else
        echo "Invalid folder name"
    fi
done
