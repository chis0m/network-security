#!/usr/bin/env bash
#
# parse-snyk-report.sh - Parse Snyk vulnerability JSON reports
#

set -e

# Default keys
SNYK_DEFAULT_KEYS=(
    title
    package
    version
    severity
    cvss
    cve
    cwe
    fixed_in
)

# Optional keys
SNYK_OPTIONAL_KEYS=(
    title
    package
    version
    severity
    cvss
    cve
    cwe
    fixed_in
    exploit
    description
    references
)

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $0 -f FILE [OPTIONS]

Parse vulnerability scan results from Snyk JSON output.

Required:
  -f, --file FILE        Path to Snyk JSON report

Optional:
  -o, --output KEYS      Comma-separated keys to display
  -v, --verbose          Show descriptions and references
  -s, --summary          Show only summary counts
  -h, --help             Show this help

Available keys:
  title, package, version, severity, cvss, cve, cwe, fixed_in, exploit, description, references

Examples:
  $0 -f snyk.json
  $0 -f snyk.json -o title,package,severity,cve
  $0 -f snyk.json -s
EOF
}

# Parse args
FILE=""
OUTPUT_KEYS=""
VERBOSE=false
SUMMARY_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_KEYS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--summary)
            SUMMARY_ONLY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate
if [[ -z "$FILE" ]]; then
    echo -e "${RED}Error: -f is required${NC}"
    usage
    exit 1
fi

if [[ ! -f "$FILE" ]]; then
    echo -e "${RED}Error: File not found: $FILE${NC}"
    exit 1
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required. Install with: apt install jq${NC}"
    exit 1
fi

# Default keys
if [[ -z "$OUTPUT_KEYS" ]]; then
    OUTPUT_KEYS=$(IFS=','; echo "${SNYK_DEFAULT_KEYS[*]}")
fi

print_separator() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_header() {
    echo -e "\n${BOLD}${BLUE}$1${NC}"
}

print_field() {
    local label="$1"
    local value="$2"
    local color="${3:-$NC}"
    [[ -n "$value" && "$value" != "null" ]] && echo -e "  ${BOLD}$label:${NC} $color$value$NC"
}

# --- Snyk parser ---
parse_snyk() {
    local count
    count=$(jq -r '.vulnerabilities | length' "$FILE" 2>/dev/null || echo "0")

    if [[ "$SUMMARY_ONLY" == true ]]; then
        echo -e "\n${BOLD}Snyk Summary${NC}"
        print_separator
        echo -e "  Total vulnerabilities: ${BOLD}$count${NC}"

        if [[ $count -gt 0 ]]; then
            echo -e "\n  By severity:"
            jq -r '.vulnerabilities[].severity // "unknown" | ascii_upcase' "$FILE" | sort | uniq -c | while read num sev; do
                echo "    $sev: $num"
            done

            echo -e "\n  By package:"
            jq -r '.vulnerabilities[].packageName' "$FILE" | sort | uniq -c | sort -rn | head -10 | while read num pkg; do
                echo "    $pkg: $num"
            done
        fi
        return
    fi

    echo -e "\n${BOLD}Snyk Vulnerabilities ($count total)${NC}"
    print_separator

    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No vulnerabilities found.${NC}"
        return
    fi

    IFS=',' read -ra KEYS <<< "$OUTPUT_KEYS"
    local i=0

    while read -r vuln; do
        [[ -z "$vuln" ]] && continue
        i=$((i + 1))

        print_header "Vulnerability #$i"

        for key in "${KEYS[@]}"; do
            key=$(echo "$key" | xargs)

            case $key in
                title)     print_field "Title"       "$(echo "$vuln" | jq -r '.title')" "$RED" ;;
                package)   print_field "Package"     "$(echo "$vuln" | jq -r '.packageName')" "$YELLOW" ;;
                version)   print_field "Version"     "$(echo "$vuln" | jq -r '.version')" ;;
                severity)  print_field "Severity"    "$(echo "$vuln" | jq -r '.severity | ascii_upcase')" "$RED" ;;
                cvss)      print_field "CVSS Score"  "$(echo "$vuln" | jq -r '.cvssScore // empty')" ;;
                cve)       print_field "CVE"         "$(echo "$vuln" | jq -r '.identifiers.CVE[0] // empty')" "$YELLOW" ;;
                cwe)       print_field "CWE"         "$(echo "$vuln" | jq -r '.identifiers.CWE[0] // empty')" ;;
                fixed_in)  print_field "Fixed In"    "$(echo "$vuln" | jq -r '.fixedIn[0] // empty')" "$GREEN" ;;
                exploit)   print_field "Exploit"     "$(echo "$vuln" | jq -r '.exploit // empty')" ;;
                description)
                    [[ "$VERBOSE" == true ]] && print_field "Description" \
                    "$(echo "$vuln" | jq -r '.description | split("\n")[0:5] | join("\n")')"
                    ;;
                references)
                    [[ "$VERBOSE" == true ]] && echo "$vuln" | jq -r '.references[].url // empty' | while read ref; do
                        [[ -n "$ref" ]] && echo -e "  ${BOLD}Ref:${NC} $ref"
                    done
                    ;;
            esac
        done

        echo ""
    done < <(jq -c '.vulnerabilities[]' "$FILE")
}

# Main
echo -e "${BOLD}Snyk Vulnerability Report Parser${NC}"
echo -e "File: ${CYAN}$FILE${NC} | Keys: ${CYAN}$OUTPUT_KEYS${NC}"

parse_snyk

echo ""
