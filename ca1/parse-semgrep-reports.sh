#!/usr/bin/env bash
#
# parse-semgrep-report.sh - Parse Semgrep JSON reports
#

set -e

# Default keys
SEMGREP_DEFAULT_KEYS=(
    check_id
    path
    line
    message
    severity
    cwe
    fix
)

# Optional keys
SEMGREP_OPTIONAL_KEYS=(
    check_id
    path
    line
    col
    message
    severity
    cwe
    owasp
    fix
    source
    vulnerability_class
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

Parse Semgrep JSON scan results.

Required:
  -f, --file FILE        Path to Semgrep JSON report

Optional:
  -o, --output KEYS      Comma-separated keys to display
  -v, --verbose          Show references and extra metadata
  -s, --summary          Show only summary counts
  -h, --help             Show this help

Available keys:
  check_id, path, line, col, message, severity, cwe, owasp, fix, source, vulnerability_class

Examples:
  $0 -f semgrep.json
  $0 -f semgrep.json -o check_id,path,severity,message
  $0 -f semgrep.json -s
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
    OUTPUT_KEYS=$(IFS=','; echo "${SEMGREP_DEFAULT_KEYS[*]}")
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

# --- Semgrep parser ---
parse_semgrep() {
    local count
    count=$(jq -r '.results | length' "$FILE" 2>/dev/null || echo "0")

    if [[ "$SUMMARY_ONLY" == true ]]; then
        echo -e "\n${BOLD}Semgrep Summary${NC}"
        print_separator
        echo -e "  Total findings: ${BOLD}$count${NC}"

        if [[ $count -gt 0 ]]; then
            echo -e "\n  By severity:"
            jq -r '.results[].extra.severity // "UNKNOWN" | ascii_upcase' "$FILE" | sort | uniq -c | while read num sev; do
                echo "    $sev: $num"
            done

            echo -e "\n  By file:"
            jq -r '.results[].path' "$FILE" | sort | uniq -c | sort -rn | head -10 | while read num path; do
                echo "    $path: $num"
            done
        fi
        return
    fi

    echo -e "\n${BOLD}Semgrep Findings ($count total)${NC}"
    print_separator

    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No findings.${NC}"
        return
    fi

    IFS=',' read -ra KEYS <<< "$OUTPUT_KEYS"
    local i=0

    while read -r result; do
        [[ -z "$result" ]] && continue
        i=$((i + 1))

        print_header "Finding #$i"

        for key in "${KEYS[@]}"; do
            key=$(echo "$key" | xargs)

            case $key in
                check_id)   print_field "Rule"        "$(echo "$result" | jq -r '.check_id')" "$YELLOW" ;;
                path)       print_field "File"        "$(echo "$result" | jq -r '.path')" ;;
                line)       print_field "Line"        "$(echo "$result" | jq -r '.start.line')" ;;
                col)        print_field "Column"      "$(echo "$result" | jq -r '.start.col')" ;;
                message)    print_field "Message"     "$(echo "$result" | jq -r '.extra.message')" "$RED" ;;
                severity)   print_field "Severity"    "$(echo "$result" | jq -r '.extra.severity')" "$RED" ;;
                cwe)        print_field "CWE"         "$(echo "$result" | jq -r '.extra.metadata.cwe[0] // empty')" ;;
                owasp)      print_field "OWASP"       "$(echo "$result" | jq -r '.extra.metadata.owasp[0] // empty')" ;;
                fix)        print_field "Fix"         "$(echo "$result" | jq -r '.extra.fix // empty')" "$GREEN" ;;
                source)     print_field "Source"      "$(echo "$result" | jq -r '.extra.metadata.source // empty')" ;;
                vulnerability_class)
                    print_field "Vuln Class" "$(echo "$result" | jq -r '.extra.metadata.vulnerability_class[0] // empty')"
                    ;;
            esac
        done

        if [[ "$VERBOSE" == true ]]; then
            echo "$result" | jq -r '.extra.metadata.references[]? // empty' | while read ref; do
                [[ -n "$ref" ]] && echo -e "  ${BOLD}Ref:${NC} $ref"
            done
        fi

        echo ""
    done < <(jq -c '.results[]' "$FILE")
}

# Main
echo -e "${BOLD}Semgrep Report Parser${NC}"
echo -e "File: ${CYAN}$FILE${NC} | Keys: ${CYAN}$OUTPUT_KEYS${NC}"

parse_semgrep

echo ""
