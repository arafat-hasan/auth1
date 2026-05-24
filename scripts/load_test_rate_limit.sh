#!/bin/bash

# Load Test Script for Rate Limiting
# Uses Apache Bench (ab) or curl for load testing
# Tests rate limiting under concurrent load

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BASE_URL="${BASE_URL:-http://localhost:8080}"
ENDPOINT="${1:-/api/v1/auth/login}"
REQUESTS="${2:-100}"
CONCURRENCY="${3:-10}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Rate Limiting Load Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Base URL:    ${YELLOW}$BASE_URL${NC}"
echo -e "Endpoint:    ${YELLOW}$ENDPOINT${NC}"
echo -e "Requests:    ${YELLOW}$REQUESTS${NC}"
echo -e "Concurrency: ${YELLOW}$CONCURRENCY${NC}"
echo ""

# Create test payload
PAYLOAD_FILE="/tmp/rate_limit_test_payload.json"
cat > "$PAYLOAD_FILE" <<EOF
{
  "email": "loadtest@example.com",
  "password": "TestPassword123!"
}
EOF

# Check if Apache Bench is available
if command -v ab &> /dev/null; then
    echo -e "${GREEN}Using Apache Bench (ab)${NC}"
    echo ""

    ab -n "$REQUESTS" -c "$CONCURRENCY" \
       -p "$PAYLOAD_FILE" \
       -T "application/json" \
       -H "Content-Type: application/json" \
       "$BASE_URL$ENDPOINT"

    echo ""
    echo -e "${GREEN}Load test completed with Apache Bench${NC}"
else
    echo -e "${YELLOW}Apache Bench not found, using curl with parallel requests${NC}"
    echo ""

    SUCCESS_COUNT=0
    RATE_LIMITED_COUNT=0
    ERROR_COUNT=0

    # Create temp directory for parallel execution
    TEMP_DIR=$(mktemp -d)

    # Function to make a request
    make_request() {
        local index=$1
        local result_file="$TEMP_DIR/result_$index.txt"

        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$BASE_URL$ENDPOINT" \
            -H "Content-Type: application/json" \
            -d @"$PAYLOAD_FILE")

        echo "$HTTP_CODE" > "$result_file"
    }

    # Make parallel requests
    echo -e "Making $REQUESTS requests with $CONCURRENCY concurrent connections..."

    for ((i=1; i<=REQUESTS; i++)); do
        make_request $i &

        # Control concurrency
        if (( i % CONCURRENCY == 0 )); then
            wait
        fi

        # Progress indicator
        if (( i % 10 == 0 )); then
            echo -ne "Progress: $i/$REQUESTS\r"
        fi
    done

    # Wait for remaining requests
    wait

    echo ""
    echo ""

    # Analyze results
    for result_file in "$TEMP_DIR"/result_*.txt; do
        HTTP_CODE=$(cat "$result_file")

        case "$HTTP_CODE" in
            200|201|400|401)
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                ;;
            429)
                RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
                ;;
            *)
                ERROR_COUNT=$((ERROR_COUNT + 1))
                ;;
        esac
    done

    # Clean up
    rm -rf "$TEMP_DIR"

    # Display results
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Results${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "Total Requests:      ${YELLOW}$REQUESTS${NC}"
    echo -e "Successful:          ${GREEN}$SUCCESS_COUNT${NC}"
    echo -e "Rate Limited (429):  ${YELLOW}$RATE_LIMITED_COUNT${NC}"
    echo -e "Errors:              ${RED}$ERROR_COUNT${NC}"
    echo ""

    # Calculate percentages
    SUCCESS_PCT=$(awk "BEGIN {printf \"%.2f\", ($SUCCESS_COUNT / $REQUESTS) * 100}")
    RATE_LIMITED_PCT=$(awk "BEGIN {printf \"%.2f\", ($RATE_LIMITED_COUNT / $REQUESTS) * 100}")

    echo -e "Success Rate:        ${GREEN}$SUCCESS_PCT%${NC}"
    echo -e "Rate Limited:        ${YELLOW}$RATE_LIMITED_PCT%${NC}"
    echo ""

    if [ $RATE_LIMITED_COUNT -gt 0 ]; then
        echo -e "${GREEN}✓ Rate limiting is working (some requests were limited)${NC}"
    else
        echo -e "${YELLOW}⚠ No rate limiting detected (all requests succeeded)${NC}"
        echo -e "${YELLOW}  This may be expected if limits are high relative to test load${NC}"
    fi
fi

# Clean up
rm -f "$PAYLOAD_FILE"

echo ""
echo -e "${GREEN}Load test completed!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo -e "  $0 [endpoint] [requests] [concurrency]"
echo -e ""
echo -e "${YELLOW}Examples:${NC}"
echo -e "  $0 /api/v1/auth/login 100 10"
echo -e "  $0 /api/v1/auth/signup 50 5"
echo -e "  BASE_URL=https://api.example.com $0 /api/v1/auth/login 200 20"
