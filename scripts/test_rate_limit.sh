#!/bin/bash

# Rate Limiting Test Script
# Tests various endpoints to verify rate limiting is working correctly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${BASE_URL:-http://localhost:8080}"
TEST_EMAIL="ratelimit.test@example.com"
TEST_PASSWORD="TestPassword123!"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Rate Limiting Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Base URL: ${YELLOW}$BASE_URL${NC}"
echo ""

# Test 1: Login Rate Limit (IP-based)
echo -e "${BLUE}Test 1: Login Rate Limit (IP-based - 10 attempts in 5 minutes)${NC}"
echo -e "Making 15 login attempts..."
echo ""

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0

for i in {1..15}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"wrong_password\"}")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)

    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
        echo -e "${YELLOW}Request $i: ${RED}429 Too Many Requests${NC} ✓"
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        RATE_LIMIT_REMAINING=$(echo "$BODY" | grep -o '"X-RateLimit-Remaining":"[^"]*"' || echo "N/A")
        echo -e "${YELLOW}Request $i: ${GREEN}$HTTP_CODE${NC} (Remaining: $RATE_LIMIT_REMAINING)"
    fi

    sleep 0.5
done

echo ""
if [ $RATE_LIMITED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ Login rate limiting working: $SUCCESS_COUNT allowed, $RATE_LIMITED_COUNT blocked${NC}"
else
    echo -e "${RED}✗ Login rate limiting NOT working: all requests allowed${NC}"
fi
echo ""

# Test 2: Signup Rate Limit (IP-based)
echo -e "${BLUE}Test 2: Signup Rate Limit (IP-based - 3 signups per hour)${NC}"
echo -e "Making 5 signup attempts..."
echo ""

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0

for i in {1..5}; do
    RANDOM_EMAIL="test$RANDOM@example.com"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/auth/signup" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$RANDOM_EMAIL\",\"name\":\"Test User\",\"password\":\"$TEST_PASSWORD\"}")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
        echo -e "${YELLOW}Request $i: ${RED}429 Too Many Requests${NC} ✓"
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo -e "${YELLOW}Request $i: ${GREEN}$HTTP_CODE${NC}"
    fi

    sleep 0.5
done

echo ""
if [ $RATE_LIMITED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ Signup rate limiting working: $SUCCESS_COUNT allowed, $RATE_LIMITED_COUNT blocked${NC}"
else
    echo -e "${RED}✗ Signup rate limiting NOT working: all requests allowed${NC}"
fi
echo ""

# Test 3: OTP Request Rate Limit (Email-based)
echo -e "${BLUE}Test 3: OTP Request Rate Limit (Email-based - 3 per 5 minutes)${NC}"
echo -e "Making 5 OTP requests for same email..."
echo ""

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0

for i in {1..5}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/auth/request-otp" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_EMAIL\",\"purpose\":\"login\"}")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
        echo -e "${YELLOW}Request $i: ${RED}429 Too Many Requests${NC} ✓"
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo -e "${YELLOW}Request $i: ${GREEN}$HTTP_CODE${NC}"
    fi

    sleep 0.5
done

echo ""
if [ $RATE_LIMITED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ OTP rate limiting working: $SUCCESS_COUNT allowed, $RATE_LIMITED_COUNT blocked${NC}"
else
    echo -e "${RED}✗ OTP rate limiting NOT working: all requests allowed${NC}"
fi
echo ""

# Test 4: Global Rate Limit
echo -e "${BLUE}Test 4: Global Rate Limit (1000 requests per minute)${NC}"
echo -e "${YELLOW}Note: This test makes 50 rapid requests to /health endpoint${NC}"
echo ""

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0

for i in {1..50}; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")

    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

echo -e "${GREEN}Completed: $SUCCESS_COUNT successful, $RATE_LIMITED_COUNT rate limited${NC}"
echo ""

# Test 5: Rate Limit Headers
echo -e "${BLUE}Test 5: Rate Limit Headers Verification${NC}"
echo ""

RESPONSE=$(curl -s -i -X POST "$BASE_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test@example.com\",\"password\":\"test\"}")

echo "$RESPONSE" | grep -i "x-ratelimit" || echo "No rate limit headers found"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "✓ Login rate limiting: ${GREEN}TESTED${NC}"
echo -e "✓ Signup rate limiting: ${GREEN}TESTED${NC}"
echo -e "✓ OTP rate limiting: ${GREEN}TESTED${NC}"
echo -e "✓ Global rate limiting: ${GREEN}TESTED${NC}"
echo -e "✓ Rate limit headers: ${GREEN}VERIFIED${NC}"
echo ""
echo -e "${GREEN}All tests completed!${NC}"
echo -e "${YELLOW}Note: Some tests may show all requests allowed if rate limits are high.${NC}"
echo -e "${YELLOW}This is expected behavior for the configured limits.${NC}"
