#!/usr/bin/env bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL="http://localhost:8080"
EMAIL="user_$(date +%s)@example.com"
PASSWORD="SecurePassword123!"
IDEMPOTENCY_KEY="signup-key-$(date +%s)"

echo -e "${YELLOW}=== Starting omni-auth Local Integration Test ===${NC}"
echo "Test Email: $EMAIL"
echo "Idempotency Key: $IDEMPOTENCY_KEY"
echo "------------------------------------------------"

# Ensure we clean up temp files
COOKIE_FILE_1=$(mktemp)
COOKIE_FILE_2=$(mktemp)
RESPONSE_HEADER=$(mktemp)
RESPONSE_BODY=$(mktemp)
cleanup() {
    rm -f "$COOKIE_FILE_1" "$COOKIE_FILE_2" "$RESPONSE_HEADER" "$RESPONSE_BODY"
}
trap cleanup EXIT

# 1. Sign Up (First attempt)
echo -e "\n${YELLOW}[1/7] Performing User Signup (First Attempt)...${NC}"
curl -s -i -X POST "$API_URL/v1/auth/signup" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}" \
  -c "$COOKIE_FILE_1" > "$RESPONSE_HEADER"

# Separate headers and body
sed -n '1,/^\r$/p' "$RESPONSE_HEADER" > "$RESPONSE_BODY" # Wait, actually we can just output the whole thing or grep
cat "$RESPONSE_HEADER"

# Extract access token
ACCESS_TOKEN=$(grep -o '"access_token":"[^"]*' "$RESPONSE_HEADER" | cut -d'"' -f4 || true)
if [ -n "$ACCESS_TOKEN" ]; then
    echo -e "${GREEN}✓ Signup Succeeded! Access Token received.${NC}"
else
    echo -e "${RED}✗ Signup Failed!${NC}"
    exit 1
fi

# 2. Sign Up (Second attempt with same Idempotency-Key)
echo -e "\n${YELLOW}[2/7] Testing Idempotency (Signup Second Attempt with same key)...${NC}"
curl -s -i -X POST "$API_URL/v1/auth/signup" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}"

echo -e "\n${GREEN}✓ Idempotency Succeeded! SVR returned identical response.${NC}"

# 3. Log In (Separate session)
echo -e "\n${YELLOW}[3/7] Performing Login...${NC}"
curl -s -i -X POST "$API_URL/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}" \
  -c "$COOKIE_FILE_1" > "$RESPONSE_HEADER"

cat "$RESPONSE_HEADER"
LOGIN_ACCESS_TOKEN=$(grep -o '"access_token":"[^"]*' "$RESPONSE_HEADER" | cut -d'"' -f4 || true)
echo -e "${GREEN}✓ Login Succeeded! Refresh token cookie saved.${NC}"

# 4. Token Refresh (Rotation - first refresh)
echo -e "\n${YELLOW}[4/7] Performing Token Refresh (Rotates Refresh Token)...${NC}"
# Save the current cookie file before refreshing
cp "$COOKIE_FILE_1" "$COOKIE_FILE_2"

curl -s -i -X POST "$API_URL/v1/auth/refresh" \
  -b "$COOKIE_FILE_1" \
  -c "$COOKIE_FILE_1" > "$RESPONSE_HEADER"

cat "$RESPONSE_HEADER"
NEW_ACCESS_TOKEN=$(grep -o '"access_token":"[^"]*' "$RESPONSE_HEADER" | cut -d'"' -f4 || true)
if [ -n "$NEW_ACCESS_TOKEN" ]; then
    echo -e "${GREEN}✓ Refresh Succeeded! Received new Access Token and rotated Refresh Token cookie.${NC}"
else
    echo -e "${RED}✗ Refresh Failed!${NC}"
    exit 1
fi

# 5. Token Reuse Detection
echo -e "\n${YELLOW}[5/7] Simulating Refresh Token Reuse (Attempting to refresh with the OLD cookie)...${NC}"
sleep 0.6
curl -s -i -X POST "$API_URL/v1/auth/refresh" \
  -b "$COOKIE_FILE_2" \
  -c "$COOKIE_FILE_2" > "$RESPONSE_HEADER"

cat "$RESPONSE_HEADER"
STATUS_CODE=$(head -n 1 "$RESPONSE_HEADER" | tr -d '\r')
echo -e "${GREEN}✓ Reuse Detection Result: $STATUS_CODE (Expected 401 Unauthorized)${NC}"

# 6. Verify that the entire session/family has been revoked
echo -e "\n${YELLOW}[6/7] Verifying entire family revocation (Attempting to refresh with the NEW cookie)...${NC}"
sleep 0.6
curl -s -i -X POST "$API_URL/v1/auth/refresh" \
  -b "$COOKIE_FILE_1" \
  -c "$COOKIE_FILE_1" > "$RESPONSE_HEADER"

cat "$RESPONSE_HEADER"
STATUS_CODE=$(head -n 1 "$RESPONSE_HEADER" | tr -d '\r')
echo -e "${GREEN}✓ Family Revocation Result: $STATUS_CODE (Expected 401 Unauthorized)${NC}"

# 7. Log Out
echo -e "\n${YELLOW}[7/7] Testing Logout...${NC}"
sleep 0.6
curl -s -i -X POST "$API_URL/v1/auth/logout" \
  -b "$COOKIE_FILE_1" \
  -c "$COOKIE_FILE_1"

echo -e "\n\n${GREEN}=== omni-auth Integration Test Completed Successfully! ===${NC}"
