#!/bin/bash

# Set color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Print header
echo -e "${GREEN}Running tests for wyrmlock${NC}"
echo "=============================="

# Create directories if they don't exist
mkdir -p test-reports

# Run tests with coverage
echo -e "${YELLOW}Running tests with coverage...${NC}"
go test -v -race -coverprofile=test-reports/coverage.out ./...

# Check if tests passed
if [ $? -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi

# Generate coverage report
echo -e "${YELLOW}Generating coverage report...${NC}"
go tool cover -html=test-reports/coverage.out -o test-reports/coverage.html
go tool cover -func=test-reports/coverage.out

# Display coverage summary
COVERAGE=$(go tool cover -func=test-reports/coverage.out | grep total | awk '{print $3}')
echo -e "${GREEN}Total coverage: ${COVERAGE}${NC}"

# Print completion message
echo -e "${GREEN}Test execution completed!${NC}"
echo "Coverage report generated at test-reports/coverage.html" 