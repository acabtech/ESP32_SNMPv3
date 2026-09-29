#!/bin/sh
# run_host_tests.sh — build and execute the host-side unit tests.
# Run from anywhere:  tests/host/run_host_tests.sh
set -e
cd "$(dirname "$0")"
make
./build/test_runner