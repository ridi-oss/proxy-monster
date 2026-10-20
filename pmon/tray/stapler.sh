#!/usr/bin/env bash
# `xcrun stapler` with retries: it looks the ticket up in Apple's CloudKit, and that connection drops on CI
# runners ("The network connection was lost.", exit 68).
#
#   ./stapler.sh staple|validate <path>
set -uo pipefail

for attempt in 1 2 3 4; do
    xcrun stapler "$@"
    status=$?
    if [ "$status" = 0 ] || [ "$attempt" = 4 ]; then
        exit "$status"
    fi
    sleep $((attempt * 15))
done
