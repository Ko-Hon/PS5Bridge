#!/bin/bash
set -euo pipefail
TASK_TEST_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
cd "$TASK_TEST_DIR"
mkdir -p .build
xcrun swiftc -module-cache-path "$TASK_TEST_DIR/.build/module-cache" -swift-version 5 -D BRIDGE_TESTS -parse-as-library Sources/Shared.swift Tests/CoreTests.swift -o .build/CoreTests
.build/CoreTests "$TASK_TEST_DIR/.build/control-tests-$$"
xcrun swiftc -module-cache-path "$TASK_TEST_DIR/.build/module-cache" -swift-version 5 -parse-as-library Sources/Shared.swift Sources/Helper.swift -o .build/BridgeHelper
for TASK_LEGACY_COMMAND in --start --serve --stop; do
  if .build/BridgeHelper "$TASK_LEGACY_COMMAND" > .build/entry-check.txt 2>&1; then
    echo "Legacy entry unexpectedly accepted"; exit 1
  fi
  rg -q '旧版内核转发入口已永久移除' .build/entry-check.txt
done
if rg -n 'pfctl|net\.inet\.ip\.(forwarding|redirect)=|route-to|reply-to|activeRules|pausedRules' Sources; then
  echo "Forbidden kernel-forwarding implementation found"; exit 1
fi
TASK_GO_BIN="${TASK_GO_BIN:-$TASK_TEST_DIR/../toolchains/go/bin/go}"
if [[ ! -x "$TASK_GO_BIN" ]]; then TASK_GO_BIN="$(command -v go)"; fi
export GOPATH="${GOPATH:-$TASK_TEST_DIR/../go-cache}"
export GOCACHE="${GOCACHE:-$TASK_TEST_DIR/../go-build-cache}"
(cd Relay && "$TASK_GO_BIN" test -mod=vendor -race -v -timeout 60s . && "$TASK_GO_BIN" vet -mod=vendor .)
