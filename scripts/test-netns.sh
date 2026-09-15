#!/bin/sh
set -eu

test_binary=${1:-./build/netfilter-integration.test}
case "$test_binary" in
  /*) ;;
  *) test_binary="$(pwd)/${test_binary#./}" ;;
esac

mkdir -p "$(dirname "$test_binary")"
go test -tags=integration -c -o "$test_binary" ./internal/netfilter

if [ "$(id -u)" -eq 0 ]; then
  exec unshare --net --mount-proc "$test_binary" -test.v -test.run '^TestIntegration'
fi
exec sudo unshare --net --mount-proc "$test_binary" -test.v -test.run '^TestIntegration'
