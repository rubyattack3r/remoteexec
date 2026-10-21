#!/usr/bin/env bash
set -euo pipefail

fixture_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${fixture_root}/../.." && pwd)"
output_directory="${1:-${repository_root}/.scratch/fixtures/bin}"

mkdir -p "${output_directory}"

GOOS=windows GOARCH=amd64 go build \
  -o "${output_directory}/command-probe.exe" \
  "${fixture_root}/payloads/command"
GOOS=windows GOARCH=amd64 go build \
  -o "${output_directory}/service-probe.exe" \
  "${fixture_root}/payloads/service"

x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -shared \
  -o "${output_directory}/launcher-probe.dll" \
  "${fixture_root}/launcher-contracts/native-dll/probe.c"
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -shared \
  -o "${output_directory}/control-probe.cpl" \
  "${fixture_root}/launcher-contracts/cpl/probe.c"
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -shared \
  -o "${output_directory}/wmi-provider-probe.dll" \
  "${fixture_root}/techniques/wmi-provider/provider.c" \
  "${fixture_root}/techniques/wmi-provider/exports.def" \
  -lole32 -lwbemuuid

printf 'Built native Windows fixtures in %s\n' "${output_directory}"
printf 'Build the managed fixture with build.ps1 on Windows.\n'
