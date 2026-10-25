#!/usr/bin/env bash
# Download the pinned official Magisk APK, verify it, and extract magiskboot to .ci-tools/.
# Used by CI and locally (Linux x86_64). On other hosts pass your own binary: build.py --magiskboot PATH
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ci/magiskboot.env; set +a

mkdir -p .ci-tools
if [[ -x .ci-tools/magiskboot ]] && echo "$MAGISKBOOT_SHA256  .ci-tools/magiskboot" | sha256sum -c - >/dev/null 2>&1; then
  echo "magiskboot already present and verified"; exit 0
fi

curl --fail --location --retry 3 "$MAGISK_APK_URL" --output .ci-tools/magisk.apk
echo "$MAGISK_APK_SHA256  .ci-tools/magisk.apk" | sha256sum -c -
unzip -p .ci-tools/magisk.apk "$MAGISKBOOT_ENTRY" > .ci-tools/magiskboot
chmod +x .ci-tools/magiskboot
echo "$MAGISKBOOT_SHA256  .ci-tools/magiskboot" | sha256sum -c -
