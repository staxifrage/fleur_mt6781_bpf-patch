#!/usr/bin/env bash
# Run from anywhere inside the repo AFTER copying the new files over it.
# Everything is `git rm`, so it is reviewable (git status) and reversible
# (git restore --staged --worktree <path>). Nothing is committed for you.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# 1. generated / downloaded output must not be tracked (files stay on disk, now in .gitignore)
git rm -r -q --cached --ignore-unmatch .ci-tools work output

# 2. superseded code (build.py replaces the three patch/verify scripts; the locator is in research/)
git rm -q --ignore-unmatch tools/patch_kernel.py tools/patch_kernel.py.new \
  tools/verify_kernel_patch.py tools/find_mtk_arraymap_check.py

# 3. byte-identical duplicate of boot_a-current.img, and the old single-image hash pin
git rm -q --ignore-unmatch dump/boot_a-current.img ci/boot_a-current.img.sha256

git status --short
cat <<'MSG'

Left alone on purpose - your call:
  boot_a-current.img / boot_b-current.img   your dumps. CI now reads input/ or a release, so
                       move them out of the repo (or into input/ as boot_a.img / boot_b.img)
  boot.img             stock 4.19.191 kernel; keep as a backup, outside the repo if you can
  dump/{kernel,ramdisk.cpio,dtb}   reproducible with magiskboot; CI no longer reads them
Old releases / output images contain the broken "nop" - do not flash them (see README).
MSG
