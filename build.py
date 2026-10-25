#!/usr/bin/env python3
"""Patch MediaTek BPF array-map bug in one or more boot images (POCO M4 Pro 4G / fleur).

    python3 build.py input/boot_a.img input/boot_b.img        # what CI runs
    python3 build.py input/boot_a.img --dry-run                # only look for the patch sites
    python3 build.py a.img --magiskboot /path/to/magiskboot --out out/

For EACH image (processed independently; one image failing never hides another's result):
  1. magiskboot unpack
  2. locate the MTK bounds-check using the upstream mtk-bpf-patcher signatures (1..MAX_HITS
     matches, each must decode as `cbnz w8, <label>`) and replace each cbnz with a NOP.
     No match is reported as "no match", never guessed: the kernel is either not affected
     or compiled in a shape these signatures do not cover.
  3. independent diff check: only the expected 4-byte windows changed, each is a NOP
  4. magiskboot repack, unpack the result again, confirm the patched kernel survived and
     every other component is byte-identical to the original
  5. write <out>/<image name>-bpf-patched.img

Also writes <out>/patch_report.json and <out>/SHA256SUMS.txt, and (in GitHub Actions) a
table to the job summary. Exit code 1 if any image FAILED or if nothing was patched.

Only the SITES block below knows anything about the patch itself.
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# AArch64 NOP is 0xD503201F. The image is little-endian, so in the FILE it is 1f 20 03 d5.
# (d5 03 20 1f in file order decodes as `fnmadd s21, s30, s0, s0`, not a nop.)
NOP = struct.pack("<I", 0xD503201F)
assert NOP == b"\x1f\x20\x03\xd5"

# ------------------------------------------------------------------------------------
# THE PATCH - edit here and nowhere else.
# Signatures are R0rt1z2/mtk-bpf-patcher's, for 4.14.x / 4.19.x, bytes as stored in the file.
# MediaTek's ALPS05247589 compiles to a `cbnz w8, <skip>` that jumps over the memcpy() in
# array_map_update_elem() whenever the slot offset is non-zero. Each signature contains that
# cbnz at byte offset `at`; it is replaced by a NOP so the memcpy() always runs.
# ------------------------------------------------------------------------------------
SITES = {
    "index math, then cbnz": {"sig": "0a2450292801080a087d0a1b28010035", "at": 12},
    "cbnz before memcpy args": {"sig": "48010035822240b980420491e10313aa", "at": 0},
}
MAX_HITS = 4  # more matches than this means the signature is not specific enough here
# ------------------------------------------------------------------------------------

COMPONENTS = ("ramdisk.cpio", "dtb", "kernel_dtb", "second", "extra", "recovery_dtbo")
IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


class BuildError(Exception):
    """This image cannot be processed (bad image, failed verification, tool error)."""


class NoMatch(BuildError):
    """The kernel has no known signature. Not an error in the image; nothing to patch."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_all(data, pat):
    hits, i = [], data.find(pat)
    while i >= 0:
        hits.append(i)
        i = data.find(pat, i + 1)
    return hits


def is_cbnz_w8(word):
    """True for `cbnz w8, <label>` (32-bit form, Rt = w8)."""
    return word & 0xFF00001F == 0x35000008


def find_sites(kernel):
    """Return [(name, file offset of the cbnz)]. Raises NoMatch / BuildError, fails closed."""
    sites = []
    for name, s in SITES.items():
        sig = bytes.fromhex(s["sig"])
        for hit in find_all(kernel, sig):
            off = hit + s["at"]
            if off % 4:
                raise BuildError(f"{name}: unaligned match at 0x{off:x}")
            if not is_cbnz_w8(struct.unpack_from("<I", kernel, off)[0]):
                raise BuildError(f"{name}: word at 0x{off:x} is not `cbnz w8`")
            sites.append((name, off))
    if not sites:
        done = sum(
            len(find_all(kernel, bytes.fromhex(s["sig"])[:s["at"]] + NOP + bytes.fromhex(s["sig"])[s["at"] + 4:]))
            for s in SITES.values()
        )
        if done:
            raise NoMatch(f"already patched ({done} patched sequence(s) found)")
        raise NoMatch("no signature found: kernel is not affected, or the check is compiled "
                      "differently. Run research/bpf_array_test.c on the device to confirm the "
                      "bug exists before patching anything")
    if len(sites) > MAX_HITS:
        raise BuildError(f"{len(sites)} matches (limit {MAX_HITS}): signature too generic for this kernel")
    return sites


def check_diff(orig, new, offsets):
    """Independent check: identical outside the windows, windows are NOPs, size unchanged."""
    if len(orig) != len(new):
        raise BuildError("patched kernel size differs from original")
    prev = 0
    for off in sorted(offsets):
        if orig[prev:off] != new[prev:off]:
            raise BuildError(f"unexpected change before 0x{off:x}")
        if new[off:off + 4] != b"\x1f\x20\x03\xd5":
            raise BuildError(f"0x{off:x} is {new[off:off + 4].hex()}, not a NOP (1f2003d5)")
        prev = off + 4
    if orig[prev:] != new[prev:]:
        raise BuildError("unexpected change after the last patch site")


def magiskboot(exe, *args, cwd):
    r = subprocess.run([str(exe), *map(str, args)], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        tail = (r.stdout + r.stderr).strip()[-600:]
        raise BuildError(f"magiskboot {' '.join(map(str, args))} failed ({r.returncode}): {tail}")


def process(image, mb, out, dry_run):
    data = image.read_bytes()
    result = {"image": image.name, "input_sha256": sha256(data), "input_size": len(data)}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        a, b = tmp / "a", tmp / "b"
        a.mkdir(), b.mkdir()
        src = a / "boot.img"
        src.write_bytes(data)

        magiskboot(mb, "unpack", "-h", src.name, cwd=a)
        if not (a / "kernel").exists():
            raise BuildError("no kernel in this image (is it really a boot image?)")
        orig_kernel = (a / "kernel").read_bytes()
        m = orig_kernel.find(b"Linux version ")
        if m >= 0:
            result["kernel_version"] = orig_kernel[m + 14:m + 80].split(b" ")[0].decode(errors="replace")

        try:
            sites = find_sites(orig_kernel)
        except NoMatch as e:
            e.kernel_version = result.get("kernel_version")
            raise
        offsets = [off for _, off in sites]
        patched = bytearray(orig_kernel)
        for off in offsets:
            patched[off:off + 4] = NOP
        patched = bytes(patched)
        check_diff(orig_kernel, patched, offsets)
        result["sites"] = [
            {"name": n, "offset": hex(o), "original": orig_kernel[o:o + 4].hex(), "replacement": NOP.hex()}
            for n, o in sites
        ]
        if dry_run:
            return {**result, "status": "would patch", "detail": f"{len(sites)} site(s)"}

        (a / "kernel").write_bytes(patched)
        out_img = tmp / "patched.img"
        magiskboot(mb, "repack", src, out_img, cwd=a)
        if out_img.stat().st_size > len(data):
            raise BuildError("repacked image is larger than the original")

        shutil.copy(out_img, b / "patched.img")
        magiskboot(mb, "unpack", "-h", "patched.img", cwd=b)
        if (b / "kernel").read_bytes() != patched:
            raise BuildError("patched kernel did not survive repack")
        for c in COMPONENTS:
            if (a / c).exists() != (b / c).exists() or ((a / c).exists() and (a / c).read_bytes() != (b / c).read_bytes()):
                raise BuildError(f"{c} changed or disappeared after repack")

        final = out / f"{image.stem}-bpf-patched.img"
        shutil.copy(out_img, final)
        result.update(
            status="patched",
            detail=f"{len(sites)} site(s), {4 * len(sites)} bytes changed",
            output=final.name,
            output_sha256=sha256(final.read_bytes()),
            kernel_original_sha256=sha256(orig_kernel),
            kernel_patched_sha256=sha256(patched),
        )
        return result


def write_summary(results):
    icon = {"patched": "✅", "would patch": "✅", "no match": "⚪", "FAILED": "❌"}
    lines = ["## Boot image patch results", "", "| image | kernel | result | detail |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| `{r['image']}` | {r.get('kernel_version', '?')} | {icon[r['status']]} {r['status']} | {r['detail']} |")
    lines += ["", "_Hardware tested: no. Flash only images marked patched, and keep a backup of the originals._"]
    text = "\n".join(lines) + "\n"
    print("\n" + text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("images", nargs="+", type=Path, help="boot images to patch (e.g. boot_a.img boot_b.img)")
    ap.add_argument("--magiskboot", type=Path, default=ROOT / ".ci-tools" / "magiskboot")
    ap.add_argument("--out", type=Path, default=ROOT / "output")
    ap.add_argument("--dry-run", action="store_true", help="look for the patch sites, write nothing")
    args = ap.parse_args()

    if not args.magiskboot.is_file():
        sys.exit(f"[!] magiskboot not found: {args.magiskboot} (run tools/fetch_magiskboot.sh)")
    stems = [p.stem for p in args.images]
    if len(set(stems)) != len(stems):
        sys.exit("[!] two input images have the same file name; rename one")
    args.out.mkdir(parents=True, exist_ok=True)

    results = []
    for image in args.images:
        print(f"[*] {image}")
        try:
            if not image.is_file():
                raise BuildError("file not found")
            r = process(image, args.magiskboot.resolve(), args.out, args.dry_run)
        except NoMatch as e:
            r = {"image": image.name, "status": "no match", "detail": str(e)}
            if getattr(e, "kernel_version", None):
                r["kernel_version"] = e.kernel_version
            if IN_ACTIONS:
                print(f"::warning title={image.name}::{e}")
        except BuildError as e:
            r = {"image": image.name, "status": "FAILED", "detail": str(e)}
            if IN_ACTIONS:
                print(f"::error title={image.name}::{e}")
        print(f"    -> {r['status']}: {r['detail']}")
        results.append(r)

    if not args.dry_run:
        done = [r for r in results if r["status"] == "patched"]
        (args.out / "patch_report.json").write_text(
            json.dumps({"hardware_tested": False, "results": results}, indent=2) + "\n")
        sums = "".join(f"{r['input_sha256']}  {r['image']}\n{r['output_sha256']}  {r['output']}\n" for r in done)
        if sums:
            (args.out / "SHA256SUMS.txt").write_text(sums)
    write_summary(results)

    ok = any(r["status"] in ("patched", "would patch") for r in results)
    failed = any(r["status"] == "FAILED" for r in results)
    sys.exit(0 if ok and not failed else 1)


if __name__ == "__main__":
    main()
