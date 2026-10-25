# fleur_mt6781_bpf-patch-4.19-kernel

Patches the `boot_a` dump of a POCO M4 Pro 4G (fleur, MT6781, kernel
`4.19.325-cip129-st13-g4284dce0f576-dirty`) to work around the MediaTek `4.14`/`4.19`
"fix ubsan error" commit (`ALPS05247589`) that is reported to break BPF `arraymap`:
netd cannot register its maps, so Wi-Fi/mobile data show as connected but nothing routes.

The dump was taken with [`mtkclient`](https://github.com/bkerler/mtkclient) (BROM/Kamakiri).

## Status - read before flashing

**Hardware tested: no. And for the shipped `boot_a` kernel there is currently nothing to patch.**

- The 4.19.325-cip129-st13 kernel in `boot_a` and `boot_b` (identical) has no MediaTek
  check in `array_map_update_elem()` (`0x179bc4`) or `array_map_lookup_elem()` (`0x179b90`):
  no `cbnz` after the index/`mul` math, no NOP where one was, and neither upstream
  `mtk-bpf-patcher` signature occurs anywhere in the image. `boot.img` (stock 4.19.191)
  does not contain them either. The kernel is therefore either unaffected or compiled in a
  shape these signatures do not cover.
- The previous version of this repo patched two `tbz` branches at `0x178628` / `0x1786cc`.
  Those are in a different function (`0x178080`: six arguments, `0x120` frame, writes
  `LIST_POISON2`), and they never matched the upstream pattern (`cbnz w8` that skips the
  memcpy). **Treat them as wrong.** They were also written as `d5 03 20 1f`, which is not a
  NOP on a little-endian image (it decodes as `fnmadd s21, s30, s0, s0`; a NOP is
  `1f 20 03 d5`). Do not flash anything built before this change (`output/`, `bpf-test-*`
  prereleases).

`build.py` now uses the upstream signatures and **aborts if none match**. To decide whether
your device is affected at all, run the acceptance test on the stock kernel as root:

```
clang -O2 -o bpf_array_test research/bpf_array_test.c && su -c ./bpf_array_test
```

`BUG PRESENT` (index 0 ok, 1..3 dropped or `EINVAL`) means the kernel is affected and the
signatures need extending for this build; `OK` means the no-internet problem has another cause.
After any patch is flashed the same test must print `OK`.

## One-click patching with GitHub Actions

1. **Provide your images** - either
   - create a release (any tag, e.g. `my-images`) and attach your boot images to it (`boot_a.img`,
     `boot_b.img`, or a custom ROM's `boot.img`; every `*.img` asset is patched, so attach only boot images)
     in the browser (release attachments go up to 2 GB; plain web upload of repo files stops at
     25 MB), or
   - commit them to `input/` (any `*.img` there is patched; a push to `input/` starts a run).
2. **Actions -> Patch boot images -> Run workflow.** Type the release tag, or leave it blank to use
   `input/`. Tick *publish_release* if you also want a prerelease.
3. **Download the `patched-boot-images` artifact** from the run page. The job summary shows a row
   per image: patched / no match / FAILED.

Each image is handled independently. Only images that were actually patched appear in the
artifact. The run goes red if any image FAILED or if nothing was patched. "No match" is not a
guess-and-patch: it means the kernel contains none of the known signatures (see Status).

Locally (Linux x86_64; elsewhere pass your own binary with `--magiskboot PATH`):

```
tools/fetch_magiskboot.sh                          # pinned official Magisk APK -> .ci-tools/
python3 build.py input/boot_a.img input/boot_b.img   # -> output/*-bpf-patched.img
python3 build.py input/boot_a.img --dry-run          # only look for the patch sites
```

No third-party Python packages are needed. For every image `build.py` checks that: at least one
upstream signature matches (at most 4 hits) and every hit decodes as `cbnz w8, <label>`; exactly
the expected 4-byte windows changed and are NOPs; the repacked image contains the patched kernel;
and every other boot component is unchanged.

## Changing the patch

Edit the `SITES` block at the top of `build.py` - it is the only place that
knows about offsets or byte patterns.

## Layout

| path | purpose |
|---|---|
| `build.py` | the whole pipeline |
| `tools/fetch_magiskboot.sh` | pinned, hash-verified magiskboot |
| `ci/` | pinned Magisk version and hashes |
| `input/` | optional place for your `boot_a.img` / `boot_b.img` |
| `research/` | reverse-engineering helpers (not used by the build) |
| `docs/research-log.md` | the earlier analysis notes, unchanged |

License: AGPL-3.0.
