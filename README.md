# fleur_mt6781_bpf-patch-4.19-kernel

Patches the `boot_a` dump of a POCO M4 Pro 4G (fleur, MT6781, kernel
`4.19.325-cip129-st13-g4284dce0f576-dirty`) to work around the MediaTek `4.14`/`4.19`
"fix ubsan error" commit (`ALPS05247589`) that is reported to break BPF `arraymap`:
netd cannot register its maps, so Wi-Fi/mobile data show as connected but nothing routes.

The dump was taken with [`mtkclient`](https://github.com/bkerler/mtkclient) (BROM/Kamakiri).

## Status - read before flashing

**Hardware tested: no. None of the three kernels analysed so far contains the bug this repo targets.**

I disassembled `array_map_update_elem()` and `array_map_lookup_elem()` in each of them:

| kernel | `array_map_update_elem` | result |
|---|---|---|
| `4.19.191` (stock MIUI `boot.img`) | `0x15f6b8` | clean: flags / `-E2BIG` / `-EEXIST` / per-CPU / `(index & mask) * elem_size` + `memcpy`, no extra guard |
| `4.19.325-cip129-st13` (`boot_a`/`boot_b`) | `0x179bc4` | clean, same shape (plus BPF_F_LOCK handling) |
| `4.19.325-Fleux-V4+` (Infinity X 4.0 `boot_a`/`boot_b`, identical) | `0x176244` | clean, same shape |

Neither upstream `mtk-bpf-patcher` signature occurs in any of them, and all three have
`BPF_SYSCALL`, `BPF_JIT`, `CGROUP_BPF`, `NETFILTER_XT_MATCH_BPF`, `NET_CLS_BPF` and `XFRM_INTERFACE`
enabled (read from the embedded kernel config). So the arraymap/ubsan bug is not what is
breaking networking on these builds, and `build.py` correctly reports "no match".

The previous version of this repo patched two `tbz` branches at `0x178628` / `0x1786cc` of the
`cip129` kernel. Those are in an unrelated function (`0x178080`) and were also written as
`d5 03 20 1f`, which is not a NOP on a little-endian image (it decodes as
`fnmadd s21, s30, s0, s0`; a NOP is `1f 20 03 d5`). Do not flash anything built before this change.

To find the real cause on the device, as root: run `research/bpf_array_test.c` (array maps),
and capture `logcat -b all | grep -iE "netd|bpf|netbpfload|tethering"` and `dmesg | grep -i bpf`
right after boot.

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
bash tools/fetch_magiskboot.sh                     # pinned official Magisk APK -> .ci-tools/
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
