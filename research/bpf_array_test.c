/* bpf_array_test.c - does BPF_MAP_UPDATE_ELEM on an ARRAY map really store the value?
 *
 * This is the acceptance test for the MediaTek ALPS05247589 bug and for any patch:
 *   - on the STOCK kernel: "BUG PRESENT" confirms the kernel is affected
 *   - on a PATCHED kernel: must print "OK", otherwise the patch did not fix it
 * The bug skips the memcpy() for non-zero slot offsets, so index 0 works and 1..3 do not.
 *
 * Build (Termux):  pkg install clang && clang -O2 -o bpf_array_test bpf_array_test.c
 * Build (NDK):     $NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android30-clang -O2 -o bpf_array_test bpf_array_test.c
 * Run (root):      su -c ./bpf_array_test
 */
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long sys_bpf(int cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(void) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_type = BPF_MAP_TYPE_ARRAY;
    a.key_size = 4;
    a.value_size = 8;
    a.max_entries = 4;
    int fd = (int)sys_bpf(BPF_MAP_CREATE, &a);
    if (fd < 0) {
        fprintf(stderr, "BPF_MAP_CREATE failed: %s (run as root; SELinux may also block it)\n", strerror(errno));
        return 2;
    }

    int bad = 0;
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t want = 0x1111111100000000ULL + i + 1, got = 0;

        memset(&a, 0, sizeof(a));
        a.map_fd = fd;
        a.key = (uint64_t)(uintptr_t)&i;
        a.value = (uint64_t)(uintptr_t)&want;
        a.flags = BPF_ANY;
        long u = sys_bpf(BPF_MAP_UPDATE_ELEM, &a);
        int ue = errno;

        memset(&a, 0, sizeof(a));
        a.map_fd = fd;
        a.key = (uint64_t)(uintptr_t)&i;
        a.value = (uint64_t)(uintptr_t)&got;
        long l = sys_bpf(BPF_MAP_LOOKUP_ELEM, &a);

        int ok = (u == 0 && l == 0 && got == want);
        printf("index %u: update=%ld%s lookup=%ld read=0x%016llx %s\n", i, u,
               u ? strerror(ue) : "", l, (unsigned long long)got, ok ? "ok" : "MISMATCH");
        bad |= !ok;
    }
    puts(bad ? "RESULT: BUG PRESENT - updates are dropped or rejected"
             : "RESULT: OK - all array updates stored and read back");
    return bad;
}
