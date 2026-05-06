// Minimal AArch64 fixture for patch_asm branch encoding tests.
// Rebuild example:
// NDK_BIN="../../tools/android-ndk/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin"
// "$NDK_BIN/clang" --target=aarch64-linux-gnu -fuse-ld=lld -nostdlib -no-pie \
//   -Wl,-m,aarch64linux -Wl,-e,_start arm64_patch_fixture.S -o arm64_patch_fixture.elf

    .text
    .global _start
    .global branch_site
    .global patch_target
    .global alternate_target

_start:
    bl branch_site
    mov x0, #0
    mov x8, #93
    svc #0

branch_site:
    bl patch_target
    ret

patch_target:
    ret

alternate_target:
    ret
