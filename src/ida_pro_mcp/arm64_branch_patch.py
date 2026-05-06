from __future__ import annotations

import re

_A64_OP_B = 0x14000000
_A64_OP_BL = 0x94000000
_IMM26_MASK = 0x3FFFFFF
_IMM26_SIGNED_HI = 1 << 25
_SUPPORTED_A64_BRANCH_RE = re.compile(
    r"^(?P<mnemonic>b|bl)\s+(?:#\s*)?(?P<target>0[xX][0-9a-fA-F]+)$",
    re.IGNORECASE,
)


def _encode_branch_imm26(opcode_top: int, src_ea: int, dst_ea: int) -> bytes | None:
    delta = int(dst_ea) - int(src_ea)
    if delta & 3:
        return None
    imm = delta // 4
    if imm < -_IMM26_SIGNED_HI or imm > _IMM26_SIGNED_HI - 1:
        return None
    word = int(opcode_top) | (imm & _IMM26_MASK)
    return word.to_bytes(4, "little")


def assemble_supported_arm64_branch(ea: int, asm: str) -> bytes | None:
    """
    Encode a very small AArch64 branch subset without relying on IDA's assembler.

    Supported forms are limited to unconditional immediate branches with absolute
    hexadecimal targets:
    - ``b 0x...``
    - ``bl 0x...``
    - ``b #0x...``
    - ``bl #0x...``

    Returns ``None`` when ``asm`` is outside this guaranteed-correct subset.
    Raises ``ValueError`` when the syntax matches the subset but the requested
    branch cannot be encoded safely.
    """
    match = _SUPPORTED_A64_BRANCH_RE.fullmatch(asm.strip())
    if match is None:
        return None

    src_ea = int(ea)
    dst_ea = int(match.group("target"), 16)
    if src_ea & 3:
        raise ValueError(
            f"AArch64 patch address must be 4-byte aligned: {hex(src_ea)}"
        )
    if dst_ea & 3:
        raise ValueError(
            f"AArch64 branch target must be 4-byte aligned: {hex(dst_ea)}"
        )

    mnemonic = match.group("mnemonic").lower()
    opcode_top = _A64_OP_BL if mnemonic == "bl" else _A64_OP_B
    encoded = _encode_branch_imm26(opcode_top, src_ea, dst_ea)
    if encoded is None:
        raise ValueError(
            "AArch64 branch target is out of range for imm26 encoding"
        )
    return encoded

