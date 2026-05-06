import pathlib
import sys
import unittest

_SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(_SRC_ROOT))
try:
    from ida_pro_mcp.arm64_branch_patch import assemble_supported_arm64_branch
finally:
    sys.path.remove(str(_SRC_ROOT))


class AssembleSupportedArm64BranchTests(unittest.TestCase):
    def test_bl_forward(self):
        encoded = assemble_supported_arm64_branch(0x1000, "bl 0x1100")
        self.assertEqual(encoded, bytes.fromhex("40000094"))

    def test_b_backward(self):
        encoded = assemble_supported_arm64_branch(0x1100, "b 0x1000")
        self.assertEqual(encoded, bytes.fromhex("c0ffff17"))

    def test_accepts_hash_prefix_and_case(self):
        encoded = assemble_supported_arm64_branch(0x1000, "BL #0x1004")
        self.assertEqual(encoded, bytes.fromhex("01000094"))

    def test_ignores_unsupported_syntax(self):
        self.assertIsNone(assemble_supported_arm64_branch(0x1000, "b.eq 0x1100"))
        self.assertIsNone(assemble_supported_arm64_branch(0x1000, "bl sub_1010"))
        self.assertIsNone(assemble_supported_arm64_branch(0x1000, "blr x0"))

    def test_rejects_unaligned_patch_address(self):
        with self.assertRaisesRegex(ValueError, "patch address must be 4-byte aligned"):
            assemble_supported_arm64_branch(0x1002, "bl 0x1100")

    def test_rejects_unaligned_target(self):
        with self.assertRaisesRegex(ValueError, "branch target must be 4-byte aligned"):
            assemble_supported_arm64_branch(0x1000, "bl 0x1102")

    def test_rejects_out_of_range_target(self):
        with self.assertRaisesRegex(ValueError, "out of range"):
            assemble_supported_arm64_branch(0x1000, "b 0x8001000")
