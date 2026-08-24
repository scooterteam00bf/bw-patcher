#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher - Leqi Speed Limit Module (shared base)
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

import struct
from typing import List, Tuple, Dict, Optional
from bwpatcher.core_n32 import CoreN32Patcher
from bwpatcher.utils import find_pattern, SignatureException


class LeqiSpeedPatcher(CoreN32Patcher):
    """
    Shared speed-limit patcher for N32 (Leqi) controller firmware variants.

    Implements the methodology from 19-speed-limit-patch-methodology.md:
    hijack the speed-calc site, inject mode-aware logic, store result, return.
    Subclasses supply variant-specific offsets, hijack style, and assembly templates.
    """

    MODE_PEDESTRIAN = 1
    MODE_DRIVE = 2
    MODE_SPORT = 3

    MODE_ORDER = ('ped', 'drive', 'sport')

    def __init__(self, data: bytes):
        super().__init__(data)
        self.patched_speeds: Dict[str, int] = {}
        self._speed_block_patched = False
        self._inject_offset: Optional[int] = None

    def _speed_limit_fix(self) -> List[Tuple[str, str, str, str]]:
        """Regional bypass hook; default no-op for variants without it."""
        return []

    def _locate_patch_offsets(self) -> None:
        raise NotImplementedError

    def _apply_hijack_patch(self) -> Tuple[str, str, str, str]:
        raise NotImplementedError

    def _build_speed_logic_asm(self) -> str:
        raise NotImplementedError

    def _assemble_inject_block(self, asm_code: str) -> bytes:
        return self.assembly(asm_code, self._inject_offset)

    def _verify_inject_site(self, patch_bytes: bytes) -> None:
        """Verify inject region before first patch; no-op for dead-code variants."""

    def _build_mode_check_asm(
        self,
        mode_reg: str,
        speed_reg: str,
        patched_branch_target: str,
    ) -> str:
        """Build cmp/bne/movw chain for modes present in patched_speeds."""
        mode_map = {
            'ped': self.MODE_PEDESTRIAN,
            'drive': self.MODE_DRIVE,
            'sport': self.MODE_SPORT,
        }
        mode_checks = [m for m in self.MODE_ORDER if m in self.patched_speeds]
        asm_code = ""

        for i, mode in enumerate(mode_checks):
            mode_num = mode_map[mode]
            speed = self.patched_speeds[mode]
            next_label = (
                f"check_{mode_checks[i + 1]}"
                if i + 1 < len(mode_checks)
                else "default_case"
            )

            asm_code += f"""
            check_{mode}:
            cmp {mode_reg}, #{mode_num}
            bne {next_label}
            movw {speed_reg}, #{speed}
            b {patched_branch_target}
            """

        return asm_code

    def _patch_speed_block(
        self,
        ped_kmh: Optional[float] = None,
        drive_kmh: Optional[float] = None,
        sport_kmh: Optional[float] = None,
    ) -> List[Tuple[str, str, str, str]]:
        if ped_kmh is not None:
            self.patched_speeds['ped'] = self._calc_speed(ped_kmh, size=0)
        if drive_kmh is not None:
            self.patched_speeds['drive'] = self._calc_speed(drive_kmh, size=0)
        if sport_kmh is not None:
            self.patched_speeds['sport'] = self._calc_speed(sport_kmh, size=0)

        results: List[Tuple[str, str, str, str]] = []
        results.extend(self._speed_limit_fix())

        if not self._speed_block_patched:
            self._locate_patch_offsets()
            results.append(self._apply_hijack_patch())

        asm_code = self._build_speed_logic_asm()
        assert self._inject_offset is not None
        patch_bytes = self._assemble_inject_block(asm_code)

        if not self._speed_block_patched:
            self._verify_inject_site(patch_bytes)

        pre = self.data[self._inject_offset:self._inject_offset + len(patch_bytes)]
        self.data[self._inject_offset:self._inject_offset + len(patch_bytes)] = patch_bytes

        patch_name = (
            "speed_logic_block" if not self._speed_block_patched else "speed_constants_updated"
        )
        results.append((
            patch_name,
            hex(self._inject_offset),
            pre.hex(),
            patch_bytes.hex(),
        ))

        self._speed_block_patched = True
        return results

    def speed_limit_ped(self, kmh: float) -> List[Tuple[str, str, str, str]]:
        return self._patch_speed_block(ped_kmh=kmh)

    def speed_limit_drive(self, kmh: float) -> List[Tuple[str, str, str, str]]:
        return self._patch_speed_block(drive_kmh=kmh)

    def speed_limit_sport(self, kmh: float) -> List[Tuple[str, str, str, str]]:
        return self._patch_speed_block(sport_kmh=kmh)

    def _verify_hijack_bytes(self, offset: int, expected: List[int]) -> None:
        actual = bytes(self.data[offset:offset + len(expected)])
        expected_bytes = bytes(expected)
        if actual != expected_bytes:
            raise Exception(
                f"Hijack site @0x{offset:X}: expected {expected_bytes.hex()}, "
                f"found {actual.hex()}"
            )

    def _verify_zero_padding(self, offset: int, size: int) -> None:
        region = self.data[offset:offset + size]
        if any(b != 0 for b in region):
            raise Exception(
                f"Inject site @0x{offset:X} is not zero padding "
                f"({size} bytes required)"
            )

    def _apply_bw_hijack(
        self,
        hijack_offset: int,
        inject_offset: int,
        sig_hijack: List[int],
        patch_name: str = "hijack_speed_calc",
    ) -> Tuple[str, str, str, str]:
        self._verify_hijack_bytes(hijack_offset, sig_hijack)
        branch_asm = f"b.w {hex(inject_offset)}"
        branch_bytes = self.assembly(branch_asm, hijack_offset)
        if len(branch_bytes) != 4:
            raise Exception(f"Hijack branch must be 4 bytes, got {len(branch_bytes)}")

        pre = self.data[hijack_offset:hijack_offset + 4]
        self.data[hijack_offset:hijack_offset + 4] = branch_bytes
        return (patch_name, hex(hijack_offset), pre.hex(), branch_bytes.hex())

    def _build_padding_speed_logic_asm(
        self,
        reload_asm: str,
        mode_reg: str,
        speed_reg: str,
        ptr_reg: str,
        return_address: int,
        output_ptr: int,
    ) -> str:
        """Build self-contained inject block for padding-injection variants."""
        store_label = "store"
        patched_target = store_label

        asm_code = reload_asm + "\n"
        asm_code += f"and {mode_reg}, {mode_reg}, #3\n"
        asm_code += self._build_mode_check_asm(mode_reg, speed_reg, patched_target)
        asm_code += f"""
        default_case:
        add.w {speed_reg}, {speed_reg}, {speed_reg}, lsl #2
        lsls {speed_reg}, {speed_reg}, #1
        {store_label}:
        ldr {ptr_reg}, [pc, #4]
        strh {speed_reg}, [{ptr_reg}]
        b.w {hex(return_address)}
        """
        return asm_code

    def _assemble_with_literal_pool(
        self, asm_code: str, inject_offset: int, literal_value: int
    ) -> bytes:
        """Assemble inject block and append a 4-byte literal pool word."""
        code_bytes = self.assembly(asm_code, inject_offset)
        return code_bytes + struct.pack("<I", literal_value)


class LeqiPaddingSpeedPatcher(LeqiSpeedPatcher):
    """
    Leqi speed patcher using verified-zero padding for injected code (mi6, mi6lite).

    Hijacks a 4-byte instruction run with b.w into the padding region.
    """

    SIG_HIJACK: List[int]
    HIJACK_OFFSET: int
    INJECT_OFFSET: int
    RETURN_ADDRESS: int
    OUTPUT_PTR: int = 0x200001A2
    MIN_PADDING_SIZE: int = 64

    def _locate_patch_offsets(self) -> None:
        self._inject_offset = self.INJECT_OFFSET

    def _apply_hijack_patch(self) -> Tuple[str, str, str, str]:
        return self._apply_bw_hijack(
            self.HIJACK_OFFSET,
            self.INJECT_OFFSET,
            self.SIG_HIJACK,
        )

    def _verify_inject_site(self, patch_bytes: bytes) -> None:
        self._verify_zero_padding(self.INJECT_OFFSET, max(len(patch_bytes), self.MIN_PADDING_SIZE))

    def _assemble_inject_block(self, asm_code: str) -> bytes:
        return self._assemble_with_literal_pool(
            asm_code, self._inject_offset, self.OUTPUT_PTR
        )

