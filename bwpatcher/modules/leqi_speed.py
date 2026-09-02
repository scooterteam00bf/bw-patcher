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

    # UART regional cap in 0.1 km/h units (35 km/h, same as Elite SPECIAL/Standard).
    REGION_LIMIT_VALUE = 0x15E

    def __init__(self, data: bytes):
        super().__init__(data)
        self.patched_speeds: Dict[str, int] = {}
        self._speed_block_patched = False
        self._inject_offset: Optional[int] = None
        self._hijack_offset: Optional[int] = None
        self._return_address: Optional[int] = None
        self._output_ptr: Optional[int] = None
        self._region_limit_patch_ofs: Optional[int] = None
        self._region_limit_store_ofs: Optional[int] = None

    def _speed_limit_fix(self) -> List[Tuple[str, str, str, str]]:
        """Regional bypass hook; default no-op for variants without it."""
        return []

    def _resolve_region_limit_sites(
        self,
        anchor: List[Optional[int]],
        stock_patch: List[int],
    ) -> Tuple[int, int]:
        if self._region_limit_patch_ofs is not None:
            assert self._region_limit_store_ofs is not None
            return self._region_limit_patch_ofs, self._region_limit_store_ofs

        sig_ofs = find_pattern(self.data, anchor)
        try:
            patch_slot = next(i for i, byte in enumerate(anchor) if byte is None)
        except StopIteration as exc:
            raise Exception("Region limit anchor has no patch-slot wildcards") from exc

        patch_len = sum(1 for byte in anchor if byte is None)
        if patch_len != len(stock_patch):
            raise Exception(
                f"Region limit stock patch length {len(stock_patch)} "
                f"does not match anchor wildcards ({patch_len})"
            )

        patch_ofs = sig_ofs + patch_slot
        store_ofs = sig_ofs + len(anchor) - 2
        self._region_limit_patch_ofs = patch_ofs
        self._region_limit_store_ofs = store_ofs
        return patch_ofs, store_ofs

    def _apply_region_limit_movw_branch(
        self,
        anchor: List[Optional[int]],
        stock_patch: List[int],
        reg: str,
        patch_name: str,
    ) -> List[Tuple[str, str, str, str]]:
        value = self.REGION_LIMIT_VALUE

        try:
            patch_ofs, store_ofs = self._resolve_region_limit_sites(anchor, stock_patch)
        except SignatureException:
            return []

        asm = f"movw {reg}, #{hex(value)}\nb {hex(store_ofs)}"
        post = self.assembly(asm, patch_ofs)
        if len(post) != len(stock_patch):
            raise Exception(
                f"Region limit patch @0x{patch_ofs:X}: expected {len(stock_patch)} bytes, "
                f"got {len(post)}"
            )

        pre = bytes(self.data[patch_ofs:patch_ofs + len(post)])
        if pre == post:
            return []

        stock = bytes(stock_patch)
        if pre == stock:
            self.data[patch_ofs:patch_ofs + len(post)] = post
            return [(patch_name, hex(patch_ofs), pre.hex(), post.hex())]

        raise Exception(
            f"Region limit patch @0x{patch_ofs:X}: expected {stock.hex()}, found {pre.hex()}"
        )

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

    def _read_ldr_pc_literal(self, insn_offset: int) -> int:
        """Decode a 16-bit Thumb `ldr Rt, [pc, #imm]` and read its literal pool word."""
        insn = self.data[insn_offset:insn_offset + 2]
        if len(insn) != 2:
            raise Exception(f"ldr @0x{insn_offset:X}: truncated instruction")

        hw = insn[0] | (insn[1] << 8)
        imm = (hw & 0xFF) * 4
        pc = (insn_offset + 4) & ~3
        literal_addr = pc + imm
        if literal_addr + 4 > len(self.data):
            raise Exception(
                f"ldr @0x{insn_offset:X}: literal pool @0x{literal_addr:X} out of range"
            )
        return struct.unpack_from('<I', self.data, literal_addr)[0]

    def _find_tail_zero_padding(self, min_size: int, search_window: int = 0x800) -> int:
        """Locate the largest zero run in the firmware tail (inject padding)."""
        search_from = max(0, len(self.data) - search_window)
        best_start: Optional[int] = None
        best_len = 0

        offset = search_from
        while offset < len(self.data):
            if self.data[offset] != 0:
                offset += 1
                continue

            run_end = offset
            while run_end < len(self.data) and self.data[run_end] == 0:
                run_end += 1
            run_len = run_end - offset
            if run_len >= min_size and run_len > best_len:
                best_start = offset
                best_len = run_len
            offset = run_end

        if best_start is None:
            raise Exception(
                f"No zero padding >= {min_size} bytes found in last 0x{search_window:X} bytes"
            )
        return best_start

    def _resolve_speed_padding_sites(
        self,
        anchor: List[int],
        hijack_size: int,
        output_ptr_ldr_offset: int,
        min_padding_size: int,
    ) -> None:
        if self._hijack_offset is not None:
            assert self._inject_offset is not None
            assert self._return_address is not None
            assert self._output_ptr is not None
            return

        sig_ofs = find_pattern(self.data, anchor)
        if hijack_size > len(anchor):
            raise Exception(
                f"Speed calc hijack size {hijack_size} exceeds anchor length {len(anchor)}"
            )
        if output_ptr_ldr_offset + 2 > len(anchor):
            raise Exception("output_ptr_ldr_offset must fall within speed calc anchor")

        self._hijack_offset = sig_ofs
        self._return_address = sig_ofs + len(anchor)
        self._output_ptr = self._read_ldr_pc_literal(sig_ofs + output_ptr_ldr_offset)
        self._inject_offset = self._find_tail_zero_padding(min_padding_size)

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

    Hijacks a 4-byte instruction run with b.w into tail zero padding. Hijack,
    return, output pointer, and inject sites are resolved via pattern matching.
    """

    SIG_SPEED_CALC_ANCHOR: List[int]
    HIJACK_SIZE: int = 4
    OUTPUT_PTR_LDR_OFFSET: int
    MIN_PADDING_SIZE: int = 64
    TAIL_SEARCH_WINDOW: int = 0x800

    def _locate_patch_offsets(self) -> None:
        try:
            self._resolve_speed_padding_sites(
                self.SIG_SPEED_CALC_ANCHOR,
                self.HIJACK_SIZE,
                self.OUTPUT_PTR_LDR_OFFSET,
                self.MIN_PADDING_SIZE,
            )
        except SignatureException as exc:
            raise Exception("Could not find speed calc signature for patching") from exc

    def _apply_hijack_patch(self) -> Tuple[str, str, str, str]:
        assert self._hijack_offset is not None
        assert self._inject_offset is not None
        return self._apply_bw_hijack(
            self._hijack_offset,
            self._inject_offset,
            self.SIG_SPEED_CALC_ANCHOR[:self.HIJACK_SIZE],
        )

    def _verify_inject_site(self, patch_bytes: bytes) -> None:
        assert self._inject_offset is not None
        self._verify_zero_padding(
            self._inject_offset,
            max(len(patch_bytes), self.MIN_PADDING_SIZE),
        )

    def _assemble_inject_block(self, asm_code: str) -> bytes:
        assert self._inject_offset is not None
        assert self._output_ptr is not None
        return self._assemble_with_literal_pool(
            asm_code, self._inject_offset, self._output_ptr
        )

