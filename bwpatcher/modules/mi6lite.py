#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher - Mi 6 Lite Module
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

from typing import List, Optional, Tuple

from bwpatcher.modules.leqi_speed import LeqiPaddingSpeedPatcher
from bwpatcher.utils import SignatureException, find_pattern


class Mi6litePatcher(LeqiPaddingSpeedPatcher):
    """
    Patcher for Xiaomi Mi 6 Lite with N32 (Leqi) controller.

    Hijacks the speed-calc instructions with b.w into tail zero padding.
    Base pointer in r1, speed value in r0.
    """

    FIRMWARE_SIZE = 0xB000  # Fallback only; real size is read from the EU1 header (see
                             # docs/20-dynamic-firmware-size-detection.md)

    # UART cmd 0x21 telemetry path (FUN_0000270c): ldrb r0,[r1,#5] * 10 -> strh.
    # Hijacked with b.w into tail padding for mode-aware SLD/SLS/SLP limits.
    SIG_SPEED_CALC_ANCHOR = [
        0x48, 0x79, 0x54, 0x49,
        0x00, 0xEB, 0x80, 0x00,
        0x40, 0x00,
        0x08, 0x80,
    ]
    OUTPUT_PTR_LDR_OFFSET = 2
    # Skip 8 bytes of non-zero tail metadata (e.g. 0xAC40) before inject block.
    INJECT_PADDING_OFFSET = 8

    # UART cmd 0x21 regional cap tree in FUN_0000270c (~0x3226, jump-table dispatch).
    # Stock selects EU (movs #0xcf / 20.7 km/h) or GL (movw #0x101 / 25.7 km/h) and
    # stores the value to motor config struct field +0x28 via strh r1,[r7].
    SIG_REGION_LIMIT_ANCHOR: List[Optional[int]] = [
        0x67, 0x4F,
        None, None, None, None, None, None,
        0xD1, 0x18, 0x0B, 0xD0, 0x01, 0x29, 0x0C, 0xD1, 0x06, 0xE0,
        0x01, 0x28, 0x04, 0xD0, 0xA0, 0xF5, 0x80, 0x71, 0x1F, 0x39,
        0x05, 0xD1, 0x01, 0xE0, 0xCF, 0x21, 0x01, 0xE0, 0x40, 0xF2,
        0x01, 0x11, 0x39, 0x80,
    ]

    # v2 reference: three surgical edits relative to SIG_REGION_LIMIT_ANCHOR.
    REGION_CMP_BEQ_OFFSET = 4       # beq #EU_path -> b #EU_path
    REGION_SKIP_BRANCH_OFFSET = 0x22  # b #store -> nop (fall through to movw)
    REGION_MOVW_IMM_OFFSET = 0x26     # movw #0x101 -> #REGION_LIMIT_VALUE

    REGION_CMP_BEQ_STOCK = bytes([0x0C, 0xD0])
    REGION_CMP_BEQ_PATCH = bytes([0x0C, 0xE0])
    REGION_SKIP_BRANCH_STOCK = bytes([0x01, 0xE0])
    REGION_SKIP_BRANCH_PATCH = bytes([0x00, 0xBF])
    REGION_MOVW_IMM_STOCK = 0x01
    REGION_MOVW_IMM_PATCH = 0x5E

    def __init__(self, data: bytes):
        super().__init__(data)
        self._region_limit_sig_ofs: Optional[int] = None

    def _resolve_region_limit_anchor(self) -> int:
        if self._region_limit_sig_ofs is not None:
            return self._region_limit_sig_ofs

        try:
            sig_ofs = find_pattern(self.data, self.SIG_REGION_LIMIT_ANCHOR)
        except SignatureException:
            raise SignatureException("region limit anchor")

        self._region_limit_sig_ofs = sig_ofs
        return sig_ofs

    def _patch_site(
        self,
        name: str,
        offset: int,
        stock: bytes,
        post: bytes,
    ) -> Optional[Tuple[str, str, str, str]]:
        pre = bytes(self.data[offset:offset + len(post)])
        if pre == post:
            return None
        if pre != stock:
            raise Exception(
                f"Region limit patch @0x{offset:X}: expected {stock.hex()}, found {pre.hex()}"
            )
        self.data[offset:offset + len(post)] = post
        return (name, hex(offset), pre.hex(), post.hex())

    def _apply_region_limit(self) -> List[Tuple[str, str, str, str]]:
        """Force REGION_LIMIT_VALUE (35 km/h) for all region IDs in UART cmd 0x21 path."""
        try:
            sig_ofs = self._resolve_region_limit_anchor()
        except SignatureException:
            return []

        sites = [
            (
                "region_limit_bypass",
                sig_ofs + self.REGION_CMP_BEQ_OFFSET,
                self.REGION_CMP_BEQ_STOCK,
                self.REGION_CMP_BEQ_PATCH,
            ),
            (
                "region_limit_nop",
                sig_ofs + self.REGION_SKIP_BRANCH_OFFSET,
                self.REGION_SKIP_BRANCH_STOCK,
                self.REGION_SKIP_BRANCH_PATCH,
            ),
            (
                "region_limit_movw",
                sig_ofs + self.REGION_MOVW_IMM_OFFSET,
                bytes([self.REGION_MOVW_IMM_STOCK]),
                bytes([self.REGION_MOVW_IMM_PATCH]),
            ),
        ]

        results: List[Tuple[str, str, str, str]] = []
        for name, offset, stock, post in sites:
            patch = self._patch_site(name, offset, stock, post)
            if patch is not None:
                results.append(patch)
        return results

    def _speed_limit_fix(self) -> List[Tuple[str, str, str, str]]:
        return self._apply_region_limit()

    def _locate_patch_offsets(self) -> None:
        try:
            self._resolve_speed_padding_sites(
                self.SIG_SPEED_CALC_ANCHOR,
                self.HIJACK_SIZE,
                self.OUTPUT_PTR_LDR_OFFSET,
                self.MIN_PADDING_SIZE + self.INJECT_PADDING_OFFSET,
            )
        except SignatureException as exc:
            raise Exception("Could not find speed calc signature for patching") from exc
        assert self._inject_offset is not None
        self._inject_offset += self.INJECT_PADDING_OFFSET

    def _build_speed_logic_asm(self) -> str:
        assert self._return_address is not None
        assert self._output_ptr is not None
        reload_asm = """
        ldrb r0, [r1, #5]
        ldrb r2, [r1, #2]
        """
        return self._build_padding_speed_logic_asm(
            reload_asm=reload_asm,
            mode_reg="r2",
            speed_reg="r0",
            ptr_reg="r1",
            return_address=self._return_address,
            output_ptr=self._output_ptr,
        )
