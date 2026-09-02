#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher - Mi 6 Module
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

from typing import List, Optional, Tuple

from bwpatcher.modules.leqi_speed import LeqiPaddingSpeedPatcher
from bwpatcher.utils import SignatureException, find_pattern


class Mi6Patcher(LeqiPaddingSpeedPatcher):
    """
    Patcher for Xiaomi Mi 6 with N32 (Leqi) controller.

    Hijacks the speed-calc instruction with b.w into tail zero padding.
    Base pointer in r8, speed value in r2.
    """

    FIRMWARE_SIZE = 0xA800  # Fallback only; real size is read from the EU1 header (see
                             # docs/20-dynamic-firmware-size-detection.md)

    # ldrb.w r2,[r8,#5] + ldr r3,[pc] + *10 + strh r2,[r3]
    SIG_SPEED_CALC_ANCHOR = [
        0x98, 0xF8, 0x05, 0x20,
        0x4A, 0x4B,
        0x02, 0xEB, 0x82, 0x02,
        0x52, 0x00,
        0x1A, 0x80,
    ]
    OUTPUT_PTR_LDR_OFFSET = 4

    # UART cmd 0x21 regional speed switch in FUN_0000270c (~0x2e24, tbb dispatch).
    # Stock selects EU/DE (movs #0xcf), GL (movw #0x101), or SPECIAL (movw #0x147)
    # and stores via strh r2,[r3] to DAT_00003024.
    SIG_REGION_LIMIT_ANCHOR: List[Optional[int]] = [
        0x82, 0x4B,
        None, None, None, None, None, None,
        0x67, 0xE0, 0xDF, 0xE8, 0x01, 0xF0, 0x10, 0x05, 0x03, 0x03,
        0x03, 0x00, 0xCF, 0x22, 0x01, 0xE0, 0x40, 0xF2, 0x01, 0x12,
        0x1A, 0x80,
    ]
    STOCK_REGION_LIMIT_GATE = bytes([0x05, 0x29, 0x0B, 0xD2, 0x00, 0xE0])

    # Redirect all tbb @0x2e24 cases to case D @0x2e32, then movw #0x15e.
    REGION_JUMPTABLE_OFFSET = 0x0E
    REGION_JUMPTABLE_LEN = 5
    REGION_JUMPTABLE_STOCK = bytes([0x10, 0x05, 0x03, 0x03, 0x03])
    REGION_JUMPTABLE_PATCH = bytes([0x05] * REGION_JUMPTABLE_LEN)
    REGION_MOVW_IMM_OFFSET = 0x1A
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
                "region_limit_jumptable",
                sig_ofs + self.REGION_JUMPTABLE_OFFSET,
                self.REGION_JUMPTABLE_STOCK,
                self.REGION_JUMPTABLE_PATCH,
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

    def _build_speed_logic_asm(self) -> str:
        assert self._return_address is not None
        assert self._output_ptr is not None
        reload_asm = """
        ldrb.w r2, [r8, #5]
        ldrb.w r1, [r8, #2]
        """
        return self._build_padding_speed_logic_asm(
            reload_asm=reload_asm,
            mode_reg="r1",
            speed_reg="r2",
            ptr_reg="r3",
            return_address=self._return_address,
            output_ptr=self._output_ptr,
        )
