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

    # UART 0x21 regional cap tbb gate (wildcards = cmp/bhs/b patch slot).
    SIG_REGION_LIMIT_ANCHOR: List[Optional[int]] = [
        0x82, 0x4B,
        None, None, None, None, None, None,
        0x67, 0xE0, 0xDF, 0xE8, 0x01, 0xF0, 0x10, 0x05, 0x03, 0x03,
        0x03, 0x00, 0xCF, 0x22, 0x01, 0xE0, 0x40, 0xF2, 0x01, 0x12,
        0x1A, 0x80,
    ]
    STOCK_REGION_LIMIT_PATCH = [0x05, 0x29, 0x0B, 0xD2, 0x00, 0xE0]

    def _speed_limit_fix(self) -> List[Tuple[str, str, str, str]]:
        return self._apply_region_limit_movw_branch(
            self.SIG_REGION_LIMIT_ANCHOR,
            self.STOCK_REGION_LIMIT_PATCH,
            "r2",
            "region_limit_special",
        )

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
