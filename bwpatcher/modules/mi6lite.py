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


class Mi6litePatcher(LeqiPaddingSpeedPatcher):
    """
    Patcher for Xiaomi Mi 6 Lite with N32 (Leqi) controller.

    Hijacks the speed-calc instructions with b.w into tail zero padding.
    Base pointer in r1, speed value in r0.
    """

    FIRMWARE_SIZE = 0xB000  # Fallback only; real size is read from the EU1 header (see
                             # docs/20-dynamic-firmware-size-detection.md)

    # ldrb r0,[r1,#5] + ldr r1,[pc] + *10 + strh r0,[r1]
    SIG_SPEED_CALC_ANCHOR = [
        0x48, 0x79, 0x54, 0x49,
        0x00, 0xEB, 0x80, 0x00,
        0x40, 0x00,
        0x08, 0x80,
    ]
    OUTPUT_PTR_LDR_OFFSET = 2

    # UART 0x21 regional cap tree (wildcards = cmp/beq/bgt patch slot).
    SIG_REGION_LIMIT_ANCHOR: List[Optional[int]] = [
        0x67, 0x4F,
        None, None, None, None, None, None,
        0xD1, 0x18, 0x0B, 0xD0, 0x01, 0x29, 0x0C, 0xD1, 0x06, 0xE0,
        0x01, 0x28, 0x04, 0xD0, 0xA0, 0xF5, 0x80, 0x71, 0x1F, 0x39,
        0x05, 0xD1, 0x01, 0xE0, 0xCF, 0x21, 0x01, 0xE0, 0x40, 0xF2,
        0x01, 0x11, 0x39, 0x80,
    ]
    STOCK_REGION_LIMIT_PATCH = [0x62, 0x45, 0x0C, 0xD0, 0x04, 0xDC]

    def _speed_limit_fix(self) -> List[Tuple[str, str, str, str]]:
        return self._apply_region_limit_movw_branch(
            self.SIG_REGION_LIMIT_ANCHOR,
            self.STOCK_REGION_LIMIT_PATCH,
            "r1",
            "region_limit_gl",
        )

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
