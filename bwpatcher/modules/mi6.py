#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher - Mi 6 Module
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

from bwpatcher.modules.leqi_speed import LeqiPaddingSpeedPatcher


class Mi6Patcher(LeqiPaddingSpeedPatcher):
    """
    Patcher for Xiaomi Mi 6 with N32 (Leqi) controller.

    Hijacks the speed-calc instruction at 0x2a68 with b.w into zero padding
    at 0xa410. Base pointer in r8, speed value in r2.
    """

    FIRMWARE_SIZE = 0xA800  # Fallback only; real size is read from the EU1 header (see
                             # docs/20-dynamic-firmware-size-detection.md)

    SIG_HIJACK = [0x98, 0xf8, 0x05, 0x20]
    HIJACK_OFFSET = 0x2A68
    INJECT_OFFSET = 0xA410
    RETURN_ADDRESS = 0x2A76
    OUTPUT_PTR = 0x200001A2

    def _build_speed_logic_asm(self) -> str:
        reload_asm = """
        ldrb.w r2, [r8, #5]
        ldrb.w r1, [r8, #2]
        """
        return self._build_padding_speed_logic_asm(
            reload_asm=reload_asm,
            mode_reg="r1",
            speed_reg="r2",
            ptr_reg="r3",
            return_address=self.RETURN_ADDRESS,
            output_ptr=self.OUTPUT_PTR,
        )
