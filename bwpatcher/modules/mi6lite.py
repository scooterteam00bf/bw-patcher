#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher - Mi 6 Lite Module
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

from bwpatcher.modules.leqi_speed import LeqiPaddingSpeedPatcher


class Mi6litePatcher(LeqiPaddingSpeedPatcher):
    """
    Patcher for Xiaomi Mi 6 Lite with N32 (Leqi) controller.

    Hijacks the speed-calc instructions at 0x2dea with b.w into zero padding
    at 0xac50. Base pointer in r1, speed value in r0.
    """

    FIRMWARE_SIZE = 0xB000  # Fallback only; real size is read from the EU1 header (see
                             # docs/20-dynamic-firmware-size-detection.md)

    SIG_HIJACK = [0x48, 0x79, 0x54, 0x49]
    HIJACK_OFFSET = 0x2DEA
    INJECT_OFFSET = 0xAC50
    RETURN_ADDRESS = 0x2DF6
    OUTPUT_PTR = 0x200001A2

    def _build_speed_logic_asm(self) -> str:
        reload_asm = """
        ldrb r0, [r1, #5]
        ldrb r2, [r1, #2]
        """
        return self._build_padding_speed_logic_asm(
            reload_asm=reload_asm,
            mode_reg="r2",
            speed_reg="r0",
            ptr_reg="r1",
            return_address=self.RETURN_ADDRESS,
            output_ptr=self.OUTPUT_PTR,
        )
