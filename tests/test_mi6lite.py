#!/usr/bin/env python3
"""Pytest tests for Mi6 Lite patcher module."""

from pathlib import Path

import pytest
from bwpatcher.modules.mi6lite import Mi6litePatcher

FIRMWARE_BODY_SIZE = 0xB000
REAL_FIRMWARE = Path(__file__).resolve().parents[1] / "bins" / "6lite.dec.bin"
V2_FIRMWARE = Path(__file__).resolve().parents[1] / "patched_mi6lite_firmware_v2.dec.bin"
REGION_LIMIT_TEST_OFFSET = 0x8000
REGION_ANCHOR_WILDCARD_BYTES = [0x62, 0x45, 0x0C, 0xD0, 0x04, 0xDC]
EXPECTED_REGION_V2 = bytes.fromhex(
    "62450ce004dcd1180bd001290cd106e0012804d0a0f580711f3905d101e0cf2100bf40f25e113980"
)
INJECT_PROLOGUE = bytes.fromhex("48798a7802f00302")


def _embed_bytes(data: bytearray, offset: int, pattern: list) -> None:
    for i, byte in enumerate(pattern):
        data[offset + i] = byte


def _embed_region_limit_anchor(data: bytearray, offset: int) -> None:
    patch_i = 0
    for byte in Mi6litePatcher.SIG_REGION_LIMIT_ANCHOR:
        if byte is None:
            data[offset] = REGION_ANCHOR_WILDCARD_BYTES[patch_i]
            patch_i += 1
        else:
            data[offset] = byte
        offset += 1


def _make_firmware_buffer():
    """Build synthetic decrypted firmware with realistic tail padding layout."""
    if REAL_FIRMWARE.is_file():
        data = bytearray(REAL_FIRMWARE.read_bytes())
    else:
        data = bytearray(b"\xff" * FIRMWARE_BODY_SIZE)
        _embed_bytes(data, 0x2DEA, Mi6litePatcher.SIG_SPEED_CALC_ANCHOR)
        tail = bytearray(b"\xff" * Mi6litePatcher.TAIL_SEARCH_WINDOW)
        zero_run_start = len(tail) - 0x400
        tail[zero_run_start:] = b"\x00" * (len(tail) - zero_run_start)
        data[-Mi6litePatcher.TAIL_SEARCH_WINDOW:] = tail

    if not REAL_FIRMWARE.is_file():
        _embed_region_limit_anchor(data, REGION_LIMIT_TEST_OFFSET)
    return data


class TestMi6litePatcher:
    def test_speed_limit_sport_on_real_firmware(self):
        if not REAL_FIRMWARE.is_file():
            pytest.skip("bins/6lite.dec.bin not available")

        patcher = Mi6litePatcher(bytearray(REAL_FIRMWARE.read_bytes()))
        results = patcher.speed_limit_sport(30)
        patches = {r[0]: r for r in results}

        assert patches["hijack_speed_calc"][1] == "0x2dea"
        assert patches["hijack_speed_calc"][3] == "07f031bf"
        assert patches["speed_logic_block"][1] == "0xac50"
        assert patches["region_limit_bypass"][3] == "0ce0"
        assert patches["region_limit_nop"][3] == "00bf"
        assert patches["region_limit_movw"][3] == "5e"

    def test_v2_region_and_hijack_bytes(self):
        if not REAL_FIRMWARE.is_file() or not V2_FIRMWARE.is_file():
            pytest.skip("reference firmware bins not available")

        patcher = Mi6litePatcher(bytearray(REAL_FIRMWARE.read_bytes()))
        patcher.speed_limit_ped(25)
        patcher.speed_limit_drive(30)
        patcher.speed_limit_sport(35)
        patched = bytes(patcher.data)
        v2_body = V2_FIRMWARE.read_bytes()[0x80:0x80 + len(patched)]

        assert patched[0x2DEA:0x2DEE] == bytes.fromhex("07f031bf")
        assert patched[0x3228:0x3250] == EXPECTED_REGION_V2
        assert patched[0x3228:0x3250] == v2_body[0x3228:0x3250]
        assert patched[0xAC50:0xAC90] == v2_body[0xAC50:0xAC90]
        assert patched[0xAC50:0xAC58] == INJECT_PROLOGUE

    def test_speed_limit_sport_matches_resolved_sites(self):
        patcher = Mi6litePatcher(_make_firmware_buffer())
        results = patcher.speed_limit_sport(30)
        patches = {r[0]: r for r in results}

        assert patches["hijack_speed_calc"][1] == "0x2dea"
        assert patches["region_limit_bypass"][3] == "0ce0"
        assert patches["region_limit_movw"][3] == "5e"
        assert patches["speed_logic_block"][1] == hex(patcher._inject_offset)

    def test_speed_limit_drive_updates_constants(self):
        patcher = Mi6litePatcher(_make_firmware_buffer())
        patcher.speed_limit_sport(30)
        results = patcher.speed_limit_drive(25)

        assert len(results) == 1
        assert results[0][0] == "speed_constants_updated"
        assert "40f2fa00" in results[0][3]  # movw r0, #250
        assert "40f22c10" in results[0][3]  # movw r0, #300 still present

    def test_region_limit_fixed_across_sport_changes(self):
        patcher = Mi6litePatcher(_make_firmware_buffer())
        patcher.speed_limit_sport(30)
        results = patcher.speed_limit_sport(35)

        assert len(results) == 1
        assert results[0][0] == "speed_constants_updated"

    def test_idempotency(self):
        patcher = Mi6litePatcher(_make_firmware_buffer())
        original_size = len(patcher.data)

        patcher.speed_limit_sport(30)
        patcher.speed_limit_drive(25)
        patcher.speed_limit_ped(6)

        assert len(patcher.data) == original_size

    def test_nonzero_padding_raises(self):
        data = _make_firmware_buffer()
        probe = Mi6litePatcher(data)
        probe._locate_patch_offsets()
        inject_ofs = probe._inject_offset
        run_end = inject_ofs
        while run_end < len(data) and data[run_end] == 0:
            run_end += 1
        data[inject_ofs:run_end] = b"\xff" * (run_end - inject_ofs)
        patcher = Mi6litePatcher(data)

        with pytest.raises(Exception, match="zero padding"):
            patcher.speed_limit_sport(30)

    def test_hijack_mismatch_raises(self):
        data = _make_firmware_buffer()
        data[0x2DEA] = 0x00
        patcher = Mi6litePatcher(data)

        with pytest.raises(Exception, match="Could not find speed calc signature"):
            patcher.speed_limit_sport(30)

    def test_missing_speed_signature_raises(self):
        data = bytearray(b"\xff" * FIRMWARE_BODY_SIZE)
        patcher = Mi6litePatcher(data)

        with pytest.raises(Exception, match="Could not find speed calc signature"):
            patcher.speed_limit_sport(30)
