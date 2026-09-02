#!/usr/bin/env python3
"""Pytest tests for Mi6 patcher module."""

from pathlib import Path

import pytest
from bwpatcher.modules.mi6 import Mi6Patcher

FIRMWARE_BODY_SIZE = 0xA800
REAL_FIRMWARE = Path(__file__).resolve().parents[1] / "bins" / "6.dec.bin"
REGION_LIMIT_TEST_OFFSET = 0x8000
REGION_GATE_WILDCARD_BYTES = list(Mi6Patcher.STOCK_REGION_LIMIT_GATE)
EXPECTED_REGION_JUMPTABLE = Mi6Patcher.REGION_JUMPTABLE_PATCH
EXPECTED_REGION_MOVW = bytes.fromhex("40f25e12")


def _embed_bytes(data: bytearray, offset: int, pattern: list) -> None:
    for i, byte in enumerate(pattern):
        data[offset + i] = byte


def _embed_region_limit_anchor(data: bytearray, offset: int) -> None:
    patch_i = 0
    for byte in Mi6Patcher.SIG_REGION_LIMIT_ANCHOR:
        if byte is None:
            data[offset] = REGION_GATE_WILDCARD_BYTES[patch_i]
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
        _embed_bytes(data, 0x2A68, Mi6Patcher.SIG_SPEED_CALC_ANCHOR)
        tail = bytearray(b"\xff" * Mi6Patcher.TAIL_SEARCH_WINDOW)
        zero_run_start = len(tail) - 0x400
        tail[zero_run_start:] = b"\x00" * (len(tail) - zero_run_start)
        data[-Mi6Patcher.TAIL_SEARCH_WINDOW:] = tail

    if not REAL_FIRMWARE.is_file():
        _embed_region_limit_anchor(data, REGION_LIMIT_TEST_OFFSET)
    return data


class TestMi6Patcher:
    def test_speed_limit_sport_on_real_firmware(self):
        if not REAL_FIRMWARE.is_file():
            pytest.skip("bins/6.dec.bin not available")

        stock = REAL_FIRMWARE.read_bytes()
        patcher = Mi6Patcher(bytearray(stock))
        results = patcher.speed_limit_sport(30)
        patches = {r[0]: r for r in results}
        patched = bytes(patcher.data)

        assert patches["hijack_speed_calc"][1] == "0x2a68"
        assert patches["speed_logic_block"][1] == "0xa40e"
        assert patches["region_limit_jumptable"][3] == EXPECTED_REGION_JUMPTABLE.hex()
        assert patches["region_limit_movw"][3] == "5e"
        assert patched[0x2E28:0x2E2D] == EXPECTED_REGION_JUMPTABLE
        assert patched[0x2E32:0x2E36] == EXPECTED_REGION_MOVW
        assert patched[0x2E1C:0x2E22] == stock[0x2E1C:0x2E22]

    def test_speed_limit_sport_matches_resolved_sites(self):
        patcher = Mi6Patcher(_make_firmware_buffer())
        results = patcher.speed_limit_sport(30)
        patches = {r[0]: r for r in results}

        assert patches["hijack_speed_calc"][1] == "0x2a68"
        assert patches["region_limit_jumptable"][3] == EXPECTED_REGION_JUMPTABLE.hex()
        assert patches["region_limit_movw"][3] == "5e"
        assert patches["speed_logic_block"][1] == hex(patcher._inject_offset)

    def test_speed_limit_drive_updates_constants(self):
        patcher = Mi6Patcher(_make_firmware_buffer())
        patcher.speed_limit_sport(30)
        results = patcher.speed_limit_drive(25)

        assert len(results) == 1
        assert results[0][0] == "speed_constants_updated"
        assert "40f2fa02" in results[0][3]  # movw r2, #250
        assert "40f22c12" in results[0][3]  # movw r2, #300 still present

    def test_region_limit_fixed_across_sport_changes(self):
        patcher = Mi6Patcher(_make_firmware_buffer())
        patcher.speed_limit_sport(30)
        results = patcher.speed_limit_sport(35)

        assert len(results) == 1
        assert results[0][0] == "speed_constants_updated"

    def test_idempotency(self):
        patcher = Mi6Patcher(_make_firmware_buffer())
        original_size = len(patcher.data)

        patcher.speed_limit_sport(30)
        patcher.speed_limit_drive(25)
        patcher.speed_limit_ped(6)

        assert len(patcher.data) == original_size

    def test_nonzero_padding_raises(self):
        data = _make_firmware_buffer()
        probe = Mi6Patcher(data)
        probe._resolve_speed_padding_sites(
            Mi6Patcher.SIG_SPEED_CALC_ANCHOR,
            Mi6Patcher.HIJACK_SIZE,
            Mi6Patcher.OUTPUT_PTR_LDR_OFFSET,
            Mi6Patcher.MIN_PADDING_SIZE,
        )
        inject_ofs = probe._inject_offset
        run_end = inject_ofs
        while run_end < len(data) and data[run_end] == 0:
            run_end += 1
        data[inject_ofs:run_end] = b"\xff" * (run_end - inject_ofs)
        patcher = Mi6Patcher(data)

        with pytest.raises(Exception, match="zero padding"):
            patcher.speed_limit_sport(30)

    def test_hijack_mismatch_raises(self):
        data = _make_firmware_buffer()
        data[0x2A68] = 0x00
        patcher = Mi6Patcher(data)

        with pytest.raises(Exception, match="Could not find speed calc signature"):
            patcher.speed_limit_sport(30)

    def test_missing_speed_signature_raises(self):
        data = bytearray(b"\xff" * FIRMWARE_BODY_SIZE)
        patcher = Mi6Patcher(data)

        with pytest.raises(Exception, match="Could not find speed calc signature"):
            patcher.speed_limit_sport(30)
