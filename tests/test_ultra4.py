#!/usr/bin/env python3
"""Pytest tests for Ultra4 (dreame.scooter.p2301) LKS32 speed-limit patches."""

from pathlib import Path

import pytest

from bwpatcher.modules.ultra4 import Ultra4Patcher
from bwpatcher.utils import patch_firmware

STOCK_CANDIDATES = [
    Path(__file__).parent.parent / "bins" / "0017_083efd3080a972f2277705bcbd49912a_mcu_dreame.scooter.p2301.bin",
    Path("/home/jethro/projects/hax-reorg/firmware/ota/0017_083efd3080a972f2277705bcbd49912a_mcu_dreame.scooter.p2301.bin"),
    Path("/home/jethro/projects/hax/bins/0017_083efd3080a972f2277705bcbd49912a_mcu_dreame.scooter.p2301.bin"),
]

# After SLS=36.7 + SLD=25.0:
#   0x5610 ldr r3,[pc,#8] / strh ; 0x5614 ldr r1,[pc,#8] / strh
#   0x5618 b #0x563e ; pool drive=250 @0x561c ; sport=367 @0x5620
EXPECTED_SPEED_CORE = bytes.fromhex("024b03800249418011e01a4afa0000006f010000")


def _find_stock() -> Path:
    for path in STOCK_CANDIDATES:
        if path.exists():
            return path
    return None


@pytest.fixture
def stock_data():
    path = _find_stock()
    if path is None:
        pytest.skip("Ultra4 stock p2301 MCU bin not found")
    data = path.read_bytes()
    assert len(data) == 30720
    return data


class TestUltra4Patcher:
    def test_gui_order_sls_then_sld(self, stock_data):
        out = patch_firmware(
            "ultra4", bytearray(stock_data), ["sls=36.7", "sld=25.0", "chk"], web=True
        )
        assert bytes(out)[0x5610:0x5624] == EXPECTED_SPEED_CORE

    def test_reverse_order_sld_then_sls(self, stock_data):
        out = patch_firmware(
            "ultra4", bytearray(stock_data), ["sld=25.0", "sls=36.7", "chk"], web=True
        )
        assert bytes(out)[0x5610:0x5624] == EXPECTED_SPEED_CORE

    def test_pool_values(self, stock_data):
        out = patch_firmware(
            "ultra4", bytearray(stock_data), ["sls=36.7", "sld=25.0"], web=True
        )
        core = bytes(out)[0x5610:0x5624]
        assert int.from_bytes(core[0xC:0x10], "little") == 250  # drive 25.0
        assert int.from_bytes(core[0x10:0x14], "little") == 367  # sport 36.7

    def test_dms_and_mss_still_apply(self, stock_data):
        patcher = Ultra4Patcher(bytearray(stock_data))
        dms = patcher.dashboard_max_speed(22.0)
        mss = patcher.motor_start_speed(5)
        assert dms[0][0] == "dashboard_max_speed"
        assert mss[0][0] == "motor_start_speed"
        assert dms[0][1] == "0x2356"
        assert mss[0][1] == "0x3652"

    def test_remove_speed_limit_sport(self, stock_data):
        patcher = Ultra4Patcher(bytearray(stock_data))
        results = patcher.remove_speed_limit_sport()
        assert results  # branch + value + ldr
        assert bytes(patcher.data)[0x5614:0x5616] == bytes.fromhex("0249")
        assert int.from_bytes(bytes(patcher.data)[0x5620:0x5624], "little") == 367
