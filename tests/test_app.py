import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

import app as manager


@pytest.fixture(scope="session")
def qt_app():
    instance = QApplication.instance()
    return instance or QApplication([])


def test_normalize_target_domain_and_ipv4():
    assert manager.normalize_target("Example.COM") == ("example.com", "Домен")
    assert manager.normalize_target("192.0.2.10") == ("192.0.2.10/32", "IPv4-адрес")
    assert manager.normalize_target("192.0.2.0/24") == ("192.0.2.0/24", "IPv4-сеть")


@pytest.mark.parametrize("value", ["", "999.1.1.1", "example", "bad_domain.com", "2001:db8::1"])
def test_normalize_target_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        manager.normalize_target(value)


def test_parse_terse_preserves_flags_and_fields():
    parsed = manager.parse_terse('0 R name="ether1" type="ether" mtu=1500')
    assert len(parsed) == 1
    assert parsed[0]["flags"] == {"R"}
    assert parsed[0]["f"]["name"] == "ether1"
    assert parsed[0]["f"]["mtu"] == "1500"


def test_ip_scan_parser_extracts_ip_mac_latency_and_name():
    rows = manager.App.parse_ip_scan(None, "192.0.2.15 AA:BB:CC:DD:EE:FF 1.4ms laptop\ninvalid row")
    assert rows == [{
        "ip": "192.0.2.15",
        "mac": "AA:BB:CC:DD:EE:FF",
        "response": "1.4ms",
        "scan_name": "laptop",
    }]


def test_backdrop_switches_real_canvas_theme(qt_app):
    backdrop = manager.Backdrop()
    backdrop.set_theme("light")
    assert backdrop.theme == "light"
    backdrop.set_theme("dark")
    assert backdrop.theme == "dark"
    backdrop.set_theme("not-a-theme")
    assert backdrop.theme == "default"


def test_application_theme_and_general_settings_smoke(qt_app):
    window = manager.App()
    try:
        window.settings["ui_theme"] = "light"
        window.apply_visual_preferences()
        assert window.centralWidget().theme == "light"
        assert "#202938" in window.styleSheet()
        assert window.findChild(QPushButton, "clear_lan_history_btn") is not None
        window.settings["ui_theme"] = "dark"
        window.apply_visual_preferences()
        assert window.centralWidget().theme == "dark"
    finally:
        window._allow_close = True
        window.close()
