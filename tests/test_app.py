import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QPushButton, QScrollBar

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


def test_scrollbars_use_custom_antialiased_painter(qt_app):
    style = manager.RoundedScrollBarStyle()
    scrollbar = manager.QScrollBar(Qt.Orientation.Vertical)
    scrollbar.setRange(0, 100)
    scrollbar.setPageStep(20)
    scrollbar.resize(18, 140)
    scrollbar.setStyle(style)
    scrollbar.show()
    qt_app.processEvents()
    image = manager.QPixmap(scrollbar.size())
    image.fill(manager.Qt.GlobalColor.transparent)
    painter = manager.QPainter(image)
    scrollbar.render(painter)
    painter.end()

    # The extreme corner stays transparent while the center of the track is painted.
    assert image.toImage().pixelColor(0, 0).alpha() == 0
    assert image.toImage().pixelColor(9, 70).alpha() > 0
    scrollbar.close()


def test_scrollbars_follow_selected_application_theme(qt_app):
    qt_app.setStyle(manager.RoundedScrollBarStyle())
    window = manager.App()
    try:
        for theme, expected in (
            ("default", "#60a5fa"),
            ("dark", "#65717b"),
            ("light", "#60a5fa"),
        ):
            window.settings["ui_theme"] = theme
            window.apply_visual_preferences()
            assert qt_app.property("scrollbar_theme") == theme
            assert isinstance(qt_app.style(), manager.RoundedScrollBarStyle)
            assert "QScrollBar:" not in window.styleSheet()
            assert expected not in window.styleSheet()
    finally:
        window._allow_close = True
        window.close()


def test_terminal_output_colors_do_not_leak_into_next_command(qt_app):
    window = manager.App()
    try:
        window.terminal_output.clear()
        window.append_terminal_text("[12:00:00] $ /system resource print", "#c9d7e8")
        window.append_terminal_text("uptime: 1d", "#4ade80")

        success_cursor = window.terminal_output.document().find("uptime: 1d")
        assert success_cursor.charFormat().foreground().color().name() == "#4ade80"
        assert window.terminal_output.textCursor().charFormat().foreground().color().name() == "#c9d7e8"

        window.append_terminal_text("[12:00:01] $ /wrong-command", "#c9d7e8")
        command_cursor = window.terminal_output.document().find("/wrong-command")
        assert command_cursor.charFormat().foreground().color().name() == "#c9d7e8"

        window.append_terminal_text("ОШИБКА: expected end of command", "#fb7185")
        error_cursor = window.terminal_output.document().find("ОШИБКА:")
        assert error_cursor.charFormat().foreground().color().name() == "#fb7185"
        assert window.terminal_output.textCursor().charFormat().foreground().color().name() == "#c9d7e8"
    finally:
        window._allow_close = True
        window.close()


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



def test_lan_map_nodes_are_selectable_and_show_details(qt_app):
    window = manager.App()
    records = [
        {
            "mac": "AA:BB:CC:DD:EE:01", "ip": "192.0.2.10", "hostname": "workstation",
            "interface": "bridge-LAN", "vendor": "Intel", "sources": ["IP Scan", "ARP"],
            "state": "online", "last_seen": "2026-11-16 12:00:00", "kind": "endpoint",
        },
        {
            "mac": "AA:BB:CC:DD:EE:02", "ip": "192.0.2.20", "hostname": "nas",
            "interface": "bridge-LAN", "vendor": "QNAP", "sources": ["DHCP"],
            "state": "new", "last_seen": "2026-11-16 12:00:00", "kind": "endpoint",
        },
    ]
    current = {row["mac"]: row for row in records}
    try:
        window.render_lan_map(records, current, 1, 0)
        node = next(
            item for item in window.lan_map_scene.items()
            if isinstance(item.data(0), dict) and item.data(0).get("ip") == "192.0.2.10"
        )
        assert node.flags() & manager.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
        node.setSelected(True)
        assert "192.0.2.10" in window.lan_map_details.text()
        assert "AA:BB:CC:DD:EE:01" in window.lan_map_details.text()

        window.lan_map_search.setText("192.0.2.20")
        visible = [
            item.data(0).get("ip") for item in window.lan_map_scene.items()
            if isinstance(item.data(0), dict) and item.data(0).get("ip")
        ]
        assert visible == ["192.0.2.20"]
        assert len(window._lan_map_records) == 2
    finally:
        window._allow_close = True
        window.close()



def test_default_topology_canvas_uses_dark_background(qt_app):
    window = manager.App()
    try:
        window.settings["ui_theme"] = "default"
        window.render_lan_map([], {}, 0, 0)
        assert window.lan_map_scene.backgroundBrush().color().name() == "#0b1220"
        assert window.lan_map_view.backgroundBrush().color().name() == "#0b1220"
        assert window.lan_map_view.viewport().palette().color(
            manager.QPalette.ColorRole.Base
        ).name() == "#0b1220"
    finally:
        window._allow_close = True
        window.close()


def test_detached_topology_window_shares_scene_and_selection(qt_app):
    window = manager.App()
    try:
        record = {
            "mac": "AA:BB:CC:DD:EE:10", "ip": "192.0.2.30", "hostname": "detached-test",
            "interface": "bridge-LAN", "vendor": "Test vendor", "sources": ["IP Scan"],
            "state": "online", "kind": "endpoint",
        }
        window.settings["ui_theme"] = "default"
        window.render_lan_map([record], {record["mac"]: record}, 0, 0)
        window.open_lan_map_window()
        assert window._lan_map_detached_view.scene() is window.lan_map_scene
        assert window._lan_map_detached_view.backgroundBrush().color().name() == "#0b1220"
        assert window._lan_map_detached_view.viewport().palette().color(
            manager.QPalette.ColorRole.Base
        ).name() == "#0b1220"
        node = next(
            item for item in window.lan_map_scene.items()
            if isinstance(item.data(0), dict) and item.data(0).get("ip") == "192.0.2.30"
        )
        node.setSelected(True)
        assert "192.0.2.30" in window._lan_map_detached_details.text()
        window._lan_map_window.close()
        assert window._lan_map_window is None
    finally:
        if window._lan_map_window is not None:
            window._lan_map_window.close()
        window._allow_close = True
        window.close()


def test_custom_title_buttons_have_compact_dimensions(qt_app):
    window = manager.App()
    try:
        buttons = window.title_bar.findChildren(QPushButton)
        assert len(buttons) == 3
        assert all(button.width() == 32 and button.height() == 24 for button in buttons)
    finally:
        window._allow_close = True
        window.close()


def test_network_map_view_uses_incremental_updates_and_cached_background(qt_app):
    view = manager.NetworkMapView()
    try:
        assert view.viewportUpdateMode() == manager.QGraphicsView.ViewportUpdateMode.BoundingRectViewportUpdate
        assert view.cacheMode() & manager.QGraphicsView.CacheModeFlag.CacheBackground
    finally:
        view.close()


def test_network_map_fit_uses_explicit_scene_rect(qt_app):
    scene = manager.QGraphicsScene()
    scene.setSceneRect(0, 0, 1200, 800)
    scene.addRect(0, 0, 10, 10)
    view = manager.NetworkMapView()
    try:
        view.setScene(scene)
        view.fit_map()
        assert view.transform().m11() > 0
    finally:
        view.close()
