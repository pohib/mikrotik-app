from __future__ import annotations
import sys, os, json, re, ipaddress, base64, hashlib, queue, threading, time, math, csv
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable

try:
    import paramiko
except ImportError:
    paramiko = None

from PySide6.QtCore import Qt, QTimer, Signal, QObject, QPointF, QRectF
from html import escape as esc
from PySide6.QtGui import QFont, QAction, QTextCursor, QPainter, QColor, QLinearGradient, QRadialGradient, QPainterPath, QPen, QBrush, QPixmap, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QLineEdit,
    QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QFileDialog, QPlainTextEdit, QComboBox, QSplitter, QDialog, QDialogButtonBox,
    QFormLayout, QCheckBox, QGroupBox, QAbstractItemView, QToolButton, QSpinBox, QScrollArea, QSizePolicy, QTextEdit, QGraphicsDropShadowEffect, QSizeGrip
)

APP_NAME = "MikroTik VPN Manager"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "MikroTikVPNManager"
CONFIG_FILE = APP_DIR / "settings.json"
KNOWN_HOSTS_FILE = APP_DIR / "known_hosts"
MANGLE_COMMENT = "VPN-MANAGER-DOMAIN-ROUTE"
NAT_COMMENT = "VPN-MANAGER-NAT"
TEMP_TEST_COMMENT = "VPN-MANAGER-TEMP-TEST"
ADDRESS_LIST_DEFAULT = "vpn_domains"

PRESETS = {
    "YouTube": ["youtube.com", "youtube-nocookie.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"],
    "OpenAI": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "Claude": ["claude.ai", "anthropic.com", "claudeusercontent.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telegra.ph", "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24"],
    "Netflix": ["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxso.net", "nflxext.com"],
    "Cloudflare services": ["cloudflare.com", "cloudflare-dns.com", "one.one.one.one"],
    "Instagram": ["instagram.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com", "cdninstagram.com", "fbcdn.net", "facebook.com", "messenger.com", "threads.net"],
}


def normalize_target(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        raise ValueError("Пустое значение")
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4:
            raise ValueError("Пока поддерживается только IPv4")
        return str(net), "IPv4-сеть"
    try:
        addr = ipaddress.ip_address(value)
        if addr.version != 4:
            raise ValueError("Пока поддерживается только IPv4")
        return f"{addr}/32", "IPv4-адрес"
    except ValueError as e:
        if "только IPv4" in str(e):
            raise
    if re.fullmatch(r"[0-9.]+", value):
        raise ValueError("Некорректный IPv4-адрес")
    domain = value.rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError("Некорректный домен") from e
    if len(domain) > 253 or len(domain.split(".")) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in domain.split(".")):
        raise ValueError("Введи домен, IPv4 или IPv4/CIDR")
    return domain, "Домен"


def ros_q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class RouterConnection:
    def __init__(self, host, port, username, key_file, passphrase, ui_queue):
        if paramiko is None:
            raise RuntimeError("Paramiko не установлен. Запусти start.bat.")
        self.host, self.port, self.username = host, port, username
        self.key_file, self.passphrase, self.ui_queue = key_file, passphrase or None, ui_queue
        self.client = None
        self.lock = threading.Lock()

    def connect(self):
        if not self.host or not Path(self.key_file).is_file():
            raise RuntimeError("Укажи адрес MikroTik и существующий приватный SSH-ключ")
        APP_DIR.mkdir(parents=True, exist_ok=True)
        client = paramiko.SSHClient()
        if KNOWN_HOSTS_FILE.exists():
            client.load_host_keys(str(KNOWN_HOSTS_FILE))
        hn = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
        known = bool(client.get_host_keys().lookup(hn))
        class Confirm(paramiko.MissingHostKeyPolicy):
            def missing_host_key(inner, ssh, hostname, key):
                ev, result = threading.Event(), {"accept": False}
                self.ui_queue.put(("TRUST", {"host": self.host, "port": self.port, "type": key.get_name(), "fp": fingerprint(key), "event": ev, "result": result}))
                if not ev.wait(120) or not result["accept"]:
                    raise paramiko.SSHException("SSH host key не подтверждён")
                ssh.get_host_keys().add(hostname, key.get_name(), key)
        client.set_missing_host_key_policy(Confirm())
        try:
            client.connect(hostname=self.host, port=self.port, username=self.username, key_filename=self.key_file,
                           passphrase=self.passphrase, look_for_keys=False, allow_agent=False,
                           timeout=12, banner_timeout=12, auth_timeout=15)
            key = client.get_transport().get_remote_server_key()
            if not known:
                client.save_host_keys(str(KNOWN_HOSTS_FILE))
        except Exception:
            client.close(); raise
        self.client = client
        return known, fingerprint(key)

    def close(self):
        # Не ждём lock: при зависшей команде закрытие transport прервёт recv()
        # и позволит фоновому worker завершиться, не блокируя GUI.
        client = self.client
        self.client = None
        if client:
            try:
                transport = client.get_transport()
                if transport:
                    transport.close()
            finally:
                client.close()

    def exec(self, command, timeout=30):
        with self.lock:
            client = self.client
            tr = client.get_transport() if client else None
            if not tr or not tr.is_active():
                raise RuntimeError("SSH-соединение отсутствует")
            _stdin, stdout, stderr = client.exec_command(command, timeout=min(12, timeout))
            channel = stdout.channel
            channel.settimeout(0.2)
            out_parts, err_parts = [], []
            deadline = time.monotonic() + max(1, timeout)
            while True:
                try:
                    while channel.recv_ready():
                        out_parts.append(channel.recv(32768))
                    while channel.recv_stderr_ready():
                        err_parts.append(channel.recv_stderr(32768))
                except Exception:
                    if not tr.is_active():
                        raise RuntimeError("SSH-соединение закрыто во время выполнения команды")
                    raise
                if channel.exit_status_ready():
                    while channel.recv_ready():
                        out_parts.append(channel.recv(32768))
                    while channel.recv_stderr_ready():
                        err_parts.append(channel.recv_stderr(32768))
                    break
                if time.monotonic() >= deadline:
                    channel.close()
                    raise TimeoutError(f"Команда RouterOS превысила таймаут {timeout} с: {command}")
                time.sleep(0.04)
            status = channel.recv_exit_status()
        out = b"".join(out_parts).decode("utf-8", "replace")
        err = b"".join(err_parts).decode("utf-8", "replace")
        combined = (out + ("\n" + err if err else "")).strip()
        if any(x in combined.lower() for x in ("failure:", "syntax error", "expected end of command", "bad command name")):
            raise RuntimeError(f"RouterOS отклонил команду:\n{command}\n{combined}")
        if status not in (0, -1):
            raise RuntimeError(f"SSH exit status {status}: {combined}")
        return combined


TONES = {"ok": "#4ade80", "warn": "#fbbf24", "bad": "#fb7185", "info": "#7db0ff", "muted": "#7f93b2", "off": "#5b6b85"}


def human_bytes(n):
    n = float(n)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or u == "ТБ":
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024


def fmt_bits(bps):
    if bps <= 0:
        return "0 бит/с"
    for u, div in (("Гбит/с", 1e9), ("Мбит/с", 1e6), ("Кбит/с", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f}".rstrip("0").rstrip(".") + " " + u
    return f"{bps:.0f} бит/с"


def nice_ceil(v):
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def parse_terse(text):
    """Разбор вывода RouterOS `print terse`: список {'flags': set, 'f': dict}."""
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line[0].isdigit():
            continue
        first = line.find("=")
        if first < 0:
            continue
        head = line[:first].split()
        flags = set("".join(head[1:-1])) if len(head) > 2 else set()
        fields = {k: v.strip('"') for k, v in re.findall(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)', line)}
        items.append({"flags": flags, "f": fields})
    return items


class Dot(QWidget):
    """Индикатор состояния со свечением."""
    def __init__(self, state="off"):
        super().__init__(); self.state = state; self.setFixedSize(16, 16)

    def set_state(self, state):
        if state != self.state:
            self.state = state; self.update()

    def paintEvent(self, _event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        col = QColor(TONES.get(self.state, TONES["off"]))
        glow = QRadialGradient(8, 8, 8); g0 = QColor(col); g0.setAlpha(150 if self.state != "off" else 40); g1 = QColor(col); g1.setAlpha(0)
        glow.setColorAt(0, g0); glow.setColorAt(1, g1)
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QBrush(glow)); p.drawEllipse(QPointF(8, 8), 8, 8)
        p.setBrush(col); p.drawEllipse(QPointF(8, 8), 4.2, 4.2)


class TrafficChart(QWidget):
    """График скорости WireGuard (RX/TX) с градиентной заливкой."""
    N = 120

    def __init__(self):
        super().__init__()
        self.rx, self.tx = [], []
        self.msg = "Нет данных — подключись к роутеру"
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, rx, tx):
        self.rx, self.tx = list(rx), list(tx); self.update()

    def paintEvent(self, _event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height(); L, R, T, B = 84, 14, 12, 28
        pw, ph = w - L - R, h - T - B
        if pw < 40 or ph < 40:
            return
        f = QFont(self.font()); f.setPointSize(8); p.setFont(f)
        peak = max(self.rx + self.tx + [0]) * 8
        top = nice_ceil(max(peak * 1.1, 100_000))
        al_r = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        for i in range(5):
            y = T + ph * i / 4
            p.setPen(QPen(QColor(255, 255, 255, 24), 1)); p.drawLine(QPointF(L, y), QPointF(L + pw, y))
            p.setPen(QColor("#6f84a6")); p.drawText(QRectF(0, y - 9, L - 10, 18), al_r, fmt_bits(top * (1 - i / 4)) if i < 4 else "0")
        p.setPen(QColor("#5f7499"))
        p.drawText(QRectF(L, h - B + 6, 140, 16), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "−10 мин")
        p.drawText(QRectF(L + pw - 140, h - B + 6, 140, 16), al_r, "сейчас")
        if len(self.rx) < 2:
            p.setPen(QColor("#7d90ad")); p.drawText(QRectF(L, T, pw, ph), Qt.AlignmentFlag.AlignCenter, self.msg)
            return
        step = pw / (self.N - 1)
        for series, color in ((self.rx, "#38bdf8"), (self.tx, "#fbbf24")):
            n = len(series)
            pts = [QPointF(L + pw - (n - 1 - i) * step, T + ph - min(v * 8 / top, 1.0) * ph) for i, v in enumerate(series)]
            path = QPainterPath(pts[0])
            for pt in pts[1:]:
                path.lineTo(pt)
            area = QPainterPath(path); area.lineTo(pts[-1].x(), T + ph); area.lineTo(pts[0].x(), T + ph); area.closeSubpath()
            c0 = QColor(color); c0.setAlpha(95); c1 = QColor(color); c1.setAlpha(0)
            grad = QLinearGradient(0, T, 0, T + ph); grad.setColorAt(0, c0); grad.setColorAt(1, c1)
            p.fillPath(area, QBrush(grad))
            p.setPen(QPen(QColor(color), 2)); p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(path)
            p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(color)); p.drawEllipse(pts[-1], 3.6, 3.6)


def mangle_cmd(f):
    return (f'/ip firewall mangle add chain=prerouting in-interface={f["lan_interface"]} src-address={f["lan_subnet"]} '
            f'dst-address-list={f["address_list"]} dst-address-type=!local action=mark-routing '
            f'new-routing-mark={f["route_table"]} passthrough=no comment="{MANGLE_COMMENT}"')


def nat_cmd(f):
    return (f'/ip firewall nat add chain=srcnat action=masquerade src-address={f["lan_subnet"]} '
            f'out-interface={f["wg_interface"]} comment="{NAT_COMMENT}"')


def target_cmd(f, t, k):
    if k == "Домен":
        return f'/ip dns static add name={t} type=FWD address-list={f["address_list"]} match-subdomain=yes comment={ros_q("VPN-MANAGER:" + t)}'
    return f'/ip firewall address-list add list={f["address_list"]} address={t} comment={ros_q("VPN-MANAGER-CIDR:" + t)}'


class RouterOSHighlighter(QSyntaxHighlighter):
    """Подсветка синтаксиса RouterOS в предпросмотре."""
    def __init__(self, doc):
        super().__init__(doc)
        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat(); f.setForeground(QColor(color))
            if bold: f.setFontWeight(QFont.Weight.Bold)
            f.setFontItalic(italic); return f
        self.f_head = fmt("#7db0ff", True); self.f_comment = fmt("#62779a", False, True); self.f_path = fmt("#7db0ff")
        self.f_key = fmt("#2dd4bf"); self.f_val = fmt("#fbbf24")
        self.f_verb = {"add": fmt("#4ade80", True), "print": fmt("#9db4d6"), "flush": fmt("#fbbf24", True), "remove": fmt("#fb7185", True)}

    def highlightBlock(self, text):
        if text.startswith("# ═"):
            self.setFormat(0, len(text), self.f_head); return
        if text.startswith("#"):
            self.setFormat(0, len(text), self.f_comment); return
        m = re.match(r'^(/[\w-]+(?:\s+[a-z][\w-]*)*?)\s+(print|add|remove|flush)\b', text)
        if m:
            self.setFormat(m.start(1), len(m.group(1)), self.f_path)
            self.setFormat(m.start(2), len(m.group(2)), self.f_verb[m.group(2)])
        for km in re.finditer(r'([\w-]+)=("[^"]*"|\S+)', text):
            self.setFormat(km.start(1), len(km.group(1)), self.f_key)
            self.setFormat(km.start(2), len(km.group(2)), self.f_val)


def make_arrow_icon():
    """Рисует стрелку-шеврон для выпадающих списков и возвращает путь к PNG (или пустую строку)."""
    try:
        from PySide6.QtGui import QPixmap
        pm = QPixmap(14, 9); pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#9db4d6"), 2); pen.setCapStyle(Qt.PenCapStyle.RoundCap); pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen); p.drawPolyline([QPointF(2, 2), QPointF(7, 7), QPointF(12, 2)]); p.end()
        APP_DIR.mkdir(parents=True, exist_ok=True)
        path = APP_DIR / "arrow_down.png"
        return str(path).replace("\\", "/") if pm.save(str(path), "PNG") else ""
    except Exception:
        return ""


class Backdrop(QWidget):
    """Фон окна: тёмный градиент, мягкие свечения и едва заметная точечная сетка."""
    def __init__(self):
        super().__init__()
        self.tile = QPixmap(26, 26); self.tile.fill(Qt.GlobalColor.transparent)
        tp = QPainter(self.tile); tp.setRenderHint(QPainter.RenderHint.Antialiasing); tp.setPen(Qt.PenStyle.NoPen); tp.setBrush(QColor(255, 255, 255, 20)); tp.drawEllipse(QPointF(13, 13), 0.9, 0.9); tp.end()

    def paintEvent(self, _event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        base = QLinearGradient(0, 0, w, h); base.setColorAt(0, QColor("#080d19")); base.setColorAt(1, QColor("#04060b"))
        p.fillRect(self.rect(), base)
        for cx, cy, r, col in ((0.88, 0.02, 0.62, (59, 130, 246, 70)), (0.22, 1.02, 0.55, (45, 212, 191, 38)), (0.60, 0.52, 0.45, (139, 92, 246, 32))):
            g = QRadialGradient(w * cx, h * cy, max(w, h) * r)
            g.setColorAt(0, QColor(*col)); g.setColorAt(1, QColor(col[0], col[1], col[2], 0))
            p.fillRect(self.rect(), g)
        p.fillRect(self.rect(), QBrush(self.tile))


def add_shadow(widget, blur=30, dy=8, color=(0, 0, 0, 120)):
    fx = QGraphicsDropShadowEffect(widget)
    fx.setBlurRadius(blur); fx.setOffset(0, dy); fx.setColor(QColor(*color))
    widget.setGraphicsEffect(fx)


def fit_controls(root, height=42):
    """Задаёт минимальную высоту полям и кнопкам, чтобы текст никогда не обрезался."""
    for w in root.findChildren(QPushButton):
        h = 46 if w.objectName() == "ActionButton" else height
        if w.objectName() in ("ChromeButton","ChromeClose"): continue
        w.setMinimumHeight(h); w.setCursor(Qt.CursorShape.PointingHandCursor)
    for cls in (QLineEdit, QComboBox, QSpinBox):
        for w in root.findChildren(cls):
            if w.objectName().startswith("qt_"):
                continue
            w.setMinimumHeight(height)


class LogWindow(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Журнал операций — MikroTik VPN Manager")
        self.resize(900, 560)
        lay = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Фильтр журнала…")
        self.zoom = QSpinBox(); self.zoom.setRange(8, 24); self.zoom.setValue(10); self.zoom.setSuffix(" pt")
        clear = QPushButton("Очистить"); clear.clicked.connect(self.clear_log)
        bar.addWidget(self.search, 1); bar.addWidget(QLabel("Масштаб")); bar.addWidget(self.zoom); bar.addWidget(clear)
        lay.addLayout(bar)
        self.text = QPlainTextEdit(); self.text.setReadOnly(True); self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.text)
        self.search.textChanged.connect(self.filter_lines); self.zoom.valueChanged.connect(self.set_zoom)
        self.lines = []
        fit_controls(self, 40)
    def append(self, line):
        self.lines.append(line); self.filter_lines()
    def filter_lines(self):
        q = self.search.text().lower()
        self.text.setPlainText("\n".join(x for x in self.lines if q in x.lower()))
        self.text.moveCursor(QTextCursor.MoveOperation.End)
    def set_zoom(self, n):
        f = self.text.font(); f.setPointSize(n); self.text.setFont(f)
    def clear_log(self):
        self.lines.clear(); self.text.clear()


class WindowTitleBar(QFrame):
    def __init__(self, window):
        super().__init__(window); self.window=window; self.drag_pos=None
        self.setObjectName("WindowTitleBar"); self.setFixedHeight(42)
        row=QHBoxLayout(self); row.setContentsMargins(16,0,8,0); row.setSpacing(8)
        brand=QLabel("◈  MIKROTIK VPN MANAGER"); brand.setObjectName("ChromeBrand")
        brand.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        row.addWidget(brand); row.addStretch()
        for label,obj,fn in (("—","ChromeButton",window.showMinimized),("□","ChromeButton",self.toggle_maximize),("×","ChromeClose",window.close)):
            b=QPushButton(label); b.setObjectName(obj); b.setFixedSize(38,30); b.clicked.connect(fn); row.addWidget(b)
        self.max_button=row.itemAt(3).widget()
    def toggle_maximize(self):
        if self.window.isMaximized(): self.window.showNormal(); self.max_button.setText("□")
        else: self.window.showMaximized(); self.max_button.setText("❐")
    def mousePressEvent(self,event):
        if event.button()==Qt.MouseButton.LeftButton and not self.window.isMaximized():
            self.drag_pos=event.globalPosition().toPoint()-self.window.frameGeometry().topLeft(); event.accept()
    def mouseMoveEvent(self,event):
        if self.drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.window.move(event.globalPosition().toPoint()-self.drag_pos); event.accept()
    def mouseReleaseEvent(self,event): self.drag_pos=None
    def mouseDoubleClickEvent(self,event):
        if event.button()==Qt.MouseButton.LeftButton: self.toggle_maximize()


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.resize(1500, 960); self.setMinimumSize(1180, 780)
        self.q = queue.Queue(); self.router: Optional[RouterConnection] = None
        self.busy = False; self.targets = []; self.log_window = None; self.log_lines = []; self.last_diag = {}
        self.settings = self.load_settings()
        self.router_state = None; self.tr_rx = deque(maxlen=TrafficChart.N); self.tr_tx = deque(maxlen=TrafficChart.N); self.tr_prev = None; self.tr_busy = False
        self.normal_rx = deque(maxlen=TrafficChart.N); self.normal_tx = deque(maxlen=TrafficChart.N); self.wan_prev = None; self.pending_wg_config = None
        self.build_ui(); self.load_targets()
        self.timer = QTimer(self); self.timer.timeout.connect(self.poll); self.timer.start(120)
        # Автоматические проверки выключены; пользователь может отдельно включить опрос трафика.
        self.traffic_timer = QTimer(self); self.traffic_timer.timeout.connect(self.poll_traffic)
        self.traffic_timer.setInterval(5000)

    def load_settings(self):
        try: cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8")) if CONFIG_FILE.exists() else {}
        except Exception: cfg = {}
        defaults = {"host":"", "port":"2313", "username":"pwned", "key_file":"", "lan_interface":"INTERNET", "lan_subnet":"192.168.0.0/24", "lan_dns":"192.168.0.2", "route_table":"vpn", "wg_interface":"furynet-wg", "wan_interface":"WAN", "address_list":"vpn_domains", "wg_public_key":"", "wg_endpoint":"", "wg_port":"51820", "wg_allowed":"0.0.0.0/0", "wg_address":"", "wg_keepalive":"25"}
        defaults.update({k:str(v) for k,v in cfg.items() if k in defaults})
        return defaults

    def save_settings(self):
        if hasattr(self, "inputs"):
            self.settings = self.fields()
        if hasattr(self, "wg_inputs"):
            for k,w in self.wg_inputs.items():
                if k != "wg_private_key": self.settings[k] = w.text().strip()
        APP_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")

    def fields(self):
        return {k:w.text().strip() for k,w in self.inputs.items()}

    def build_ui(self):
        self.setStyleSheet(STYLE)
        root = Backdrop(); self.setCentralWidget(root)
        outer=QVBoxLayout(root); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        self.title_bar=WindowTitleBar(self); outer.addWidget(self.title_bar)
        main_host=QWidget(); main=QHBoxLayout(main_host); main.setContentsMargins(0,0,0,0); main.setSpacing(0)
        outer.addWidget(main_host,1)
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(238)
        sl = QVBoxLayout(sidebar); sl.setContentsMargins(20,26,20,20); sl.setSpacing(10)
        logo = QLabel("◈  MIKROTIK") ; logo.setObjectName("Brand")
        sl.addWidget(logo); sub = QLabel("NETWORK  /  VPN CONTROL"); sub.setObjectName("BrandSub"); sl.addWidget(sub); sl.addSpacing(28)
        self.nav = QListWidget(); self.nav.setObjectName("Nav")
        for label in ["01     Обзор", "02     VPN-маршрутизация", "03     Диагностика", "04     Firewall и DNS", "05     Резервные копии", "06     Настройки", "07     Терминал", "08     Журнал"]:
            QListWidgetItem(label, self.nav)
        self.nav.setCurrentRow(0); self.nav.currentRowChanged.connect(self.pages_changed)
        sl.addWidget(self.nav,1)
        foot = self.foot = QLabel("ROUTEROS 7  ·  SSH KEY AUTH\nSelective routing workspace"); foot.setObjectName("SidebarFoot"); foot.setWordWrap(True); sl.addWidget(foot)
        main.addWidget(sidebar)
        content = QWidget(); cv = QVBoxLayout(content); cv.setContentsMargins(32,26,32,24); cv.setSpacing(18); main.addWidget(content,1)
        header = QHBoxLayout(); titlebox = QVBoxLayout(); self.page_title=QLabel("Обзор сети"); self.page_title.setObjectName("PageTitle")
        self.page_sub=QLabel("Состояние маршрутизатора и VPN-туннеля"); self.page_sub.setObjectName("Muted")
        titlebox.addWidget(self.page_title); titlebox.addWidget(self.page_sub); header.addLayout(titlebox); header.addStretch()
        self.conn_badge=QLabel("●  НЕ ПОДКЛЮЧЕНО"); self.conn_badge.setObjectName("BadgeOff"); header.addWidget(self.conn_badge)
        self.log_btn=QPushButton("☷  Журнал операций"); self.log_btn.setObjectName("QuietButton"); self.log_btn.clicked.connect(lambda: self.nav.setCurrentRow(7)); header.addWidget(self.log_btn)
        cv.addLayout(header)
        div=QFrame(); div.setObjectName("Divider"); div.setFixedHeight(1); cv.addWidget(div)
        self.stack=QStackedWidget(); cv.addWidget(self.stack,1)
        self.pages=[]
        self.pages.append(self.page_dashboard()); self.pages.append(self.page_routing()); self.pages.append(self.page_diagnostics()); self.pages.append(self.page_firewall()); self.pages.append(self.page_backups()); self.pages.append(self.page_settings()); self.pages.append(self.page_terminal()); self.pages.append(self.page_logs())
        for p in self.pages: self.stack.addWidget(self.scrolled(p))
        footer=QHBoxLayout()
        self.status=QLabel("●  Готово  ·  Конфигурация меняется только после явного подтверждения")
        self.status.setObjectName("StatusBar"); footer.addWidget(self.status,1)
        grip=QSizeGrip(root); grip.setFixedSize(18,18); footer.addWidget(grip,0,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignBottom)
        cv.addLayout(footer)
        fit_controls(self)
        for fr in self.findChildren(QFrame):
            n = fr.objectName()
            if n == "Hero": add_shadow(fr, 44, 14, (10, 30, 90, 150))
            elif n in ("Panel", "Card"): add_shadow(fr, 32, 10, (0, 0, 0, 125))
        for b in self.findChildren(QPushButton):
            if b.objectName() == "PrimaryButton": add_shadow(b, 26, 5, (59, 130, 246, 130))

    def scrolled(self, page):
        sa = QScrollArea(); sa.setObjectName("PageScroll"); sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame); sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        sa.setWidget(page); sa.viewport().setAutoFillBackground(False); page.setAutoFillBackground(False)
        page.layout().setContentsMargins(6, 4, 16, 26)
        return sa

    def card(self, title, value="—", hint=""):
        f=QFrame(); f.setObjectName("Card"); l=QVBoxLayout(f); l.setContentsMargins(20,16,20,16); l.setSpacing(2); f.setMinimumHeight(118)
        t=QLabel(title.upper()); t.setObjectName("CardTitle"); v=QLabel(value); v.setObjectName("CardValue"); h=QLabel(hint); h.setObjectName("Muted"); [(lab.setWordWrap(True),lab.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Preferred)) for lab in (v,h)]; l.addWidget(t); l.addWidget(v); l.addWidget(h); l.addStretch()
        return f,v,h

    def page_dashboard(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(16)
        hero=QFrame(); hero.setObjectName("Hero")
        hl=QHBoxLayout(hero); hl.setContentsMargins(24,20,24,20); hl.setSpacing(18)
        intro=QVBoxLayout(); eyebrow=QLabel("NETWORK OVERVIEW  /  ROUTEROS"); eyebrow.setObjectName("Eyebrow")
        headline=QLabel("Управляй маршрутизацией."); headline.setObjectName("HeroTitle")
        description=QLabel("Контролируй WireGuard, выборочные маршруты, DNS и состояние MikroTik из одного окна.")
        description.setObjectName("HeroText"); description.setWordWrap(True)
        intro.addWidget(eyebrow); intro.addWidget(headline); intro.addWidget(description)
        hl.addLayout(intro,1)
        hero_actions=QVBoxLayout(); connect=QPushButton("Подключиться к роутеру  →"); connect.setObjectName("PrimaryButton"); connect.clicked.connect(self.connect_router)
        diag=QPushButton("Обновить состояние"); diag.setObjectName("HeroSecondary"); diag.clicked.connect(self.run_diagnostics)
        hero_actions.addWidget(connect); hero_actions.addWidget(diag); hero_actions.addStretch(); hl.addLayout(hero_actions)
        l.addWidget(hero)
        grid=QGridLayout(); grid.setSpacing(14); self.card_values={}; self.card_hints={}
        for i,(key,title,hint) in enumerate([("router","Маршрутизатор","Имя устройства / RouterOS"),("wg","WireGuard","Последний handshake peer"),("rx","Получено","Входящий трафик peer"),("tx","Передано","Исходящий трафик peer"),("vpnroute","VPN-маршрут","Default route в таблице vpn"),("dns","DNS-защита","DoH · redirect · блокировка 853")]):
            f,v,h=self.card(title,"—",hint); f.setProperty("metric",key); self.card_values[key]=v; self.card_hints[key]=h; grid.addWidget(f,i//3,i%3)
        for c in range(3): grid.setColumnStretch(c,1)
        l.addLayout(grid)
        mid=QHBoxLayout(); mid.setSpacing(14)
        tp=self.panel("Трафик WireGuard","Ожидание подключения к роутеру…"); self.tr_panel=tp
        self.chart=TrafficChart(); tp.layout().addWidget(self.chart,1)
        stats=QHBoxLayout(); stats.setSpacing(12); self.tr_labels={}
        for key,title in (("rx","<span style='color:#38bdf8'>●</span>  ПРИЁМ СЕЙЧАС"),("tx","<span style='color:#fbbf24'>●</span>  ПЕРЕДАЧА СЕЙЧАС"),("peak","ПИК ЗА 10 МИН"),("total","ВСЕГО RX / TX")):
            box=QVBoxLayout(); box.setSpacing(2); tl=QLabel(title); tl.setObjectName("CardTitle"); vl=QLabel("—"); vl.setObjectName("StatValue")
            box.addWidget(tl); box.addWidget(vl); stats.addLayout(box,1); self.tr_labels[key]=vl
        tp.layout().addLayout(stats)
        traffic_controls=QHBoxLayout()
        self.traffic_auto=QCheckBox("Автообновление трафика · 5 сек"); self.traffic_auto.setChecked(False)
        self.traffic_auto.toggled.connect(self.set_traffic_auto)
        refresh_traffic=QPushButton("Обновить сейчас"); refresh_traffic.clicked.connect(self.poll_traffic)
        traffic_controls.addWidget(self.traffic_auto); traffic_controls.addStretch(); traffic_controls.addWidget(refresh_traffic)
        tp.layout().addLayout(traffic_controls); mid.addWidget(tp,2)
        dp=self.panel("Состояние DNS","Защита от обхода и утечек"); self.dns_ind={}
        for i,(key,title) in enumerate((("overall","Общая защита"),("doh","DoH (DNS-over-HTTPS)"),("redirect","Перехват DNS :53"),("dot","Блокировка DoT/DoQ :853"),("remote","Remote requests"),("fwd","DNS FWD-записи"),("ips","IP в address-list"),("v6","IPv6 default route"))):
            if i:
                sep=QFrame(); sep.setObjectName("Sep"); sep.setFixedHeight(1); dp.layout().addWidget(sep)
            row=QHBoxLayout(); row.setSpacing(10); dot=Dot(); tl=QLabel(title); tl.setObjectName("IndTitle"); vl=QLabel("—"); vl.setObjectName("IndValue"); vl.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(dot); row.addWidget(tl,1); row.addWidget(vl); dp.layout().addLayout(row); self.dns_ind[key]=(dot,vl)
        dp.layout().addStretch(); mid.addWidget(dp,1); l.addLayout(mid)
        ap=self.panel("Активные VPN-цели","Подключись к роутеру, чтобы увидеть статусы"); self.active_panel=ap
        self.active_table=QTableWidget(0,3); self.active_table.setHorizontalHeaderLabels(["Цель","Тип","Статус"])
        hh=self.active_table.horizontalHeader(); hh.setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); hh.setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); hh.setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents)
        self.active_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.active_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.active_table.verticalHeader().hide(); self.active_table.verticalHeader().setDefaultSectionSize(38); self.active_table.setShowGrid(False); self.active_table.setAlternatingRowColors(True)
        self.active_table.setMinimumHeight(230); self.active_table.setMaximumHeight(360); ap.layout().addWidget(self.active_table); l.addWidget(ap)
        split=QHBoxLayout(); split.setSpacing(14)
        panel=self.panel("Сводка диагностики","Последний результат проверки конфигурации")
        self.dashboard_report=QPlainTextEdit(); self.dashboard_report.setReadOnly(True); self.dashboard_report.setMinimumHeight(190); self.dashboard_report.setPlaceholderText("Подключись к MikroTik, чтобы получить сводку состояния…"); self.dashboard_report.setObjectName("ReportView"); panel.layout().addWidget(self.dashboard_report)
        split.addWidget(panel,2)
        panel2=self.panel("Быстрые действия","Инструменты без перехода между разделами")
        for text,fn in [("Проверить VPN ping",self.test_vpn),("Проверить Firewall и DNS",self.refresh_firewall),("Создать backup + export",self.backup_router)]:
            b=QPushButton(text); b.setObjectName("ActionButton"); b.clicked.connect(fn); panel2.layout().addWidget(b)
        panel2.layout().addStretch(); split.addWidget(panel2,1); l.addLayout(split); l.addStretch()
        return w

    def panel(self,title,subtitle=""):
        f=QFrame(); f.setObjectName("Panel"); lay=QVBoxLayout(f); lay.setContentsMargins(18,16,18,16); lay.setSpacing(10)
        h=QLabel(title); h.setObjectName("SectionTitle"); lay.addWidget(h)
        f.sub_label=None
        if subtitle: s=QLabel(subtitle); s.setObjectName("Muted"); s.setWordWrap(True); lay.addWidget(s); f.sub_label=s
        return f

    def page_routing(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(12)
        p=self.panel("Цели выборочной маршрутизации","Добавляй домены, отдельные IPv4 (/32) и сети CIDR. IPv6 пока не поддерживается.")
        row=QHBoxLayout(); self.target_input=QLineEdit(); self.target_input.setPlaceholderText("example.com  ·  203.0.113.10  ·  203.0.113.0/24")
        add=QPushButton("＋ Добавить цель"); add.setObjectName("PrimaryButton"); add.clicked.connect(self.add_target); self.target_input.returnPressed.connect(self.add_target)
        row.addWidget(self.target_input,1); row.addWidget(add); p.layout().addLayout(row)
        row2=QHBoxLayout(); self.preset=QComboBox(); self.preset.addItems(PRESETS.keys()); load=QPushButton("Загрузить профиль"); load.clicked.connect(self.load_preset); load_all=QPushButton("Добавить все профили"); load_all.setObjectName("PrimaryButton"); load_all.clicked.connect(self.load_all_presets); row2.addWidget(self.preset); row2.addWidget(load); row2.addWidget(load_all)
        import_btn=QPushButton("Импорт TXT/CSV"); import_btn.clicked.connect(self.import_targets_file); row2.addWidget(import_btn)
        export_btn=QPushButton("Экспорт CSV"); export_btn.clicked.connect(self.export_targets_file); row2.addWidget(export_btn)
        row2.addStretch()
        self.target_search=QLineEdit(); self.target_search.setPlaceholderText("Поиск по списку…"); self.target_search.textChanged.connect(self.filter_targets); row2.addWidget(self.target_search,1); p.layout().addLayout(row2)
        self.target_table=QTableWidget(0,7); self.target_table.setHorizontalHeaderLabels(["Цель","Тип","Источник","В приложении","На роутере","Состояние цели","Детали"]); self.target_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); self.target_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); self.target_table.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents); self.target_table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.ResizeToContents); self.target_table.horizontalHeader().setSectionResizeMode(4,QHeaderView.ResizeMode.ResizeToContents); self.target_table.horizontalHeader().setSectionResizeMode(5,QHeaderView.ResizeMode.ResizeToContents); self.target_table.horizontalHeader().setSectionResizeMode(6,QHeaderView.ResizeMode.Stretch); self.target_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.target_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection); self.target_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.target_table.verticalHeader().hide(); self.target_table.setAlternatingRowColors(True); self.target_table.setShowGrid(False); self.target_table.verticalHeader().setDefaultSectionSize(38); self.target_table.setMinimumHeight(300); p.layout().addWidget(self.target_table,1)
        actions=QHBoxLayout()
        for text,fn,obj in [("Удалить локально",self.remove_local,"DangerButton"),("Предпросмотр применения",self.preview_apply,"Button"),("Применить на роутер",self.apply_all,"PrimaryButton"),("Удалить выбранное с роутера",self.remove_remote,"DangerButton"),("Обновить статусы",self.refresh_address_list,"Button")]:
            b=QPushButton(text); b.setObjectName(obj); b.clicked.connect(fn); actions.addWidget(b)
        p.layout().addLayout(actions); l.addWidget(p,1)
        note=QLabel("Логика: DNS FWD / address-list → mangle prerouting → routing table vpn → WireGuard. Основной default route через ZTE не изменяется."); note.setObjectName("InfoNote"); note.setWordWrap(True); l.addWidget(note)
        control=self.panel("Управление VPN-маршрутизацией","Временное переключение выборочного трафика между WireGuard и основным маршрутом через ZTE.")
        safety_row=QHBoxLayout()
        disable=QPushButton("Временно отключить VPN-маршрутизацию"); disable.setObjectName("DangerButton"); disable.clicked.connect(lambda:self.set_managed_mangle(False))
        enable=QPushButton("Включить VPN-маршрутизацию"); enable.setObjectName("PrimaryButton"); enable.clicked.connect(lambda:self.set_managed_mangle(True))
        safety_row.addWidget(disable); safety_row.addWidget(enable)
        self.mangle_status=QLabel("●  Статус: не проверен"); self.mangle_status.setObjectName("IndValue")
        self.mangle_state="unknown"
        check_mangle=QPushButton("Проверить статус"); check_mangle.clicked.connect(self.refresh_mangle_status)
        safety_row.addWidget(self.mangle_status,1); safety_row.addWidget(check_mangle)
        control.layout().addLayout(safety_row)
        control_note=QLabel("Переключается только правило VPN-MANAGER-DOMAIN-ROUTE. NAT, DNS, WireGuard и основной маршрут через ZTE не изменяются.")
        control_note.setObjectName("Muted"); control_note.setWordWrap(True); control.layout().addWidget(control_note)
        l.addWidget(control)
        return w

    def page_diagnostics(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Диагностика","Сбор состояния интерфейсов, peer, маршрутов, DNS и Firewall. Команды только читают конфигурацию.")
        row=QHBoxLayout()
        for text,fn in [("Полная диагностика",self.run_diagnostics),("Тест ping через VPN",self.test_vpn),("Ping WAN",self.ping_wan),("Traceroute",self.traceroute)]:
            b=QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        row.addStretch()
        clr=QPushButton("Очистить"); clr.setObjectName("QuietButton"); clr.clicked.connect(lambda:self.diag_text.clear()); row.addWidget(clr)
        cpy=QPushButton("Копировать"); cpy.setObjectName("QuietButton"); cpy.clicked.connect(lambda:QApplication.clipboard().setText(self.diag_text.toPlainText())); row.addWidget(cpy)
        p.layout().addLayout(row)
        client_box=QHBoxLayout()
        self.client_input=QLineEdit(); self.client_input.setPlaceholderText("IP телефона в LAN, например 192.168.0.50")
        client_box.addWidget(self.client_input,1)
        for label,fn in [("DHCP-клиенты",self.show_dhcp_clients),("Проверить IP клиента",self.diagnose_client),("Счётчики Mangle/DNS",self.show_policy_counters)]:
            b=QPushButton(label); b.clicked.connect(fn); client_box.addWidget(b)
        p.layout().addLayout(client_box)
        self.diag_text=QTextEdit(); self.diag_text.setObjectName("DiagView"); self.diag_text.setReadOnly(True); self.diag_text.setAcceptRichText(False); self.diag_text.setPlaceholderText("Результаты диагностики появятся здесь…"); self.diag_text.setMinimumHeight(300); p.layout().addWidget(self.diag_text,1)
        l.addWidget(p,1); return w

    def page_firewall(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Firewall и DNS","Просмотр ключевых правил защиты DNS, NAT и policy routing. Никакие правила здесь не редактируются автоматически.")
        row=QHBoxLayout()
        for text,fn in [("Обновить данные",self.refresh_firewall),("Показать NAT",lambda:self.read_command("/ip firewall nat print detail",self.firewall_text)),("Показать Filter",lambda:self.read_command("/ip firewall filter print detail",self.firewall_text)),("Показать Mangle",lambda:self.read_command("/ip firewall mangle print detail",self.firewall_text)),("DNS static",lambda:self.read_command("/ip dns static print detail",self.firewall_text))]:
            b=QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        p.layout().addLayout(row); self.firewall_text=QPlainTextEdit(); self.firewall_text.setMinimumHeight(300); self.firewall_text.setReadOnly(True); p.layout().addWidget(self.firewall_text,1); l.addWidget(p,1); return w

    def page_backups(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Резервные копии","Создаёт .backup и текстовый .rsc export на MikroTik, затем скачивает оба файла по SFTP на этот компьютер.")
        self.backup_dir=QLineEdit(str(Path.home()/"Documents"/"MikroTik Backups")); browse=QPushButton("Обзор…"); browse.clicked.connect(self.choose_backup_dir)
        row=QHBoxLayout(); row.addWidget(self.backup_dir,1); row.addWidget(browse); p.layout().addLayout(row)
        b=QPushButton("Создать и скачать backup + export"); b.setObjectName("PrimaryButton"); b.clicked.connect(self.backup_router); p.layout().addWidget(b)
        self.backup_info=QLabel("Перед созданием копии проверь свободное место на компьютере и роутере."); self.backup_info.setObjectName("Muted"); p.layout().addWidget(self.backup_info); p.layout().addStretch(); l.addWidget(p,1); return w

    def page_settings(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Подключение и параметры","Параметры сохраняются локально. Passphrase приватного ключа не сохраняется.")
        form=QFormLayout(); self.inputs={}; form.setVerticalSpacing(12); form.setHorizontalSpacing(22); form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter); form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        fields=[("Адрес MikroTik","host"),("SSH-порт","port"),("Пользователь","username"),("Приватный ключ SSH","key_file"),("LAN bridge","lan_interface"),("LAN subnet","lan_subnet"),("LAN DNS IP","lan_dns"),("Routing table","route_table"),("WireGuard interface","wg_interface"),("WAN interface","wan_interface"),("Address-list","address_list")]
        for label,key in fields:
            e=QLineEdit(self.settings[key]); self.inputs[key]=e
            if key=="key_file":
                wrap=QWidget(); rr=QHBoxLayout(wrap); rr.setContentsMargins(0,0,0,0); rr.addWidget(e,1); bb=QPushButton("Выбрать ключ"); bb.clicked.connect(lambda _=False, x=e:self.choose_key(x)); rr.addWidget(bb); form.addRow(label,wrap)
            else: form.addRow(label,e)
        self.passphrase=QLineEdit(); self.passphrase.setEchoMode(QLineEdit.EchoMode.Password); self.passphrase.setPlaceholderText("Если ключ защищён passphrase"); form.addRow("Passphrase ключа",self.passphrase)
        p.layout().addLayout(form)
        wg=self.panel("Профиль WireGuard / смена VPN-провайдера","Импортируй конфигурацию провайдера .conf или заполни поля вручную. Правила маршрутизации сохраняются.")
        wgform=QFormLayout(); self.wg_inputs={}
        for label,key in [("PrivateKey (секретный)","wg_private_key"),("PublicKey сервера","wg_public_key"),("Endpoint (домен/IP)","wg_endpoint"),("Endpoint port","wg_port"),("AllowedIPs","wg_allowed"),("Address интерфейса","wg_address"),("Persistent keepalive, сек.","wg_keepalive")]:
            e=QLineEdit("" if key=="wg_private_key" else self.settings.get(key,""))
            if key=="wg_private_key": e.setEchoMode(QLineEdit.EchoMode.Password); e.setPlaceholderText("Не сохраняется на диск")
            self.wg_inputs[key]=e; wgform.addRow(label,e)
        wg.layout().addLayout(wgform)
        wgbuttons=QHBoxLayout()
        imp=QPushButton("Импортировать .conf"); imp.clicked.connect(self.import_wireguard_conf)
        applywg=QPushButton("Применить новый VPN-профиль"); applywg.setObjectName("PrimaryButton"); applywg.clicked.connect(self.apply_wireguard_profile)
        wgbuttons.addWidget(imp); wgbuttons.addWidget(applywg); wg.layout().addLayout(wgbuttons)
        warning=QLabel("Будут изменены ключ интерфейса, параметры peer и адрес WG-интерфейса. Mangle, NAT, address-list и default route не меняются. Старый адрес на WG-интерфейсе заменяется, если указан новый Address.")
        warning.setObjectName("InfoNote"); warning.setWordWrap(True); wg.layout().addWidget(warning); l.addWidget(wg)
        row=QHBoxLayout(); save=QPushButton("Сохранить параметры"); save.setObjectName("PrimaryButton"); save.clicked.connect(self.save_settings); conn=QPushButton("Подключиться и проверить"); conn.clicked.connect(self.connect_router); disc=QPushButton("Отключиться"); disc.clicked.connect(self.disconnect_router); row.addWidget(save); row.addWidget(conn); row.addWidget(disc); p.layout().addLayout(row); p.layout().addStretch(); l.addWidget(p,1); return w

    def page_terminal(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(14)
        panel=QFrame(); panel.setObjectName("Panel")
        pl=QVBoxLayout(panel); pl.setContentsMargins(18,18,18,18); pl.setSpacing(12)
        bar=QHBoxLayout()
        heading=QVBoxLayout()
        title=QLabel("RouterOS CLI"); title.setObjectName("SectionTitle")
        subtitle=QLabel("Команды выполняются на MikroTik через текущее SSH-подключение.")
        subtitle.setObjectName("Muted")
        heading.addWidget(title); heading.addWidget(subtitle); bar.addLayout(heading,1)
        copy_btn=QPushButton("Копировать вывод"); copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.terminal_output.toPlainText()))
        clear_btn=QPushButton("Очистить"); clear_btn.clicked.connect(lambda: self.terminal_output.clear())
        bar.addWidget(copy_btn); bar.addWidget(clear_btn); pl.addLayout(bar)
        self.terminal_output=QPlainTextEdit()
        self.terminal_output.setObjectName("TerminalOutput")
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.terminal_output.setPlaceholderText("Вывод команд RouterOS появится здесь…")
        self.terminal_output.setMinimumHeight(420)
        self.terminal_output.setStyleSheet("QPlainTextEdit#TerminalOutput { background:#03060b; color:#c9d7e8; border:1px solid #1b2b43; border-radius:12px; padding:14px; font-family:'Cascadia Mono','Consolas',monospace; font-size:10pt; selection-background-color:#244b82; }")
        pl.addWidget(self.terminal_output,1)
        command_row=QHBoxLayout(); command_row.setSpacing(10)
        prompt=QLabel(">")
        prompt.setStyleSheet("color:#4ade80;font-family:Consolas,monospace;font-size:15pt;font-weight:700")
        self.terminal_input=QLineEdit()
        self.terminal_input.setPlaceholderText("/system resource print")
        self.terminal_input.setClearButtonEnabled(True)
        self.terminal_input.returnPressed.connect(self.terminal_execute)
        execute=QPushButton("Выполнить  ↵"); execute.setObjectName("PrimaryButton"); execute.clicked.connect(self.terminal_execute)
        command_row.addWidget(prompt); command_row.addWidget(self.terminal_input,1); command_row.addWidget(execute)
        pl.addLayout(command_row)
        l.addWidget(panel,1)
        note=QLabel("Внимание: это полноценный CLI RouterOS. Команды изменения конфигурации выполняются напрямую. Перед использованием проверяй команду; не вставляй неизвестные скрипты.")
        note.setObjectName("InfoNote"); note.setWordWrap(True); l.addWidget(note)
        return w

    def terminal_execute(self):
        if self.busy:
            self.status.setText("●  Дождись завершения текущей операции.")
            return
        command=self.terminal_input.text().strip()
        if not command: return
        if "\n" in command or "\r" in command:
            QMessageBox.warning(self,"Некорректная команда","Вводи одну команду RouterOS за раз.")
            return
        self.terminal_input.clear()
        stamp=datetime.now().strftime("%H:%M:%S")
        self.terminal_output.appendPlainText(f"\n[{stamp}] $ {command}")
        self.terminal_output.moveCursor(QTextCursor.MoveOperation.End)
        def job():
            try:
                r=self.router_conn()
                result=r.exec(command,timeout=60)
                self.q.put(("TERMOUT",result or "(пустой вывод)"))
            except Exception as e:
                self.q.put(("TERMOUT","ОШИБКА: "+str(e)))
        self.run_job("RouterOS CLI: "+command,job)

    def pages_changed(self,index):
        titles=[("Обзор сети","Состояние маршрутизатора и VPN-туннеля"),("VPN-маршрутизация","Домены, IPv4 и сети, направляемые через WireGuard"),("Диагностика","Проверки соединения и сетевой доступности"),("Firewall и DNS","Просмотр правил и защита DNS"),("Резервные копии","Локальное сохранение конфигурации MikroTik"),("Настройки","SSH и профиль VPN-провайдера"),("Терминал RouterOS","Интерактивная командная строка MikroTik через SSH"),("Журнал операций","История действий, команд и ошибок приложения")]
        self.stack.setCurrentIndex(index); self.page_title.setText(titles[index][0]); self.page_sub.setText(titles[index][1])

    def log(self,msg):
        line=f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
        self.log_lines.append(line)
        if self.log_window: self.log_window.append(line)
        if hasattr(self,"log_view"): self.filter_log_page()
        self.status.setText(msg.replace("\n"," ")[:220])

    def open_log(self):
        if not self.log_window:
            self.log_window=LogWindow(self)
            for line in self.log_lines: self.log_window.append(line)
        self.log_window.show(); self.log_window.raise_(); self.log_window.activateWindow()

    def poll(self):
        try:
            while True:
                kind,payload=self.q.get_nowait()
                if kind=="LOG": self.log(str(payload))
                elif kind=="TRUST":
                    d=payload
                    ans=QMessageBox.question(self,"Проверка SSH host key",f"Первое подключение к {d['host']}:{d['port']}\nТип: {d['type']}\nFingerprint: {d['fp']}\n\nСверь fingerprint с MikroTik перед подтверждением. Доверять ключу?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
                    d["result"]["accept"]=ans==QMessageBox.StandardButton.Yes; d["event"].set()
                elif kind=="CONNECTED": self.conn_badge.setText("●  SSH ПОДКЛЮЧЁН"); self.foot.setText(f"ROUTEROS 7  ·  SSH KEY AUTH\n{self.settings['host']}:{self.settings['port']}"); self.reset_traffic(True); self.conn_badge.setObjectName("BadgeOn"); self.conn_badge.style().unpolish(self.conn_badge); self.conn_badge.style().polish(self.conn_badge); self.log(f"SSH fingerprint {payload['fp']} ({'known' if payload['known'] else 'new key saved'})")
                elif kind=="ERROR": self.busy=False; self.log("ОШИБКА: "+str(payload)); self.diag_block("Ошибка",str(payload),True,True); QMessageBox.critical(self,"Ошибка",str(payload))
                elif kind=="DONE": self.busy=False; self.log("Операция завершена.")
                elif kind=="TRAFFIC": self.on_traffic(payload)
                elif kind=="TARGETS": self.on_targets(payload)
                elif kind=="MANGLE_STATUS": self.on_mangle_status(payload)
                elif kind=="DIAGBEGIN": self.diag_begin(payload)
                elif kind=="DIAGOUT": self.diag_block(*payload)
                elif kind=="DIAG":
                    result,silent=payload; self.last_diag=result
                    self.dashboard_report.setPlainText("\n".join(f"{k}: {v}" for k,v in result.items()))
                    mapping={"router":"Маршрутизатор","wg":"WireGuard handshake","rx":"RX","tx":"TX","vpnroute":"VPN default route"}
                    for card,key in mapping.items():
                        if card in self.card_values: self.card_values[card].setText(str(result.get(key,"—")))
                    doh=result.get("DoH")=="включён"; red=not result.get("DNS redirect UDP/TCP","не").startswith("не"); dot=not result.get("DoT/DoQ block","не").startswith("не")
                    n=int(doh)+int(red)+int(dot)
                    self.card_values["dns"].setText({3:"Защищён",0:"Не защищён"}.get(n,"Частично")); self.card_hints["dns"].setText(result.get("DNS security",""))
                    self.update_dns_indicators(result)
                    for key in ("rx","tx"):
                        v=str(result.get(key.upper(),""))
                        if v.isdigit(): self.card_values[key].setText(human_bytes(int(v)))
                    if not silent: self.diag_summary(result)
                elif kind=="TERMOUT":
                    self.terminal_output.appendPlainText(str(payload)); self.terminal_output.moveCursor(QTextCursor.MoveOperation.End)
                elif kind=="DISCONNECTED":
                    self.conn_badge.setText("●  НЕ ПОДКЛЮЧЕНО"); self.conn_badge.setObjectName("BadgeOff"); self.conn_badge.style().unpolish(self.conn_badge); self.conn_badge.style().polish(self.conn_badge)
                    self.router_state=None; self.render_targets(); self.reset_traffic(); self.mangle_status.setText("●  Статус: не проверен (нет SSH)"); self.mangle_status.setStyleSheet(f"color:{TONES['muted']};font-weight:700"); self.foot.setText("ROUTEROS 7  ·  SSH KEY AUTH\nSelective routing workspace")
                    for k in self.dns_ind: self.set_ind(k,"off","—")
                    self.log("SSH отключён")
                elif kind=="TEXT": payload[0].setPlainText(payload[1])
                elif kind=="BACKUP": self.backup_info.setText(payload)
        except queue.Empty: pass

    # ---------- индикаторы DNS ----------
    def set_ind(self,key,state,text):
        dot,val=self.dns_ind[key]; dot.set_state(state); val.setText(text)
        val.setStyleSheet(f"color:{TONES.get(state,TONES['off'])};font-weight:600")

    def update_dns_indicators(self,result):
        doh=result.get("DoH","")=="включён"
        self.set_ind("doh","ok" if doh else "warn","включён" if doh else "не подтверждён")
        red=result.get("DNS redirect UDP/TCP","не обнаружен")
        self.set_ind("redirect","ok" if red=="UDP + TCP" else ("bad" if red.startswith("не") else "warn"),red if not red.startswith("не") else "нет")
        dot=result.get("DoT/DoQ block","не обнаружена")
        self.set_ind("dot","ok" if dot=="TCP/853 + UDP/853" else ("bad" if dot.startswith("не") else "warn"),dot if not dot.startswith("не") else "нет")
        rem=result.get("Remote requests","")=="включён"
        self.set_ind("remote","ok" if rem else "bad","включён" if rem else "выключен")
        v6=result.get("IPv6 default route","не обнаружен").startswith("не")
        self.set_ind("v6","ok" if v6 else "warn","нет" if v6 else "есть · обход IPv4")
        good=[doh,red=="UDP + TCP",dot=="TCP/853 + UDP/853",rem]
        n=sum(1 for x in good if x)
        self.set_ind("overall","ok" if n==4 else ("bad" if n==0 else "warn"),"Защищён" if n==4 else ("Не защищён" if n==0 else f"Частично · {n}/4"))

    # ---------- трафик WireGuard ----------
    def reset_traffic(self,connected=False):
        self.tr_rx.clear(); self.tr_tx.clear(); self.tr_prev=None; self.normal_rx.clear(); self.normal_tx.clear(); self.wan_prev=None
        if hasattr(self,"normal_chart"): self.normal_chart.set_data([],[])
        self.chart.msg="Сбор данных…" if connected else "Нет данных — подключись к роутеру"; self.chart.set_data([],[])
        for v in self.tr_labels.values(): v.setText("—")
        self.tr_panel.sub_label.setText("Ожидание данных от peer…" if connected else "Ожидание подключения к роутеру…")

    def set_traffic_auto(self,enabled):
        if enabled:
            self.traffic_timer.start(); self.poll_traffic()
            self.log("Автообновление счётчиков WireGuard включено: интервал 5 секунд.")
        else:
            self.traffic_timer.stop(); self.log("Автообновление счётчиков WireGuard отключено.")

    def poll_traffic(self):
        r=self.router
        if self.tr_busy or not r or not r.client: return
        self.tr_busy=True; wg=self.settings.get("wg_interface","")
        def work():
            try:
                out=r.exec(f"/interface wireguard peers print detail where interface={ros_q(wg)}",8)
                rx=sum(int(x) for x in re.findall(r"\brx=(\d+)",out)); tx=sum(int(x) for x in re.findall(r"\btx=(\d+)",out))
                hs=re.findall(r"last-handshake=(\S+)",out); peers=out.count("public-key=")
                self.q.put(("TRAFFIC",(time.monotonic(),rx,tx,hs[0] if hs else None,peers)))
            except Exception: self.q.put(("TRAFFIC",None))
            finally: self.tr_busy=False
        threading.Thread(target=work,daemon=True).start()

    def on_traffic(self,payload):
        if payload is None:
            if not self.tr_rx: self.chart.msg="Нет ответа от роутера…"; self.chart.update()
            return
        t,rx,tx,hs,peers=payload
        if self.tr_prev:
            pt,prx,ptx=self.tr_prev; dt=t-pt
            if dt>0.5: self.tr_rx.append(max(0,rx-prx)/dt); self.tr_tx.append(max(0,tx-ptx)/dt)
        self.tr_prev=(t,rx,tx)
        if self.tr_rx:
            self.tr_labels["rx"].setText(fmt_bits(self.tr_rx[-1]*8)); self.tr_labels["tx"].setText(fmt_bits(self.tr_tx[-1]*8))
            self.tr_labels["peak"].setText(fmt_bits(max(self.tr_rx+self.tr_tx)*8))
        self.tr_labels["total"].setText(f"{human_bytes(rx)} / {human_bytes(tx)}")
        self.tr_panel.sub_label.setText(f"Peers: {peers} · последний handshake: {hs or 'нет'} · обновление каждые 5 с")
        self.chart.msg="Сбор данных…"; self.chart.set_data(self.tr_rx,self.tr_tx)

    # ---------- статусы VPN-целей ----------
    def fetch_targets(self,r):
        alist=self.settings["address_list"]
        dns=parse_terse(r.exec('/ip dns static print terse where comment~"VPN-MANAGER:"'))
        dns_cache=parse_terse(r.exec('/ip dns cache print terse'))
        managed_al=parse_terse(r.exec('/ip firewall address-list print terse where comment~"VPN-MANAGER-CIDR:"'))
        all_al=parse_terse(r.exec(f'/ip firewall address-list print terse where list={ros_q(alist)}'))
        total=len(all_al)
        dynamic_entries=[it for it in all_al if "D" in it["flags"]]
        static_entries=[it for it in all_al if "D" not in it["flags"]]
        dyn=len(dynamic_entries)
        dynamic_ips=sorted({it["f"].get("address","") for it in dynamic_entries if it["f"].get("address")})
        static_ips=sorted({it["f"].get("address","") for it in static_entries if it["f"].get("address")})
        found={}
        for it in dns:
            fields=it["f"]; c=fields.get("comment","")
            if c.startswith("VPN-MANAGER:"):
                target=c.split(":",1)[1]
                detail="DNS static FWD"
                if fields.get("address-list"): detail+=f' · address-list={fields["address-list"]}'
                if fields.get("match-subdomain"): detail+=f' · match-subdomain={fields["match-subdomain"]}'
                match_sub=fields.get("match-subdomain","")=="yes"
                cache_ips=set()
                for entry in dns_cache:
                    cf=entry["f"]; cached_name=cf.get("name","").lower().rstrip(".")
                    name_match=(cached_name==target or (match_sub and cached_name.endswith("."+target)))
                    if name_match and cf.get("type","").upper()=="A":
                        try: cache_ips.add(str(ipaddress.ip_address(cf.get("data",""))))
                        except ValueError: pass
                in_address_list=cache_ips.intersection(dynamic_ips)
                detail += f" · DNS cache A: {len(cache_ips)} IP · совпало с динамическим address-list: {len(in_address_list)}"
                found[target]=("Домен","X" in it["flags"],"I" in it["flags"],detail,bool(in_address_list),len(cache_ips))
        for it in managed_al:
            fields=it["f"]; c=fields.get("comment","")
            if c.startswith("VPN-MANAGER-CIDR:"):
                target=c.split(":",1)[1]
                kind="IPv4-адрес" if target.endswith("/32") else "IPv4-сеть"
                try:
                    wanted=ipaddress.ip_network(target,strict=False)
                    present=any(ipaddress.ip_network(a,strict=False)==wanted for a in static_ips)
                except ValueError:
                    present=False
                detail="IP присутствует в address-list" if present else "Запись есть, но адрес не найден в address-list"
                found[target]=(kind,"X" in it["flags"],"I" in it["flags"],detail,present)
        self.q.put(("TARGETS",{"found":found,"dyn":dyn,"total":total,"dns_count":len(dns),"dynamic_ips":dynamic_ips,"static_ips":static_ips}))

    def on_targets(self,payload):
        self.router_state=payload; self.render_targets()
        self.set_ind("fwd","ok" if payload["dns_count"]>0 else "off",f'{payload["dns_count"]} FWD')
        total,dyn=payload["total"],payload["dyn"]
        self.set_ind("ips","ok" if total>0 else "off",f"{dyn} дин. · {total-dyn} стат." if total else "пусто")

    def status_for(self,t,is_local):
        st=self.router_state
        if st is None: return ("Не проверено","muted")
        f=st["found"].get(t)
        if f is None: return ("Не применена","muted")
        if f[2]: return ("Ошибка конфигурации","bad")
        if f[1]: return ("Запись отключена","warn")
        if getattr(self,"mangle_state","unknown")=="disabled": return ("Цель есть · VPN-маршрутизация выключена","warn")
        if getattr(self,"mangle_state","unknown")=="invalid": return ("Цель есть · ошибка правила маршрутизации","bad")
        if getattr(self,"mangle_state","unknown")=="unknown": return ("Цель есть · правило маршрутизации не подтверждено","warn")
        if f[0]=="Домен":
            if len(f)<6 or not f[5]: return ("FWD настроена · DNS ещё не разрешён","info")
            return ("DNS разрешён · IP в address-list","ok") if f[4] else ("DNS разрешён · IP не попал в список","warn")
        if len(f)>=5 and not f[4]: return ("Нет IP в address-list","warn")
        return ("Применена на роутере","ok") if is_local else ("Только на роутере","info")

    def fetch_mangle_status(self,r):
        entries=parse_terse(r.exec(f'/ip firewall mangle print terse where comment={ros_q(MANGLE_COMMENT)}'))
        if len(entries)!=1:
            state="unknown"
            label="Не определён" if not entries else f"Неоднозначно: найдено {len(entries)} правил"
        elif "I" in entries[0]["flags"]:
            state="invalid"; label="Ошибка (invalid)"
        elif "X" in entries[0]["flags"]:
            state="disabled"; label="Отключено"
        else:
            state="enabled"; label="Включено"
        self.q.put(("MANGLE_STATUS",{"state":state,"label":label,"checked":datetime.now().strftime("%H:%M:%S")}))

    def on_mangle_status(self,payload):
        if not hasattr(self,"mangle_status"): return
        state=payload["state"]; label=payload["label"]
        self.mangle_state=state
        tone={"enabled":"ok","disabled":"warn","invalid":"bad","unknown":"muted"}.get(state,"muted")
        self.mangle_status.setText(f'●  {label} · проверено {payload["checked"]}')
        self.mangle_status.setStyleSheet(f"color:{TONES[tone]};font-weight:700")
        self.render_targets()

    def refresh_mangle_status(self):
        def job(): self.fetch_mangle_status(self.router_conn())
        self.run_job("Проверка состояния VPN-маршрутизации…",job)

    def render_active(self):
        tb=self.active_table; tb.setRowCount(0); sub=self.active_panel.sub_label; st=self.router_state
        if st is None:
            sub.setText("Подключись к роутеру, чтобы увидеть статусы"); return
        found=st["found"]; local={x for x,_ in self.targets}
        active=sum(1 for f in found.values() if not f[1] and not f[2]); disabled=sum(1 for f in found.values() if f[1]); invalid=sum(1 for f in found.values() if f[2])
        pending=len([x for x in local if x not in found]); ronly=len([x for x in found if x not in local])
        sub.setText(f"Активно {active} · отключено {disabled} · ошибочных {invalid} · не применено {pending} · только на роутере {ronly} · address-list: {st['dyn']} дин. IP")
        for tg,f in sorted(found.items()):
            label,tone=self.status_for(tg,tg in local); i=tb.rowCount(); tb.insertRow(i)
            for j,val in enumerate((tg,f[0],"●  "+label)):
                item=QTableWidgetItem(val)
                if j==2:
                    item.setForeground(QBrush(QColor(TONES[tone]))); ft=item.font(); ft.setBold(True); item.setFont(ft)
                tb.setItem(i,j,item)

    def diag_begin(self,title):
        self.diag_text.clear()
        self.diag_text.append(f'<div style="color:#ffffff;font-size:13pt;font-weight:700">{esc(title)}</div><div style="color:#6a80a6">{datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</div>')

    def diag_summary(self,result):
        rows=""
        for k,v in result.items():
            if k=="DNS security": continue
            v=str(v); low=v.lower()
            bad=low.startswith("не ") or low.startswith("ещё не") or low.startswith("выключ") or "возможен" in low or low.startswith("error")
            good=low.startswith(("есть","найден","включён","udp","tcp"))
            color="#fbbf24" if bad else ("#4ade80" if good else "#e8edf6")
            mark="▲" if bad else ("●" if good else "·")
            rows+=f'<tr><td style="color:#8a9fbf;padding:4px 18px 4px 0">{esc(k)}</td><td style="color:{color};font-weight:600">{mark} {esc(v)}</td></tr>'
        self.diag_text.append(f'<div style="margin-top:14px;color:#7db0ff;font-weight:700">▌ СВОДКА</div><table cellspacing="0" cellpadding="0">{rows}</table>')

    def diag_block(self,title,text,error=False,follow=True):
        sb=self.diag_text.verticalScrollBar(); pos=sb.value()
        head="#fb7185" if error else "#7db0ff"; body="#fda4af" if error else "#b9c8de"
        self.diag_text.append(f'<div style="margin-top:16px;color:{head};font-weight:700">▌ {esc(title)} <span style="color:#5f7499;font-weight:400">· {datetime.now().strftime("%H:%M:%S")}</span></div><pre style="color:{body};margin:4px 0 0 0">{esc(text or "(пустой вывод)")}</pre>')
        if not follow: sb.setValue(pos)

    def diag_run(self,title,command,timeout=30):
        r=self.router_conn(); out=self.cmd(r,command,timeout)
        self.q.put(("DIAGOUT",(f"{title}  ·  {command}",out,False,True)))

    def run_job(self,label,fn):
        if self.busy: return
        # Snapshot widget values on the GUI thread; worker threads never read Qt widgets.
        if hasattr(self, "inputs"):
            self.settings = self.fields()
            if hasattr(self,"wg_inputs"):
                for k,w in self.wg_inputs.items():
                    if k != "wg_private_key": self.settings[k] = w.text().strip()
            self.passphrase_value = self.passphrase.text() if hasattr(self, "passphrase") else ""
        self.busy=True; self.log(label)
        def runner():
            try: fn(); self.q.put(("DONE",None))
            except Exception as e: self.q.put(("ERROR",str(e)))
        threading.Thread(target=runner,daemon=True).start()

    def router_conn(self):
        if self.router:
            tr=self.router.client.get_transport() if self.router.client else None
            if tr and tr.is_active(): return self.router
            self.router.close(); self.router=None
        f=self.settings; port=int(f["port"])
        if not 1<=port<=65535: raise ValueError("SSH-порт вне диапазона 1–65535")
        r=RouterConnection(f["host"],port,f["username"],f["key_file"],getattr(self,"passphrase_value",""),self.q)
        known,fp=r.connect(); self.router=r; self.q.put(("CONNECTED",{"known":known,"fp":fp})); return r

    def connect_router(self):
        def job():
            r=self.router_conn()
            self.fetch_targets(r)
            self.fetch_mangle_status(r)
        self.run_job("Подключение к MikroTik и чтение статусов…",job)

    def disconnect_router(self):
        r=self.router
        self.router=None
        if not r:
            self.q.put(("DISCONNECTED",None))
            return
        self.log("Отключение SSH…")
        # Закрытие сокета выполняется в worker; UI-поток не ждёт завершения SSH-команды.
        threading.Thread(target=lambda:(r.close(),self.q.put(("DISCONNECTED",None))),daemon=True).start()

    def cmd(self,r,command,timeout=30):
        out=r.exec(command,timeout); self.q.put(("LOG",f"$ {command}\n{out or '(пустой вывод)'}")); return out

    def diagnostics(self,r,run_ping=False,silent=False):
        f=self.settings;
        if not silent: self.q.put(("DIAGBEGIN","Тест ping через WireGuard" if run_ping else "Полная диагностика"))
        checks={
            "Router identity": "/system identity print",
            "RouterOS version": "/system resource print",
            "DNS": "/ip dns print",
            "DHCP network": "/ip dhcp-server network print detail",
            "WireGuard peer": f"/interface wireguard peers print detail where interface={ros_q(f['wg_interface'])}",
            "WireGuard address": f"/ip address print detail where interface={ros_q(f['wg_interface'])}",
            "VPN route": f"/ip route print detail where routing-table={ros_q(f['route_table'])}",
            "Mangle": "/ip firewall mangle print detail",
            "NAT": "/ip firewall nat print detail",
            "DNS static": '/ip dns static print detail where comment~"VPN-MANAGER:"',
            "VPN address-list": f"/ip firewall address-list print detail where list={ros_q(f['address_list'])}",
            "DNS NAT": '/ip firewall nat print detail where comment~"DNS-REDIRECT"',
            "DNS Filter": '/ip firewall filter print detail where comment~"BLOCK-DOT|BLOCK-DOQ"',
            "Filter": "/ip firewall filter print detail",
            "IPv6 default route": "/ipv6 route print detail where dst-address=::/0",
        }
        raw={}
        for k,c in checks.items():
            try: raw[k]=self.cmd(r,c)
            except Exception as e: raw[k]="ERROR: "+str(e)
        wg=raw["WireGuard peer"]; route=raw["VPN route"]; nat=raw["NAT"]; dns=raw["DNS"]; fil=raw["Filter"]
        dnsnat=raw["DNS NAT"]; dnsfilter=raw["DNS Filter"]
        dnsredir=("UDP" if "protocol=udp" in dnsnat and "dst-port=53" in dnsnat and "action=redirect" in dnsnat else "")
        dnsredir += (" + TCP" if "protocol=tcp" in dnsnat and "dst-port=53" in dnsnat and "action=redirect" in dnsnat else "")
        dotdoq=("TCP/853" if "protocol=tcp" in dnsfilter and "dst-port=853" in dnsfilter and "action=drop" in dnsfilter else "")
        dotdoq += (" + UDP/853" if "protocol=udp" in dnsfilter and "dst-port=853" in dnsfilter and "action=drop" in dnsfilter else "")
        result={
            "Маршрутизатор": raw["Router identity"].replace("name:","").strip() or "ответ получен",
            "RouterOS": re.search(r"version:\s*(\S+)",raw["RouterOS version"]).group(1) if re.search(r"version:\s*(\S+)",raw["RouterOS version"]) else "см. журнал",
            "WireGuard handshake": "есть" if (re.search(r"last-handshake=(\S+)",wg,re.I) and re.search(r"last-handshake=(\S+)",wg,re.I).group(1).lower() != "never") else "не подтверждён",
            "RX": (re.search(r"rx=([^\s]+)",wg,re.I).group(1) if re.search(r"rx=([^\s]+)",wg,re.I) else "—"),
            "TX": (re.search(r"tx=([^\s]+)",wg,re.I).group(1) if re.search(r"tx=([^\s]+)",wg,re.I) else "—"),
            "VPN default route": "найден" if f"gateway={f['wg_interface']}" in route and "dst-address=0.0.0.0/0" in route and "inactive" not in route.lower() else "не найден / проверить",
            "NAT через WG": "найден" if f"out-interface={f['wg_interface']}" in nat and "action=masquerade" in nat else "не найден",
            "DoH": "включён" if "use-doh-server: https://" in dns and "verify-doh-cert: yes" in dns else "не подтверждён",
            "DNS redirect UDP/TCP": dnsredir or "не обнаружен",
            "DoT/DoQ block": dotdoq or "не обнаружена",
            "IPv6 default route": "обнаружен — возможен обход IPv4 policy routing" if "dst-address=::/0" in raw["IPv6 default route"] else "не обнаружен",
            "Mangle managed": "есть" if MANGLE_COMMENT in raw["Mangle"] else "ещё не создан",
            "Remote requests": "включён" if "allow-remote-requests: yes" in dns else "выключен",
        }
        result["DNS security"] = "DoH " + result["DoH"] + " · redirect " + (dnsredir or "нет") + " · DoT/DoQ " + (dotdoq or "нет")
        self.q.put(("DIAG",(result,silent)))
        if not silent:
            for k,v in raw.items(): self.q.put(("DIAGOUT",(k,v,False,False)))
        self.q.put(("LOG","Полный вывод диагностики собран. Основной маршрут main/ZTE не изменялся."))
        try: self.fetch_targets(r)
        except Exception as e: self.q.put(("LOG","Статусы VPN-целей: "+str(e)))
        if run_ping:
            if "найден" not in result["VPN default route"]: raise RuntimeError("Нет активного VPN default route в отдельной таблице")
            wa=raw["WireGuard address"]; m=re.search(r"(\d{1,3}(?:\.\d{1,3}){3})/\d+",wa)
            if not m: raise RuntimeError("Не удалось определить IPv4 интерфейса WireGuard")
            src=m.group(1)
            try:
                self.cmd(r,f'/routing rule remove [find where comment="{TEMP_TEST_COMMENT}"]')
                self.cmd(r,f'/routing rule add src-address={src}/32 action=lookup-only-in-table table={f["route_table"]} comment="{TEMP_TEST_COMMENT}"')
                out=self.cmd(r,f"/tool ping address=1.1.1.1 src-address={src} count=4")
                if not silent: self.q.put(("DIAGOUT",(f"Ping 1.1.1.1 через таблицу {f['route_table']} (src {src})",out,False,True)))
                if "received=0" in out or "packet-loss=100%" in out: raise RuntimeError("Ping через таблицу VPN не прошёл")
            finally:
                self.cmd(r,f'/routing rule remove [find where comment="{TEMP_TEST_COMMENT}"]')

    def refresh_dashboard(self):
        if self.busy or not self.router: return
        def job(): self.diagnostics(self.router_conn(),False,True)
        self.run_job("Обновление dashboard…",job)

    def run_diagnostics(self): self.run_job("Полная диагностика…",lambda:self.diagnostics(self.router_conn(),False))

    def page_logs(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(12)
        p=self.panel("Журнал операций","Все события текущего сеанса: подключение, команды RouterOS, изменения и ошибки.")
        row=QHBoxLayout(); self.log_search=QLineEdit(); self.log_search.setPlaceholderText("Поиск по журналу…"); self.log_search.textChanged.connect(self.filter_log_page)
        export=QPushButton("Экспорт TXT"); export.clicked.connect(self.export_log_page)
        clear=QPushButton("Очистить журнал"); clear.setObjectName("DangerButton"); clear.clicked.connect(self.clear_log_page)
        row.addWidget(self.log_search,1); row.addWidget(export); row.addWidget(clear); p.layout().addLayout(row)
        self.log_view=QPlainTextEdit(); self.log_view.setReadOnly(True); self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap); self.log_view.setPlaceholderText("Здесь появятся события приложения…"); self.log_view.setMinimumHeight(560); p.layout().addWidget(self.log_view,1)
        l.addWidget(p,1); return w

    def filter_log_page(self):
        if not hasattr(self,"log_view"): return
        q=self.log_search.text().lower() if hasattr(self,"log_search") else ""
        self.log_view.setPlainText("\\n".join(x for x in self.log_lines if q in x.lower()))
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def export_log_page(self):
        path,_=QFileDialog.getSaveFileName(self,"Экспорт журнала",str(Path.home()/"mikrotik-vpn-manager.log"),"Log files (*.log *.txt)")
        if path:
            Path(path).write_text("\\n".join(self.log_lines),encoding="utf-8")
            self.log(f"Журнал экспортирован: {path}")

    def clear_log_page(self):
        if QMessageBox.question(self,"Очистить журнал","Удалить все записи текущего сеанса?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        self.log_lines.clear(); self.filter_log_page()
    def test_vpn(self): self.nav.setCurrentRow(2); self.run_job("Тест ping через WireGuard…",lambda:self.diagnostics(self.router_conn(),True))
    def ping_wan(self): self.run_job("Ping 1.1.1.1 из main…",lambda:self.diag_run("Ping WAN (main)","/tool ping address=1.1.1.1 count=4"))
    def traceroute(self):
        command="/tool traceroute address=1.1.1.1 max-hops=12 count=1 timeout=1s use-dns=no"
        self.run_job("Traceroute 1.1.1.1…",lambda:self.diag_run("Traceroute · до 12 узлов, 1 проба",command,25))

    def show_dhcp_clients(self):
        def job():
            r=self.router_conn()
            for title,command in [
                ("DHCP leases","/ip dhcp-server lease print detail"),
                ("ARP clients",f'/ip arp print detail where interface={ros_q(self.settings["lan_interface"])}'),
            ]:
                try: out=self.cmd(r,command)
                except Exception as e: out="ERROR: "+str(e)
                self.q.put(("DIAGOUT",(title+" · "+command,out,False,True)))
        self.run_job("Получение списка LAN-клиентов…",job)

    def diagnose_client(self):
        raw=self.client_input.text().strip()
        try:
            addr=ipaddress.ip_address(raw)
            if addr.version!=4: raise ValueError("Нужен IPv4-адрес телефона.")
            network=ipaddress.ip_network(self.settings["lan_subnet"],strict=False)
            if addr not in network: raise ValueError(f"Адрес {addr} не входит в LAN subnet {network}.")
        except Exception as e:
            QMessageBox.warning(self,"Некорректный IP клиента",str(e)); return
        ip=str(addr)
        def job():
            r=self.router_conn()
            commands=[
                ("DHCP lease",f"/ip dhcp-server lease print detail where address={ip}"),
                ("ARP entry",f"/ip arp print detail where address={ip}"),
                ("Ping телефона с роутера",f"/ping address={ip} count=4"),
                ("Mangle counters",f'/ip firewall mangle print stats detail where comment="{MANGLE_COMMENT}"'),
                ("DNS redirect counters",'/ip firewall nat print stats detail where comment~"DNS-REDIRECT"'),
                ("Client DNS cache",'/ip dns cache print detail where name~"youtube|discord|chatgpt|netflix|google"'),
            ]
            for title,command in commands:
                try: out=self.cmd(r,command)
                except Exception as e: out="ERROR: "+str(e)
                self.q.put(("DIAGOUT",(title+" · "+command,out,False,True)))
        self.run_job(f"Диагностика LAN-клиента {ip}…",job)

    def show_policy_counters(self):
        def job():
            r=self.router_conn()
            commands=[
                ("Mangle counters",f'/ip firewall mangle print stats detail where comment="{MANGLE_COMMENT}"'),
                ("NAT counters",f'/ip firewall nat print stats detail where comment="{NAT_COMMENT}"'),
                ("DNS redirect counters",'/ip firewall nat print stats detail where comment~"DNS-REDIRECT"'),
                ("DNS filter counters",'/ip firewall filter print stats detail where comment~"BLOCK-DOT|BLOCK-DOQ"'),
                ("VPN address-list",f'/ip firewall address-list print detail where list={ros_q(self.settings["address_list"])}'),
            ]
            for title,command in commands:
                try: out=self.cmd(r,command)
                except Exception as e: out="ERROR: "+str(e)
                self.q.put(("DIAGOUT",(title+" · "+command,out,False,True)))
        self.run_job("Сбор счётчиков policy routing и DNS…",job)

    def set_managed_mangle(self,enabled):
        verb="enable" if enabled else "disable"
        warning=("Включить обратно только управляемое правило выборочной VPN-маршрутизации?" if enabled else
                 "Отключить только правило VPN-MANAGER-DOMAIN-ROUTE? Цели из списка перестанут идти через WireGuard и пойдут по основному маршруту через ZTE. Остальные правила не затрагиваются.")
        if QMessageBox.question(self,"Подтверждение",warning,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        def job():
            r=self.router_conn()
            count=r.exec(f'/ip firewall mangle print count-only where comment="{MANGLE_COMMENT}"').strip()
            if count!="1":
                found=count or "неизвестно"
                raise RuntimeError(f"Ожидалось ровно одно управляемое правило Mangle, найдено: {found}. Ничего не меняю.")
            self.cmd(r,f'/ip firewall mangle {verb} [find where comment="{MANGLE_COMMENT}"]')
            self.cmd(r,f'/ip firewall mangle print stats detail where comment="{MANGLE_COMMENT}"')
            self.fetch_mangle_status(r)
            self.q.put(("DIAGOUT",("Состояние управляемого Mangle-правила", "Команда переключения выполнена; фактический статус перечитан с роутера.",False,True)))
        self.run_job(("Включение" if enabled else "Временное отключение")+" управляемого Mangle-правила…",job)

    def import_targets_file(self):
        path,_=QFileDialog.getOpenFileName(self,"Импорт целей","", "Списки целей (*.txt *.csv);;Все файлы (*.*)")
        if not path: return
        added=skipped=0; errors=[]
        try:
            raw=Path(path).read_text(encoding="utf-8-sig")
            if path.lower().endswith(".csv"):
                values=[row[0].strip() for row in csv.reader(raw.splitlines(),delimiter=";") if row and row[0].strip()]
                if values and values[0].lower() in ("target","цель","domain","ip"): values=values[1:]
            else:
                values=[line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            existing={x[0] for x in self.targets}
            for value in values:
                try: target,kind=normalize_target(value)
                except Exception as exc: skipped+=1; errors.append(f"{value}: {exc}"); continue
                if target in existing: skipped+=1; continue
                self.targets.append((target,kind)); existing.add(target); added+=1
            self.render_targets()
            self.log(f"Импорт завершён: добавлено {added}, пропущено {skipped}.")
            if errors: QMessageBox.warning(self,"Импорт завершён",f"Добавлено: {added}\nПропущено: {skipped}\n\nПервые ошибки:\n"+"\n".join(errors[:12]))
            else: QMessageBox.information(self,"Импорт завершён",f"Добавлено: {added}\nПропущено (дубликаты): {skipped}")
        except Exception as exc:
            QMessageBox.critical(self,"Ошибка импорта",str(exc))

    def export_targets_file(self):
        path,_=QFileDialog.getSaveFileName(self,"Экспорт списка целей","vpn-targets.csv","CSV (*.csv)")
        if not path: return
        try:
            with open(path,"w",newline="",encoding="utf-8-sig") as stream:
                writer=csv.writer(stream,delimiter=";")
                writer.writerow(["Цель","Тип"])
                writer.writerows(self.targets)
            self.log(f"Экспортировано целей: {len(self.targets)} → {path}")
            QMessageBox.information(self,"Экспорт готов",f"Сохранено целей: {len(self.targets)}\n{path}")
        except Exception as exc:
            QMessageBox.critical(self,"Ошибка экспорта",str(exc))

    def load_targets(self):
        self.targets=[]; self.render_targets()
    def add_target(self):
        try: t,k=normalize_target(self.target_input.text())
        except Exception as e: QMessageBox.warning(self,"Некорректная цель",str(e)); return
        if not any(x[0]==t for x in self.targets): self.targets.append((t,k)); self.render_targets()
        self.target_input.clear()
    def load_all_presets(self):
        n=0
        for items in PRESETS.values():
            for raw in items:
                try: t,k=normalize_target(raw)
                except Exception: continue
                if not any(x[0]==t for x in self.targets): self.targets.append((t,k)); n+=1
        self.render_targets(); self.log(f"Все профили ({len(PRESETS)}): добавлено {n} целей, дубликаты пропущены")

    def load_preset(self):
        name=self.preset.currentText(); n=0
        for raw in PRESETS[name]:
            try: t,k=normalize_target(raw)
            except: continue
            if not any(x[0]==t for x in self.targets): self.targets.append((t,k)); n+=1
        self.render_targets(); self.log(f"Профиль {name}: добавлено {n} целей")
    def render_targets(self):
        if not hasattr(self,"target_table"): return
        found=self.router_state["found"] if self.router_state else {}
        local={t for t,_ in self.targets}
        rows=[(t,k,True) for t,k in self.targets]+[(t,f[0],False) for t,f in sorted(found.items()) if t not in local]
        self.target_table.setRowCount(0)
        for t,k,is_local in rows:
            f=found.get(t)
            if self.router_state is None:
                remote="Не проверено"; remote_tone="muted"; detail="Нет свежих данных от MikroTik"; target_state="Ожидает проверки"; state_tone="muted"
            elif f is None:
                remote="Не найдена"; remote_tone="warn"; detail="Управляемая запись не обнаружена на роутере"; target_state="Только в приложении"; state_tone="warn"
            elif f[2]:
                remote="Ошибка invalid"; remote_tone="bad"; detail=f[3]; target_state="Ошибка конфигурации"; state_tone="bad"
            elif f[1]:
                remote="Отключена"; remote_tone="warn"; detail=f[3]; target_state="Отключена на роутере"; state_tone="warn"
            else:
                remote="Найдена"; remote_tone="ok"; detail=f[3]; target_state,state_tone=self.status_for(t,is_local)
            local_label="В локальном списке" if is_local else "Только на роутере"
            source="DNS FWD" if k=="Домен" else "address-list"
            values=(t,k,source,local_label,remote,target_state,detail)
            i=self.target_table.rowCount(); self.target_table.insertRow(i)
            for j,val in enumerate(values):
                item=QTableWidgetItem(val); item.setData(Qt.ItemDataRole.UserRole,t)
                if j==4:
                    item.setForeground(QBrush(QColor(TONES[remote_tone]))); ft=item.font(); ft.setBold(True); item.setFont(ft)
                elif j==5:
                    item.setForeground(QBrush(QColor(TONES[state_tone]))); ft=item.font(); ft.setBold(True); item.setFont(ft)
                self.target_table.setItem(i,j,item)
        self.filter_targets(self.target_search.text() if hasattr(self,"target_search") else "")
        if hasattr(self,"active_table"): self.render_active()

    def filter_targets(self,text):
        if not hasattr(self,"target_table"): return
        for i in range(self.target_table.rowCount()): self.target_table.setRowHidden(i,text.lower() not in self.target_table.item(i,0).text().lower())
    def selected_targets(self):
        rows=sorted({x.row() for x in self.target_table.selectionModel().selectedRows()})
        return [(self.target_table.item(i,0).data(Qt.ItemDataRole.UserRole),self.target_table.item(i,1).text()) for i in rows]
    def remove_local(self):
        selected=self.selected_targets()
        self.targets=[x for x in self.targets if x not in selected]; self.render_targets()
    def plan_text(self):
        """Точные команды RouterOS в том виде, в каком они уйдут на роутер."""
        f=self.fields(); found=self.router_state["found"] if self.router_state else None
        L=["# ═══ 1. ПРОВЕРКИ — только чтение, ничего не меняют ═══"]
        L+=["/ip dns print","/ip dhcp-server network print detail",f'/ip route print detail where routing-table={ros_q(f["route_table"])}',"/ip firewall filter print detail","/ip firewall mangle print detail","/ip firewall nat print detail"]
        L+=["# Применение остановится, если: allow-remote-requests выключен; DHCP не раздаёт LAN DNS;",f'# нет активного default route в таблице {f["route_table"]} через {f["wg_interface"]}; найден FastTrack или чужие mark-routing правила.',""]
        L+=["# ═══ 2. ИЗМЕНЕНИЯ — выполняются только при успешных проверках ═══","# Маркировка трафика к целям (добавляется, если правила с меткой ещё нет)",mangle_cmd(f),"","# NAT masquerade через WireGuard (добавляется, если подходящего правила ещё нет)",nat_cmd(f),""]
        new=skip=0
        L.append(f"# Цели ({len(self.targets)}): перед каждой записью проверяется, что дубликата нет")
        for t,k in self.targets:
            cmd=target_cmd(f,t,k)
            if found is not None and t in found: L.append("# уже на роутере, будет пропущено: "+cmd); skip+=1
            else: L.append(cmd); new+=1
        L+=["","# ═══ 3. ЗАВЕРШЕНИЕ ═══","/ip dns cache flush"]
        return "\n".join(L),new,skip

    def preview_apply(self):
        if not self.targets: QMessageBox.information(self,"Список пуст","Добавь цели для маршрутизации."); return
        text,new,skip=self.plan_text()
        dlg=QDialog(self); dlg.setWindowTitle("Предпросмотр изменений"); dlg.resize(1000,720)
        lay=QVBoxLayout(dlg); lay.setContentsMargins(26,24,26,22); lay.setSpacing(12)
        title=QLabel("Предпросмотр изменений"); title.setObjectName("SectionTitle")
        sub=QLabel("Ниже — точные команды RouterOS, которые приложение отправит по SSH. Основной маршрут через ZTE не меняется."); sub.setObjectName("Muted"); sub.setWordWrap(True)
        chip=QLabel(f"●  Новых записей: {new}      ·      будет пропущено: {skip}      ·      всего целей: {len(self.targets)}"); chip.setObjectName("InfoNote")
        view=QPlainTextEdit(); view.setReadOnly(True); view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap); view.setPlainText(text); dlg._hl=RouterOSHighlighter(view.document())
        for w in (title,sub,chip): lay.addWidget(w)
        lay.addWidget(view,1)
        row=QHBoxLayout(); row.setSpacing(10)
        cp=QPushButton("Копировать команды"); cp.setObjectName("QuietButton"); cp.clicked.connect(lambda:QApplication.clipboard().setText(text))
        cancel=QPushButton("Отмена"); cancel.clicked.connect(dlg.reject)
        ok=QPushButton("Применить на роутер  →"); ok.setObjectName("PrimaryButton"); ok.clicked.connect(dlg.accept)
        row.addWidget(cp); row.addStretch(); row.addWidget(cancel); row.addWidget(ok); lay.addLayout(row)
        fit_controls(dlg,42)
        if dlg.exec()==QDialog.DialogCode.Accepted: self.apply_all()

    def prepare_router(self,r):
        f=self.settings; table,wg,lan,sub,alist=f["route_table"],f["wg_interface"],f["lan_interface"],f["lan_subnet"],f["address_list"]
        for name,val in (("routing table",table),("address-list",alist),("interface",wg),("LAN interface",lan)):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}",val): raise ValueError(f"Некорректное имя: {name}")
        net=ipaddress.ip_network(sub,strict=False)
        if net.version!=4: raise ValueError("LAN subnet должна быть IPv4")
        dns=r.exec("/ip dns print")
        if "allow-remote-requests: yes" not in dns: raise RuntimeError("На роутере выключен allow-remote-requests. Автоматически не включаю.")
        try: ipaddress.ip_address(f["lan_dns"])
        except ValueError as e: raise ValueError("LAN DNS IP должен быть корректным IP-адресом") from e
        dhcp=r.exec("/ip dhcp-server network print detail")
        if f"dns-server={f['lan_dns']}" not in dhcp.replace(" ", ""):
            raise RuntimeError(f"DHCP network не подтверждает dns-server={f['lan_dns']}. Сначала проверь DNS, выдаваемый LAN-клиентам.")
        route=r.exec(f"/ip route print detail where routing-table={ros_q(table)}")
        if f"gateway={wg}" not in route or "dst-address=0.0.0.0/0" not in route or "inactive" in route.lower(): raise RuntimeError(f"Не найден активный default route {table} через {wg}. Маршруты автоматически не создаю.")
        filters=r.exec("/ip firewall filter print detail")
        if "action=fasttrack-connection" in filters.lower(): raise RuntimeError("Обнаружен FastTrack. Нужна ручная проверка исключений перед настройкой mangle.")
        mangle=r.exec("/ip firewall mangle print detail")
        if "action=mark-routing" in mangle and MANGLE_COMMENT not in mangle: raise RuntimeError("Есть сторонние mark-routing правила. Автоматическое изменение отменено.")
        if MANGLE_COMMENT not in mangle:
            self.cmd(r,mangle_cmd(f))
        nat=r.exec("/ip firewall nat print detail")
        if not (f"out-interface={wg}" in nat and "action=masquerade" in nat and f"src-address={sub}" in nat):
            self.cmd(r,nat_cmd(f))

    def apply_target(self,r,t,k):
        alist=self.settings["address_list"]
        if k=="Домен":
            comment=f"VPN-MANAGER:{t}"
            if r.exec(f'/ip dns static print count-only where comment={ros_q(comment)}').strip().isdigit() and int(r.exec(f'/ip dns static print count-only where comment={ros_q(comment)}').strip())>0: return
            old=r.exec(f'/ip dns static print detail where name={ros_q(t)}')
            if old: raise RuntimeError(f"Уже существует DNS static запись для {t}; не перезаписываю её автоматически:\n{old}")
            self.cmd(r,target_cmd(self.settings,t,k))
        else:
            comment=f"VPN-MANAGER-CIDR:{t}"
            count=r.exec(f'/ip firewall address-list print count-only where comment={ros_q(comment)}').strip()
            if count.isdigit() and int(count)>0: return
            self.cmd(r,target_cmd(self.settings,t,k))

    def apply_all(self):
        if not self.targets: return
        if QMessageBox.question(self,"Применить изменения",f"Применить {len(self.targets)} целей? Будут созданы только управляемые правила. Основной default route и существующие правила не удаляются.",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        targets=list(self.targets)
        def job():
            r=self.router_conn(); self.prepare_router(r)
            for t,k in targets: self.apply_target(r,t,k)
            self.cmd(r,"/ip dns cache flush"); self.fetch_targets(r); self.q.put(("LOG","Цели применены. DNS FWD начнёт наполнять address-list после DNS-запросов клиентов LAN."))
        self.run_job("Применение целей с предварительными проверками…",job)

    def remove_remote(self):
        selected=self.selected_targets()
        if not selected: QMessageBox.information(self,"Не выбрано","Выбери строки в таблице."); return
        if QMessageBox.question(self,"Удалить записи", "Удалить только объекты с метками VPN-MANAGER?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
        def job():
            r=self.router_conn(); alist=self.settings["address_list"]
            for t,k in selected:
                c=f"VPN-MANAGER:{t}" if k=="Домен" else f"VPN-MANAGER-CIDR:{t}"
                path="/ip dns static" if k=="Домен" else "/ip firewall address-list"
                self.cmd(r,f'{path} remove [find where comment={ros_q(c)}]')
            self.cmd(r,"/ip dns cache flush"); self.fetch_targets(r)
        self.run_job("Удаление выбранных управляемых объектов…",job)

    def refresh_address_list(self):
        def job():
            r=self.router_conn()
            self.fetch_targets(r)
            self.fetch_mangle_status(r)
        self.run_job("Обновление статусов целей и VPN-маршрутизации…",job)
    def read_command(self,command,target):
        self.run_job("Чтение конфигурации…",lambda:self.q.put(("TEXT",(target,self.router_conn().exec(command)))))
    def refresh_firewall(self):
        commands=["/ip firewall nat print detail","/ip firewall filter print detail","/ip firewall mangle print detail","/ip dns print","/ip dns static print detail",f"/ip firewall address-list print detail where list={ros_q(self.settings['address_list'])}"]
        def job():
            r=self.router_conn(); parts=[]
            for c in commands: parts.append("$ "+c+"\n"+r.exec(c))
            self.q.put(("TEXT",(self.firewall_text,"\n\n".join(parts))))
        self.run_job("Сбор Firewall/DNS…",job)

    def choose_key(self,e):
        p,_=QFileDialog.getOpenFileName(self,"Выбрать приватный SSH-ключ",str(Path.home()),"All files (*.*)")
        if p:e.setText(p)
    def choose_backup_dir(self):
        p=QFileDialog.getExistingDirectory(self,"Папка резервных копий",self.backup_dir.text())
        if p:self.backup_dir.setText(p)
    def backup_router(self):
        dest=Path(self.backup_dir.text()).expanduser()
        stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        def job():
            r=self.router_conn(); dest.mkdir(parents=True,exist_ok=True)
            base=f"vpn-manager-{stamp}"; self.cmd(r,f"/system backup save name={base}"); self.cmd(r,f"/export file={base}")
            sftp=r.client.open_sftp(); saved=[]
            try:
                for ext in ("backup","rsc"):
                    remote=f"{base}.{ext}"; local=dest/remote
                    sftp.get(remote,str(local)); saved.append(str(local))
            finally:sftp.close()
            self.q.put(("BACKUP","Сохранено:\n"+"\n".join(saved)))
        self.run_job("Создание backup/export на MikroTik и скачивание по SFTP…",job)

    def closeEvent(self,event):
        try:
            if self.router:self.router.close()
        finally:event.accept()

STYLE="""
/* ---------- base: фон рисует Backdrop, остальные виджеты и подписи прозрачные ---------- */
QMainWindow,QDialog,QMessageBox{background:#05070d}
QFrame#WindowTitleBar{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0b1425,stop:1 #101c32);border-bottom:1px solid rgba(130,170,230,55)}
QLabel#ChromeBrand{color:#8fa8cc;font-size:9pt;font-weight:800;letter-spacing:1px}
QPushButton#ChromeButton,QPushButton#ChromeClose{background:transparent;border:0;border-radius:7px;color:#a9bbd5;font-size:13pt;padding:0}
QPushButton#ChromeButton:hover{background:rgba(255,255,255,24);color:#ffffff}
QPushButton#ChromeClose:hover{background:#d83d55;color:#ffffff}
QWidget{color:#e8edf6;font-family:'Segoe UI Variable Text','Segoe UI';font-size:10pt}
QLabel{background:transparent;border:0}
QScrollArea#PageScroll{background:transparent;border:0}

/* ---------- sidebar (glass) ---------- */
QFrame#Sidebar{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(9,14,25,225),stop:1 rgba(5,8,14,242));border-right:1px solid rgba(255,255,255,22)}
QLabel#Brand{font-size:18pt;font-weight:800;color:#ffffff}QLabel#BrandSub{color:#6a80a6;font-size:8pt;font-weight:700}
QLabel#SidebarFoot{color:#62779a;font-size:8pt;padding:14px 2px 2px 2px;border-top:1px solid rgba(255,255,255,20)}
QListWidget#Nav{background:transparent;border:0;outline:0;color:#8aa0c0;padding-top:2px}
QListWidget#Nav::item{padding:13px 14px;border-radius:11px;margin:3px 0;font-size:10pt;font-weight:600;border:1px solid transparent}
QListWidget#Nav::item:hover:!selected{background:rgba(255,255,255,14);color:#e4edfb;border:1px solid rgba(255,255,255,18)}
QListWidget#Nav::item:selected{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(70,120,235,150),stop:1 rgba(50,90,190,70));color:#ffffff;border:1px solid rgba(130,175,255,140)}

/* ---------- typography ---------- */
QLabel#PageTitle{font-size:24pt;font-weight:700;color:#ffffff}
QLabel#Muted{color:#8499b8;font-size:9pt}
QLabel#Eyebrow{color:#7db0ff;font-size:8pt;font-weight:800}
QLabel#HeroTitle{font-size:22pt;font-weight:700;color:#ffffff;padding:2px 0}
QLabel#HeroText{color:#b0c0d8;font-size:10pt}
QLabel#CardTitle{color:#8a9fbf;font-size:8pt;font-weight:800}
QLabel#CardValue{color:#ffffff;font-size:20pt;font-weight:700;padding:4px 0 2px 0}
QLabel#SectionTitle{font-size:13pt;font-weight:700;color:#f3f7ff}

/* ---------- badges / status (glass) ---------- */
QLabel#BadgeOff{color:#ffb7b7;background:rgba(244,63,94,45);border:1px solid rgba(251,113,133,130);padding:10px 16px;border-radius:11px;font-size:8pt;font-weight:800}
QLabel#BadgeOn{color:#86f3c4;background:rgba(16,185,129,45);border:1px solid rgba(52,211,153,130);padding:10px 16px;border-radius:11px;font-size:8pt;font-weight:800}
QLabel#StatusBar{color:#9db0cc;background:rgba(255,255,255,9);border:1px solid rgba(255,255,255,26);border-radius:11px;padding:11px 14px;font-size:9pt}
QLabel#InfoNote{background:rgba(59,130,246,32);color:#b6d0fb;border:1px solid rgba(96,165,250,90);border-radius:13px;padding:14px 16px}

/* ---------- glass surfaces ---------- */
QFrame#Hero{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(48,90,190,105),stop:.55 rgba(20,36,78,165),stop:1 rgba(28,48,100,130));border:1px solid rgba(140,180,255,60);border-radius:20px}
QFrame#Panel{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(30,44,72,140),stop:1 rgba(9,15,27,208));border:1px solid rgba(255,255,255,26);border-radius:18px}
QFrame#Card{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(32,48,80,145),stop:1 rgba(10,17,30,208));border:1px solid rgba(255,255,255,26);border-top:3px solid #4d86ff;border-radius:16px}
QFrame#Card[metric="router"]{border-top-color:#4d86ff}
QFrame#Card[metric="wg"]{border-top-color:#2dd4bf}
QFrame#Card[metric="rx"]{border-top-color:#38bdf8}
QFrame#Card[metric="tx"]{border-top-color:#fbbf24}
QFrame#Card[metric="vpnroute"]{border-top-color:#7c93ff}
QFrame#Card[metric="dns"]{border-top-color:#a78bfa}

/* ---------- inputs ---------- */
QLineEdit,QComboBox,QSpinBox{background:rgba(3,6,12,195);border:1px solid rgba(255,255,255,34);border-radius:11px;padding:0 12px;min-height:22px;color:#eaf0fa;selection-background-color:#2a5fc4}
QLineEdit:hover,QComboBox:hover,QSpinBox:hover{border-color:rgba(140,180,255,110)}
QLineEdit:focus,QComboBox:focus,QSpinBox:focus{border:1px solid #6aa0ff;background:rgba(8,15,28,215)}
QComboBox{padding-right:38px}
QComboBox::drop-down{subcontrol-origin:padding;subcontrol-position:center right;width:34px;background:transparent;border:0}
QComboBox::down-arrow{image:url(ARROW_URL);width:14px;height:9px}
QComboBox::down-arrow:on{top:1px}
QComboBox QAbstractItemView{background:#0a111e;color:#e8edf6;border:1px solid #2b4163;outline:0;padding:4px;selection-background-color:#22427f;selection-color:#ffffff}
QPlainTextEdit,QTextEdit,QTableWidget{background:#060a14;border:1px solid rgba(255,255,255,22);border-radius:13px;color:#d8e3f3;gridline-color:#192840;alternate-background-color:rgba(255,255,255,5);selection-background-color:#22427f;selection-color:#ffffff}
QPlainTextEdit{padding:12px;font-family:'Cascadia Mono','Cascadia Code','Consolas',monospace;font-size:9pt}
QTextEdit#DiagView{padding:12px;font-family:'Cascadia Mono','Cascadia Code','Consolas',monospace;font-size:9pt}
QHeaderView::section{background:#0b1424;color:#9ab0d0;border:0;border-bottom:1px solid #243752;padding:12px;font-size:8pt;font-weight:800}
QTableCornerButton::section{background:#0b1424;border:0}
QTableWidget::item{padding:8px;border-bottom:1px solid #15243a}

/* ---------- buttons (glass) ---------- */
QPushButton{background:rgba(255,255,255,11);color:#e9f0fc;border:1px solid rgba(255,255,255,34);border-radius:11px;padding:0 18px;min-height:22px;font-weight:600}
QPushButton:hover{background:rgba(255,255,255,28);border-color:rgba(160,195,255,120)}
QPushButton:pressed{background:rgba(255,255,255,8)}
QPushButton:disabled{color:#5c6f8b;background:rgba(255,255,255,6);border-color:rgba(255,255,255,14)}
QPushButton#PrimaryButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #4a8bff,stop:1 #2b62e8);border:1px solid rgba(170,205,255,170);color:#ffffff;font-weight:700}
QPushButton#PrimaryButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #6ba2ff,stop:1 #3d77f2);border-color:#a9cbff}
QPushButton#PrimaryButton:pressed{background:#2358c8}
QPushButton#QuietButton{background:rgba(255,255,255,9);color:#bfd0e8}
QPushButton#HeroSecondary{background:rgba(255,255,255,20);border-color:rgba(190,215,255,90);color:#e4eefe}
QPushButton#HeroSecondary:hover{background:rgba(255,255,255,34)}
QPushButton#ActionButton{text-align:left;padding:0 16px;background:rgba(255,255,255,12)}
QPushButton#ActionButton:hover{background:rgba(255,255,255,26)}
QPushButton#DangerButton{background:rgba(244,63,94,40);border-color:rgba(251,113,133,120);color:#ffd9df}
QPushButton#DangerButton:hover{background:rgba(244,63,94,70)}

/* ---------- divider / stats / indicators ---------- */
QFrame#Divider{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(90,140,255,0),stop:.2 rgba(90,140,255,150),stop:.8 rgba(45,212,191,120),stop:1 rgba(45,212,191,0));border:0}
QLabel#StatValue{font-size:14pt;font-weight:700;color:#ffffff;padding-top:2px}
QLabel#IndTitle{color:#cfdbef;font-size:10pt}
QLabel#IndValue{color:#9fb3d1;font-weight:600}
QFrame#Sep{background:rgba(255,255,255,18);border:0}

/* ---------- scrollbars ---------- */
QScrollBar:vertical{background:transparent;width:10px;margin:2px}
QScrollBar::handle:vertical{background:rgba(255,255,255,45);min-height:28px;border-radius:5px}
QScrollBar::handle:vertical:hover{background:rgba(255,255,255,80)}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:transparent}
QScrollBar:horizontal{background:transparent;height:10px;margin:2px}
QScrollBar::handle:horizontal{background:rgba(255,255,255,45);min-width:28px;border-radius:5px}
QScrollBar::handle:horizontal:hover{background:rgba(255,255,255,80)}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0}
QToolTip{background:#142238;color:#edf4ff;border:1px solid #3b5575;padding:6px}
"""



if __name__=="__main__":
    app=QApplication(sys.argv); app.setApplicationName(APP_NAME)
    _arrow = make_arrow_icon()
    STYLE = STYLE.replace("image:url(ARROW_URL);", f'image:url("{_arrow}");' if _arrow else "image:none;")
    win=App(); win.show()
    if paramiko is None: QMessageBox.critical(win,"Нет Paramiko","Запусти start.bat — он создаст venv и установит зависимости.")
    sys.exit(app.exec())