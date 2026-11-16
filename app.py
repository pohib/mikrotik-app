from __future__ import annotations
import sys, os, json, re, ipaddress, base64, hashlib, queue, threading, time, math, csv, socket, urllib.request, urllib.parse
from collections import deque
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, Callable

try:
    import paramiko
except ImportError:
    paramiko = None

from PySide6.QtCore import Qt, QEvent, QTimer, Signal, QObject, QPointF, QRectF, QPropertyAnimation, QEasingCurve, QPoint, QSize, QStringListModel
from html import escape as esc
from PySide6.QtGui import QFont, QAction, QTextCursor, QPainter, QColor, QLinearGradient, QRadialGradient, QPainterPath, QPen, QBrush, QPixmap, QSyntaxHighlighter, QTextCharFormat, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QLineEdit, QCompleter, QInputDialog,
    QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox as QtMessageBox,
    QFileDialog as QtFileDialog, QPlainTextEdit, QComboBox, QSplitter, QDialog, QDialogButtonBox,
    QFormLayout, QCheckBox, QGroupBox, QAbstractItemView, QTabWidget, QTreeWidget, QTreeWidgetItem, QToolButton, QSpinBox, QScrollArea, QSizePolicy, QTextEdit, QGraphicsDropShadowEffect, QSizeGrip, QProgressBar
)

APP_NAME = "MikroTik VPN Manager"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "MikroTikVPNManager"
CONFIG_FILE = APP_DIR / "settings.json"
KNOWN_HOSTS_FILE = APP_DIR / "known_hosts"
MANGLE_COMMENT = "VPN-MANAGER-DOMAIN-ROUTE"
NAT_COMMENT = "VPN-MANAGER-NAT"
TEMP_TEST_COMMENT = "VPN-MANAGER-TEMP-TEST"
ADDRESS_LIST_DEFAULT = "vpn_domains"

# DoH endpoints explicitly listed as compatible with RouterOS by MikroTik.
# Bootstrap DNS is used only to resolve the DoH hostname before HTTPS connects.
DOH_PRESETS = {
    "Google Public DNS": ("https://dns.google/dns-query", "8.8.8.8, 8.8.4.4"),
    "Cloudflare · стандартный": ("https://cloudflare-dns.com/dns-query", "1.1.1.1, 1.0.0.1"),
    "Cloudflare · блокировка вредоносных сайтов": ("https://security.cloudflare-dns.com/dns-query", "1.1.1.2, 1.0.0.2"),
    "Cloudflare · семейный фильтр": ("https://family.cloudflare-dns.com/dns-query", "1.1.1.3, 1.0.0.3"),
    "OpenDNS": ("https://doh.opendns.com/dns-query", "208.67.222.222, 208.67.220.220"),
    "OpenDNS · FamilyShield": ("https://doh.familyshield.opendns.com/dns-query", "208.67.222.123, 208.67.220.123"),
}

PRESETS = {
    "YouTube": ["youtube.com", "youtube-nocookie.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"],
    "ChatGPT / OpenAI": ["chatgpt.com", "chat.openai.com", "openai.com", "auth.openai.com", "api.openai.com", "platform.openai.com", "oaistatic.com", "oaiusercontent.com"],
    "Claude": ["claude.ai", "anthropic.com", "claudeusercontent.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telegra.ph", "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24"],
    "Netflix": ["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxso.net", "nflxext.com"],
    "Cloudflare services": ["cloudflare.com", "cloudflare-dns.com", "one.one.one.one"],
    "Instagram": ["instagram.com", "i.instagram.com", "graph.instagram.com", "cdninstagram.com", "fbcdn.net", "instagram.fna.fbcdn.net"],
    "TikTok": ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "byteoversea.com", "ibytedtos.com", "ipstatp.com", "byteimg.com", "muscdn.com"],
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
    def __init__(self, host, port, username, auth_method, key_file, passphrase, password, ui_queue):
        if paramiko is None:
            raise RuntimeError("Paramiko не установлен. Запусти start.bat.")
        self.host, self.port, self.username = host, port, username
        self.auth_method = auth_method or "key"
        self.key_file, self.passphrase, self.password, self.ui_queue = key_file, passphrase or None, password or None, ui_queue
        self.client = None
        self.lock = threading.Lock()

    def connect(self):
        if not self.host:
            raise RuntimeError("Укажи адрес MikroTik")
        if self.auth_method == "key":
            if not self.key_file or not Path(self.key_file).is_file():
                raise RuntimeError("Укажи существующий приватный SSH-ключ")
        elif self.auth_method == "password":
            if not self.password:
                raise RuntimeError("Укажи пароль пользователя MikroTik")
        else:
            raise RuntimeError("Неизвестный способ SSH-аутентификации")

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
            auth = {
                "hostname": self.host, "port": self.port, "username": self.username,
                "look_for_keys": False, "allow_agent": False,
                "timeout": 12, "banner_timeout": 12, "auth_timeout": 15
            }
            if self.auth_method == "password":
                auth["password"] = self.password
            else:
                auth["key_filename"] = self.key_file
                auth["passphrase"] = self.passphrase
            client.connect(**auth)
            key = client.get_transport().get_remote_server_key()
            if not known:
                client.save_host_keys(str(KNOWN_HOSTS_FILE))
        except Exception:
            client.close()
            raise
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

    def _exec_raw(self, command, timeout=30):
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
        if any(x in combined.lower() for x in ("failure:", "syntax error", "expected end of command", "bad command name", "bad parameter")):
            raise RuntimeError(f"RouterOS отклонил команду:\n{command}\n{combined}")
        if status not in (0, -1):
            raise RuntimeError(f"SSH exit status {status}: {combined}")
        return combined

    def exec(self, command, timeout=30):
        # Централизованный журнал: фиксируем все SSH-команды, включая фоновые опросы.
        safe_command = re.sub(r'(?i)((?:private|preshared)-key\s*=\s*)("[^"]*"|\S+)', r'\1[СКРЫТО]', command)
        self.ui_queue.put(("LOG", f"SSH → $ {safe_command}"))
        try:
            output = self._exec_raw(command, timeout)
        except Exception as exc:
            safe_error = re.sub(r'(?i)((?:private|preshared)-key\s*=\s*)("[^"]*"|\S+)', r'\1[СКРЫТО]', str(exc))
            self.ui_queue.put(("LOG", f"SSH ✕ {safe_command}\nОШИБКА: {safe_error}"))
            raise
        safe_output = re.sub(r'(?im)((?:private|preshared)-key\s*[:=]\s*)("[^"]*"|\S+)', r'\1[СКРЫТО]', output)
        self.ui_queue.put(("LOG", f"SSH ✓ {safe_command}\n{safe_output or '(пустой вывод)'}"))
        return output


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


def make_ui_icons():
    """Создаёт PNG-иконки интерфейса, не зависящие от системного шрифта и темы Qt."""
    paths = {}
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        for name, points in {
            "tree_collapsed": ((6, 3), (13, 9), (6, 15)),
            "tree_expanded": ((3, 6), (9, 13), (15, 6)),
        }.items():
            pm = QPixmap(20, 20)
            pm.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pm)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            pen = QPen(QColor("#a9c5ee"), 2.2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.drawPolyline([QPointF(*point) for point in points])
            painter.end()
            path = APP_DIR / f"{name}.png"
            if pm.save(str(path), "PNG"):
                paths[name] = str(path).replace("\\", "/")
        pm = QPixmap(20, 20)
        pm.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#e4edf9"), 2.0)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawLine(QPointF(5, 5), QPointF(15, 15))
        painter.drawLine(QPointF(15, 5), QPointF(5, 15))
        painter.end()
        path = APP_DIR / "dialog_close.png"
        if pm.save(str(path), "PNG"):
            paths["close"] = str(path).replace("\\", "/")
    except Exception:
        pass
    return paths


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


class DialogTitleBar(QFrame):
    """Компактная перетаскиваемая шапка для внутренних окон приложения."""
    def __init__(self, dialog, title):
        super().__init__(dialog)
        self.dialog = dialog
        self._drag_pos = None
        self.setObjectName("DialogTitleBar")
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 10, 10, 10)
        row.setSpacing(10)
        brand = QLabel("◈")
        brand.setObjectName("DialogBrand")
        row.addWidget(brand)
        heading = QLabel(title)
        heading.setObjectName("DialogHeading")
        row.addWidget(heading, 1)
        # QLabel дочерние элементы перехватывают мышь и не передают её QFrame.
        # Устанавливаем фильтр, чтобы перетаскивание работало при захвате за любой участок заголовка.
        self._drag_widgets = [self, brand, heading]
        for widget in self._drag_widgets:
            widget.installEventFilter(self)
            widget.setCursor(Qt.CursorShape.SizeAllCursor)
        close = QPushButton()
        close.setObjectName("DialogClose")
        close.setFixedSize(30, 30)
        close.setToolTip("Закрыть окно")
        close_icon = getattr(dialog, "_ui_icons", {}).get("close")
        if close_icon:
            close.setIcon(QIcon(close_icon))
            close.setIconSize(QSize(14, 14))
        else:
            close.setText("X")
        close.clicked.connect(dialog.reject)
        row.addWidget(close)

    def _begin_drag(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self.dialog.isMaximized():
            self._drag_pos = event.globalPosition().toPoint() - self.dialog.frameGeometry().topLeft()
            return True
        return False

    def eventFilter(self, watched, event):
        if watched in self._drag_widgets:
            if event.type() == QEvent.Type.MouseButtonPress and self._begin_drag(event):
                return True
            if event.type() == QEvent.Type.MouseMove and self._drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
                self.dialog.move(event.globalPosition().toPoint() - self._drag_pos)
                return True
            if event.type() == QEvent.Type.MouseButtonRelease:
                self._drag_pos = None
        return super().eventFilter(watched, event)

    def mousePressEvent(self, event):
        if self._begin_drag(event):
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.dialog.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None


def add_dialog_chrome(dialog, layout, title):
    dialog.setWindowTitle(title)
    # Сохраняем фирменное безрамочное окно без системной Windows-обёртки.
    # Масштабирование выполняется за компактный QSizeGrip в правом нижнем углу.
    dialog.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
    dialog.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
    dialog.setMinimumSize(560, 380)
    dialog.setObjectName("AppDialog")
    dialog._ui_icons = getattr(dialog.parent(), "_ui_icons", {}) if dialog.parent() is not None else {}
    dialog.setStyleSheet(STYLE + """
        QDialog#AppDialog { background:#080f1d; color:#e8effb; border:1px solid #315078; }
        QDialog#AppDialog QLabel { color:#e8effb; }
        QDialog#AppDialog QLabel#Muted { color:#91a6c6; }
        QFrame#DialogTitleBar { background:#0d192b; border:1px solid #243b5b; border-radius:11px; }
        QLabel#DialogBrand { background:#2864c8; color:#fff; border-radius:8px; min-width:28px; max-width:28px; min-height:28px; max-height:28px; qproperty-alignment:AlignCenter; font-weight:800; }
        QLabel#DialogHeading { color:#f3f7ff; font-size:10pt; font-weight:750; }
        QPushButton#DialogClose { background:#17263b; border:1px solid #304663; color:#dce8fa; border-radius:8px; padding:0; }
        QPushButton#DialogClose:hover { background:#8f3548; border-color:#c65d70; }
        QPushButton#DialogClose:pressed { background:#6e293a; }
    """)
    header=DialogTitleBar(dialog,title)
    if isinstance(layout,QGridLayout):
        old_items=[]
        grid_columns=1
        for index in range(layout.count()):
            item=layout.itemAt(index)
            row,column,row_span,column_span=layout.getItemPosition(index)
            old_items.append((item,row,column,row_span,column_span))
            grid_columns=max(grid_columns,column+column_span)
        while layout.count():
            layout.takeAt(0)
        layout.addWidget(header,0,0,1,grid_columns)
        for item,row,column,row_span,column_span in old_items:
            widget=item.widget()
            if widget is not None:
                layout.addWidget(widget,row+1,column,row_span,column_span)
            else:
                layout.addItem(item,row+1,column,row_span,column_span)
    else:
        layout.insertWidget(0,header)
    # Ручка изменения размера сохраняет кастомное оформление без системной рамки.
    resize_row = QHBoxLayout()
    resize_row.setContentsMargins(0, 0, 2, 2)
    resize_row.addStretch(1)
    resize_grip = QSizeGrip(dialog)
    resize_grip.setToolTip("Изменить размер окна")
    resize_grip.setFixedSize(16, 16)
    resize_row.addWidget(resize_grip, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
    if isinstance(layout, QGridLayout):
        last_row = max((layout.getItemPosition(i)[0] + layout.getItemPosition(i)[2] for i in range(layout.count())), default=0)
        layout.addLayout(resize_row, last_row, 0, 1, max(1, grid_columns if 'grid_columns' in locals() else 1))
    else:
        layout.addLayout(resize_row)


class QMessageBox:
    """Небольшие системные уведомления в едином frameless-оформлении."""
    StandardButton = QtMessageBox.StandardButton
    Icon = QtMessageBox.Icon

    @staticmethod
    def _show(parent, title, text, icon, buttons, default_button=None):
        box = QtMessageBox(icon, title, str(text), buttons, parent)
        add_dialog_chrome(box, box.layout(), title)
        if default_button not in (None, QtMessageBox.StandardButton.NoButton):
            box.setDefaultButton(default_button)
        return box.exec()

    @staticmethod
    def information(parent, title, text, buttons=QtMessageBox.StandardButton.Ok, defaultButton=QtMessageBox.StandardButton.NoButton):
        return QMessageBox._show(parent,title,text,QtMessageBox.Icon.Information,buttons,defaultButton)

    @staticmethod
    def warning(parent, title, text, buttons=QtMessageBox.StandardButton.Ok, defaultButton=QtMessageBox.StandardButton.NoButton):
        return QMessageBox._show(parent,title,text,QtMessageBox.Icon.Warning,buttons,defaultButton)

    @staticmethod
    def critical(parent, title, text, buttons=QtMessageBox.StandardButton.Ok, defaultButton=QtMessageBox.StandardButton.NoButton):
        return QMessageBox._show(parent,title,text,QtMessageBox.Icon.Critical,buttons,defaultButton)

    @staticmethod
    def question(parent, title, text, buttons=QtMessageBox.StandardButton.Yes|QtMessageBox.StandardButton.No, defaultButton=QtMessageBox.StandardButton.NoButton):
        return QMessageBox._show(parent,title,text,QtMessageBox.Icon.Question,buttons,defaultButton)


class QFileDialog:
    """Нативные системные диалоги заменены на Qt-диалоги в общей теме."""
    @staticmethod
    def _dialog(parent, caption, directory, name_filter, save=False, folder=False):
        dialog=QtFileDialog(parent,caption,directory,name_filter)
        dialog.setOption(QtFileDialog.Option.DontUseNativeDialog,True)
        if folder:
            dialog.setFileMode(QtFileDialog.FileMode.Directory)
            dialog.setOption(QtFileDialog.Option.ShowDirsOnly,True)
        elif save:
            dialog.setAcceptMode(QtFileDialog.AcceptMode.AcceptSave)
            dialog.setFileMode(QtFileDialog.FileMode.AnyFile)
        else:
            dialog.setAcceptMode(QtFileDialog.AcceptMode.AcceptOpen)
            dialog.setFileMode(QtFileDialog.FileMode.ExistingFile)
        add_dialog_chrome(dialog,dialog.layout(),caption)
        return dialog

    @staticmethod
    def getOpenFileName(parent=None, caption="", directory="", filter="", *args, **kwargs):
        dialog=QFileDialog._dialog(parent,caption,directory,filter)
        if dialog.exec()==QDialog.DialogCode.Accepted and dialog.selectedFiles():
            return dialog.selectedFiles()[0],filter
        return "",filter

    @staticmethod
    def getSaveFileName(parent=None, caption="", directory="", filter="", *args, **kwargs):
        dialog=QFileDialog._dialog(parent,caption,directory,filter,save=True)
        if dialog.exec()==QDialog.DialogCode.Accepted and dialog.selectedFiles():
            return dialog.selectedFiles()[0],filter
        return "",filter

    @staticmethod
    def getExistingDirectory(parent=None, caption="", directory="", *args, **kwargs):
        dialog=QFileDialog._dialog(parent,caption,directory,"",folder=True)
        if dialog.exec()==QDialog.DialogCode.Accepted and dialog.selectedFiles():
            return dialog.selectedFiles()[0]
        return ""


class DiscoverySignals(QObject):
    finished = Signal(object)


class AutoDiscoveryDialog(QDialog):
    """Автоматический сбор зависимостей: профили, Certificate Transparency, DNS-over-HTTPS и HAR."""
    def __init__(self, parent=None, dns_reader=None):
        super().__init__(parent)
        self.dns_reader = dns_reader
        self.setWindowTitle("Автоопределение зависимостей сервиса")
        self.resize(1120, 740)
        self.discovered = {}
        self.scan_thread = None
        self.signals = DiscoverySignals(self)
        self.signals.finished.connect(self._finish_scan)
        self.dns_observation_baseline_ready = False
        self.dns_observation_baseline = set()
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._ui_icons = getattr(parent, "_ui_icons", {}) if parent is not None else {}
        self.setStyleSheet("QDialog { background-color:#080f1d; color:#e8effb; } QWidget { color:#e8effb; }")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 16)
        root.setSpacing(10)
        add_dialog_chrome(self, root, "Зависимости сервисов")
        # Центрируем после расчёта геометрии, чтобы окно не открывалось за экраном.
        QTimer.singleShot(0, self._center_on_parent)

        title = QLabel("Собери домены и IP в группы сервисов")
        title.setObjectName("SectionTitle")
        root.addWidget(title)
        note = QLabel(
            "Автопоиск получает поддомены из Certificate Transparency (crt.sh), проверяет A/AAAA/CNAME через "
            "Cloudflare DNS-over-HTTPS и объединяет результаты с готовыми профилями. HAR показывает фактические "
            "запросы браузера. Certificate Transparency не гарантирует полноту списка, а DNS-адреса CDN могут "
            "использоваться несколькими сервисами — найденные IP не добавляются в маршрутизацию автоматически."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        root.addWidget(note)

        input_row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Основной домен: chatgpt.com, youtube.com, example.org")
        self.domain_input.returnPressed.connect(self.refresh_dependencies)
        self.scan_button = QPushButton("Обновить зависимости")
        self.scan_button.setObjectName("PrimaryButton")
        self.scan_button.clicked.connect(self.refresh_dependencies)
        input_row.addWidget(self.domain_input, 1)
        input_row.addWidget(self.scan_button)
        root.addLayout(input_row)

        actions = QHBoxLayout()
        har = QPushButton("Импорт HAR")
        har.clicked.connect(self.import_har)
        dns_cache = QPushButton("Снять DNS-кэш роутера")
        dns_cache.setToolTip("Дополнительный источник. DNS-кэш MikroTik не устанавливает, какое приложение создало запрос.")
        dns_cache.clicked.connect(self.request_dns_cache)
        self.monitor_dns = QPushButton("Наблюдать DNS вручную")
        self.monitor_dns.setCheckable(True)
        self.monitor_dns.toggled.connect(self.toggle_dns_monitor)
        self.dns_monitor_timer = QTimer(self)
        self.dns_monitor_timer.setInterval(7000)
        self.dns_monitor_timer.timeout.connect(self.request_dns_cache)
        self.finished.connect(lambda _result: self.dns_monitor_timer.stop())
        self.status = QLabel("Введи основной домен и нажми «Обновить зависимости».")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        actions.addWidget(har)
        actions.addWidget(dns_cache)
        actions.addWidget(self.monitor_dns)
        actions.addWidget(self.status, 1)
        root.addLayout(actions)

        # Иерархическое дерево: группа → домен → IP-адреса.
        filter_row = QHBoxLayout()
        filter_label = QLabel("Структура зависимостей")
        filter_label.setObjectName("SectionTitle")
        filter_row.addWidget(filter_label)
        filter_row.addStretch()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Фильтр по группе, домену или IP…")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._filter_tree)
        self.search_input.setMaximumWidth(330)
        filter_row.addWidget(self.search_input)
        self.expand_button = QPushButton("Развернуть всё")
        self.expand_button.clicked.connect(self.tree_expand_all)
        self.collapse_button = QPushButton("Свернуть всё")
        self.collapse_button.clicked.connect(self.tree_collapse_all)
        filter_row.addWidget(self.expand_button)
        filter_row.addWidget(self.collapse_button)
        root.addLayout(filter_row)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Группа / домен / IP", "Источник", "Достоверность"])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setIndentation(22)
        self.tree.setRootIsDecorated(True)
        self.tree.setAnimated(True)
        self.tree.setExpandsOnDoubleClick(True)
        self.tree.setMinimumHeight(390)
        self.tree.setColumnWidth(0, 480)
        self.tree.setColumnWidth(1, 300)
        self.tree.header().setStretchLastSection(True)
        self.tree.itemChanged.connect(self._tree_item_changed)
        root.addWidget(self.tree, 1)

        self.add_ips = QCheckBox("Добавлять найденные IPv4 как отдельные /32 (не рекомендуется для общих CDN)")
        self.add_ips.setChecked(False)
        root.addWidget(self.add_ips)
        warning = QLabel(
            "Уровни: «Фактический запрос» — домен найден в HAR; «Обнаружен» — найден в CT/DNS; "
            "«Профиль» — домен взят из встроенного списка. IP используются только как справочная информация, "
            "пока ты отдельно не отметишь добавление IP."
        )
        warning.setObjectName("InfoNote")
        warning.setWordWrap(True)
        root.addWidget(warning)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Закрыть")
        cancel.clicked.connect(self.reject)
        add = QPushButton("Добавить выбранное")
        add.setObjectName("PrimaryButton")
        add.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(add)
        root.addLayout(buttons)

    def _center_on_parent(self):
        parent = self.parentWidget()
        screen = None
        if parent is not None:
            reference = parent.frameGeometry().center()
            screen = QApplication.screenAt(reference)
        if screen is None:
            screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        center = parent.frameGeometry().center() if parent is not None else area.center()
        if not area.contains(center):
            center = area.center()
        x = center.x() - self.width() // 2
        y = center.y() - self.height() // 2
        x = max(area.left(), min(x, area.right() - self.width() + 1))
        y = max(area.top(), min(y, area.bottom() - self.height() + 1))
        self.move(x, y)

    @staticmethod
    def _is_domain(value):
        try:
            target, kind = normalize_target(value)
            return target if kind == "Домен" else None
        except Exception:
            return None

    @staticmethod
    def _resolve_dns(domain):
        """Возвращает A/AAAA и CNAME через публичный DoH; не меняет DNS роутера."""
        result = {"ips": set(), "cnames": set()}
        for qtype in ("A", "AAAA", "CNAME"):
            try:
                url = "https://cloudflare-dns.com/dns-query?name=" + urllib.parse.quote(domain) + "&type=" + qtype
                req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": "MikroTikVPNManager/1.7"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                for answer in payload.get("Answer", []):
                    data = str(answer.get("data", "")).rstrip(".")
                    if qtype in ("A", "AAAA"):
                        try:
                            result["ips"].add(str(ipaddress.ip_address(data)))
                        except ValueError:
                            pass
                    else:
                        alias = AutoDiscoveryDialog._is_domain(data)
                        if alias and alias != domain:
                            result["cnames"].add(alias)
            except Exception:
                continue
        return result

    def _group_for(self, domain, fallback=""):
        for profile, entries in PRESETS.items():
            for raw in entries:
                item = self._is_domain(raw)
                if item and (domain == item or domain.endswith("." + item) or item.endswith("." + domain)):
                    return profile
        return fallback or domain

    def _add_domain(self, domain, source, group=None, confidence="Обнаружен", ips=None):
        domain = self._is_domain(domain)
        if not domain:
            return
        record = self.discovered.setdefault(domain, {
            "sources": set(), "ips": set(), "group": group or self._group_for(domain),
            "confidence": confidence
        })
        record["sources"].add(source)
        if ips:
            record["ips"].update(ips)
        if confidence == "Фактический запрос":
            record["confidence"] = confidence
        elif record["confidence"] == "Профиль" and confidence == "Обнаружен":
            record["confidence"] = confidence
        if group:
            record["group"] = group

    def _render(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        grouped = {}
        for domain, record in self.discovered.items():
            grouped.setdefault(record["group"], []).append((domain, record))

        for group_name in sorted(grouped, key=str.casefold):
            entries = sorted(grouped[group_name], key=lambda item: item[0])
            ip_count = sum(len(record["ips"]) for _domain, record in entries)
            group_item = QTreeWidgetItem([f"{group_name}  ·  {len(entries)} дом.  ·  {ip_count} IP", "", ""])
            group_item.setFlags(group_item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
            group_item.setCheckState(0, Qt.CheckState.Checked)
            group_item.setData(0, Qt.ItemDataRole.UserRole, ("group", group_name))
            group_item.setToolTip(0, "Группа сервиса. Отметка выбирает все домены группы.")
            self.tree.addTopLevelItem(group_item)

            for domain, record in entries:
                sources = "; ".join(sorted(record["sources"]))
                domain_item = QTreeWidgetItem([domain, sources, record["confidence"]])
                domain_item.setFlags(domain_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                domain_item.setCheckState(0, Qt.CheckState.Checked)
                domain_item.setData(0, Qt.ItemDataRole.UserRole, ("domain", domain))
                domain_item.setToolTip(0, f"Группа: {group_name}\nДомен: {domain}\nИсточники: {sources}")
                domain_item.setToolTip(1, sources)
                group_item.addChild(domain_item)

                for ip in sorted(record["ips"], key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))):
                    ip_item = QTreeWidgetItem([ip, "DNS / HAR / наблюдение", "IP-адрес"])
                    ip_item.setData(0, Qt.ItemDataRole.UserRole, ("ip", ip))
                    ip_item.setToolTip(0, f"IP-адрес, связанный с {domain}; справочная информация.")
                    domain_item.addChild(ip_item)
            group_item.setExpanded(True)

        self.tree.blockSignals(False)
        self._filter_tree(self.search_input.text() if hasattr(self, "search_input") else "")

    def _tree_item_changed(self, item, column):
        if column == 0:
            self.tree.viewport().update()

    def _filter_tree(self, text):
        needle = text.strip().casefold()
        for i in range(self.tree.topLevelItemCount()):
            group_item = self.tree.topLevelItem(i)
            group_match = needle in group_item.text(0).casefold()
            any_match = group_match
            for j in range(group_item.childCount()):
                domain_item = group_item.child(j)
                domain_match = group_match or needle in domain_item.text(0).casefold()
                ip_match = False
                for k in range(domain_item.childCount()):
                    ip_item = domain_item.child(k)
                    visible = not needle or domain_match or needle in ip_item.text(0).casefold()
                    ip_item.setHidden(not visible)
                    ip_match = ip_match or visible
                visible_domain = not needle or domain_match or ip_match
                domain_item.setHidden(not visible_domain)
                any_match = any_match or visible_domain
            group_item.setHidden(bool(needle) and not any_match)
            if needle and any_match:
                group_item.setExpanded(True)

    def tree_expand_all(self):
        self.tree.expandAll()

    def tree_collapse_all(self):
        self.tree.collapseAll()

    def refresh_dependencies(self):
        root_domain = self._is_domain(self.domain_input.text())
        if not root_domain:
            QMessageBox.warning(self, "Некорректный домен", "Укажи основной домен, например chatgpt.com.")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.domain_input.setText(root_domain)
        group = self._group_for(root_domain, root_domain)
        self._add_domain(root_domain, "Основной домен, указан пользователем", group, "Указан пользователем")
        matched = []
        for profile, entries in PRESETS.items():
            normalized = [self._is_domain(item) for item in entries]
            if any(item and (root_domain == item or root_domain.endswith("." + item) or item.endswith("." + root_domain)) for item in normalized):
                matched.append(profile)
                for item in normalized:
                    if item:
                        self._add_domain(item, "Встроенный профиль: " + profile, profile, "Профиль")
        self._render()
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Идёт поиск…")
        self.status.setText("Запрашиваю Certificate Transparency и DNS-over-HTTPS. Это может занять некоторое время…")

        def worker():
            profile_candidates = {self._is_domain(raw) for profile in matched for raw in PRESETS.get(profile, []) if self._is_domain(raw)}
            candidates = {root_domain} | profile_candidates
            errors = []
            try:
                url = "https://crt.sh/?q=%25." + urllib.parse.quote(root_domain) + "&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "MikroTikVPNManager/1.7"})
                with urllib.request.urlopen(req, timeout=18) as response:
                    rows = json.loads(response.read().decode("utf-8", "replace"))
                for item in rows:
                    for name in str(item.get("name_value", "")).splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name == root_domain or name.endswith("." + root_domain):
                            valid = self._is_domain(name)
                            if valid:
                                candidates.add(valid)
                candidates = profile_candidates | set(sorted(candidates)[:180])
            except Exception as exc:
                errors.append("CT: " + str(exc))
            resolved = {}
            try:
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=12) as pool:
                    futures = {pool.submit(self._resolve_dns, name): name for name in candidates}
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            resolved[name] = future.result()
                        except Exception:
                            resolved[name] = {"ips": set(), "cnames": set()}
            except Exception as exc:
                errors.append("DNS: " + str(exc))
            self.signals.finished.emit({"root": root_domain, "group": group, "candidates": sorted(candidates), "resolved": resolved, "errors": errors, "profiles": matched})
        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _finish_scan(self, result):
        root = result["root"]
        group = result["group"]
        for domain in result["candidates"]:
            data = result["resolved"].get(domain, {})
            self._add_domain(domain, "Certificate Transparency (crt.sh)" if domain != root else "Основной домен",
                             self._group_for(domain, group), "Обнаружен", data.get("ips", set()))
            for alias in data.get("cnames", set()):
                self._add_domain(alias, "CNAME через Cloudflare DoH", self._group_for(alias, group), "Обнаружен")
        self._render()
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Обновить зависимости")
        total_ips = sum(len(item["ips"]) for item in self.discovered.values())
        suffix = (" Ошибки: " + " | ".join(result["errors"])) if result["errors"] else ""
        self.status.setText(
            f"Группа «{group}»: доменов в списке {len(self.discovered)}, найдено IP/IPv6 {total_ips}. "
            "CT и DNS дают кандидатов, а не доказательство зависимости." + suffix
        )

    def toggle_dns_monitor(self, enabled):
        if enabled:
            self.monitor_dns.setText("Остановить наблюдение")
            self.dns_observation_baseline_ready = False
            self.dns_observation_baseline.clear()
            self.dns_monitor_timer.start()
            self.status.setText("Снимаю исходный DNS-кэш, затем можно открыть сервис.")
            self.request_dns_cache()
        else:
            self.dns_monitor_timer.stop()
            self.monitor_dns.setText("Наблюдать DNS вручную")
            self.status.setText("Наблюдение DNS остановлено.")

    def request_dns_cache(self):
        if not callable(self.dns_reader):
            QMessageBox.warning(self, "Нет подключения", "DNS-кэш MikroTik доступен после SSH-подключения.")
            return
        self.dns_reader(self)

    def closeEvent(self, event):
        self.dns_monitor_timer.stop()
        super().closeEvent(event)

    def import_router_dns_cache(self, output):
        records = re.findall(r'name="([^"]+)"[^\n]*?(?:data|address)="([^"]+)"', str(output), flags=re.IGNORECASE)
        current_names = {domain for name, _data in records if (domain := self._is_domain(name))}
        if self.monitor_dns.isChecked() and not self.dns_observation_baseline_ready:
            self.dns_observation_baseline = current_names
            self.dns_observation_baseline_ready = True
            self.status.setText(f"Исходный DNS-кэш зафиксирован ({len(current_names)} имён). Открой нужный сервис.")
            return
        added = 0
        for name, data in records:
            domain = self._is_domain(name)
            if not domain or (self.monitor_dns.isChecked() and domain in self.dns_observation_baseline):
                continue
            group = self._group_for(domain)
            ips = set()
            try:
                ipaddress.ip_address(data)
                ips.add(data)
            except ValueError:
                alias = self._is_domain(data)
                if alias:
                    self._add_domain(alias, "CNAME из DNS-кэша MikroTik", self._group_for(alias), "Обнаружен")
            self._add_domain(domain, "DNS-кэш MikroTik", group, "Обнаружен", ips)
            self.dns_observation_baseline.add(domain)
            added += 1
        self._render()
        self.status.setText(f"DNS-кэш обработан: обновлено доменов {added}. Источник не определяет приложение-клиент.")

    def import_har(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт HAR", str(Path.home()), "HAR files (*.har *.json);;All files (*.*)")
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            entries = data.get("log", {}).get("entries", [])
            count = 0
            for entry in entries:
                request = entry.get("request", {})
                response = entry.get("response", {})
                request_url = request.get("url", "")
                request_domain = self._is_domain(urlparse(request_url).hostname or "")
                candidates = [(request_url, "HAR: фактический запрос")]
                for header in request.get("headers", []) + response.get("headers", []):
                    header_name = str(header.get("name", "")).lower()
                    if header_name in ("referer", "origin", "location"):
                        candidates.append((str(header.get("value", "")), "HAR: " + header_name))
                if response.get("redirectURL"):
                    candidates.append((response["redirectURL"], "HAR: redirect"))
                for candidate_url, source in candidates:
                    host = self._is_domain(urlparse(candidate_url).hostname or "")
                    if host:
                        ips = set()
                        if source == "HAR: фактический запрос":
                            server_ip = entry.get("serverIPAddress", "")
                            try:
                                if server_ip:
                                    ips.add(str(ipaddress.ip_address(server_ip)))
                            except ValueError:
                                pass
                        self._add_domain(host, source, self._group_for(host, self._is_domain(self.domain_input.text()) or host),
                                         "Фактический запрос" if source == "HAR: фактический запрос" else "Обнаружен", ips)
                        count += 1
            self._render()
            self.status.setText(f"HAR обработан: фактические и связанные хосты добавлены; записей: {len(self.discovered)}.")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка HAR", f"Не удалось прочитать HAR-файл:\n{exc}")

    def selected_target_records(self):
        result = []
        for i in range(self.tree.topLevelItemCount()):
            group_item = self.tree.topLevelItem(i)
            group_name = group_item.text(0).split("  ·  ", 1)[0]
            for j in range(group_item.childCount()):
                domain_item = group_item.child(j)
                if domain_item.checkState(0) != Qt.CheckState.Checked:
                    continue
                domain = domain_item.text(0)
                result.append((domain, "Домен", group_name))
                if self.add_ips.isChecked():
                    for k in range(domain_item.childCount()):
                        ip = domain_item.child(k).text(0)
                        try:
                            addr = ipaddress.ip_address(ip)
                            if addr.version == 4:
                                result.append((f"{addr}/32", "IPv4-сеть", group_name))
                        except ValueError:
                            pass
        return result

    def selected_targets(self):
        return [(target, kind) for target, kind, _group in self.selected_target_records()]

def classify_routeros_command(command):
    """Conservative CLI risk classification; unknown syntax is never assumed safe."""
    raw=command.strip()
    if not raw: return ("empty","Пустая команда","")
    if "\n" in raw or "\r" in raw: return ("critical","Многострочная команда","Ввод нескольких строк не поддерживается.")
    if ";" in raw: return ("critical","Цепочка команд","Содержит разделитель ';' и может выполнить несколько операций.")
    low=raw.lower().strip()
    root=low.lstrip("/")
    mutation=re.search(r"(?i)(?:^|\s)(add|set|remove|enable|disable|move|reset|reset-counters|clear|flush|renew|release|generate-key|run|reboot|restore|upgrade|import|create|delete)(?:\s|$)",root)
    destructive=(
        re.search(r"(?i)^/?system\s+(?:reboot|reset-configuration|shutdown)\b",low)
        or re.search(r"(?i)^/?(?:user|ip firewall|ip route|ip address|ip dns|ip service|ip ssh|ip dhcp-server|ip pool|interface|routing|system scheduler|system script|system package)\s+.*\b(remove|reset|flush|disable|set|add|enable|move|import|restore)\b",low)
        or re.search(r"(?i)^/?(?:file|backup|system backup)\s+.*\b(remove|delete|restore|save|load)\b",low)
        or re.search(r"(?i)^/?tool\s+netwatch\b.*\b(add|set|remove)\b",low)
        or root.startswith(":") or root.startswith("execute ")
    )
    if destructive:
        return ("critical","Высокий риск","Может затронуть доступ к роутеру, Firewall, маршруты, учётные записи, VPN или данные.")
    if mutation:
        return ("change","Изменение конфигурации","Команда изменяет состояние или конфигурацию MikroTik.")
    read_verb=re.search(r"(?i)(?:^|\s)(print|export|get|find|monitor|ping|resolve|traceroute|torch|snmp-get)(?:\s|$)",low)
    read_root=re.match(r"^/?(?:system|interface|ip|ipv6|routing|wireguard|tool|queue|ppp|user|certificate|file|log|disk|caps-man|wifi|ping|resolve|traceroute)\b",low)
    if read_root and read_verb:
        return ("read","Только чтение","Команда распознана как запрос состояния; явных операций изменения не найдено.")
    if re.match(r"^/?(?:ping|resolve|traceroute)\b",low):
        return ("read","Только чтение","Сетевая проверка без изменения конфигурации.")
    return ("unknown","Неизвестная / непроверенная команда","Безопасность автоматически не подтверждена. Проверь синтаксис и побочные эффекты перед выполнением.")


class TerminalCommandInput(QLineEdit):
    """Однострочный CLI-ввод с навигацией по истории команд стрелками."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.history = []
        self.history_index = 0
        self.draft = ""

    def set_history(self, history):
        self.history = history
        self.history_index = len(history)

    def remember_current_draft(self):
        if self.history_index >= len(self.history):
            self.draft = self.text()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Up and self.history:
            if self.history_index == len(self.history):
                self.draft = self.text()
            if self.history_index > 0:
                self.history_index -= 1
                self.setText(self.history[self.history_index])
                self.end(False)
            event.accept()
            return
        if event.key() == Qt.Key.Key_Down and self.history:
            if self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.setText(self.history[self.history_index])
            elif self.history_index == len(self.history) - 1:
                self.history_index = len(self.history)
                self.setText(self.draft)
            self.end(False)
            event.accept()
            return
        super().keyPressEvent(event)
        if self.history_index == len(self.history):
            self.draft = self.text()


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.resize(1360, 860); self.setMinimumSize(1024, 700)
        self.q = queue.Queue(); self.router: Optional[RouterConnection] = None
        self.busy = False; self.targets = []; self.pending_actions = []; self.log_window = None; self.log_lines = []; self.last_diag = {}
        self.settings = self.load_settings()
        try:
            groups=json.loads(self.settings.get("dependency_groups", "{}"))
            self.target_groups=groups if isinstance(groups, dict) else {}
        except Exception:
            self.target_groups = {}
        self.router_state = None; self.tr_rx = deque(maxlen=TrafficChart.N); self.tr_tx = deque(maxlen=TrafficChart.N); self.tr_prev = None; self.tr_busy = False
        self.normal_rx = deque(maxlen=TrafficChart.N); self.normal_tx = deque(maxlen=TrafficChart.N); self.wan_prev = None; self.pending_wg_config = None
        self.router_status_busy = False; self.last_router_status = None
        self.build_ui(); self.load_targets()
        self.timer = QTimer(self); self.timer.timeout.connect(self.poll); self.timer.start(120)
        # Автоматические проверки выключены; пользователь может отдельно включить опрос трафика.
        self.traffic_timer = QTimer(self); self.traffic_timer.timeout.connect(self.poll_traffic)
        self.traffic_timer.setInterval(5000)
        self.router_status_timer = QTimer(self); self.router_status_timer.timeout.connect(self.refresh_router_status)
        self.router_status_timer.setInterval(30000)
        self.login_dialog = None

    def load_settings(self):
        try: cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8")) if CONFIG_FILE.exists() else {}
        except Exception: cfg = {}
        defaults = {"host":"", "port":"2313", "username":"pwned", "auth_method":"key", "key_file":"", "lan_interface":"INTERNET", "lan_subnet":"192.168.0.0/24", "lan_dns":"192.168.0.2", "route_table":"vpn", "wg_interface":"furynet-wg", "wan_interface":"WAN", "address_list":"vpn_domains", "doh_enabled":"1", "doh_url":"https://dns.google/dns-query", "doh_bootstrap":"8.8.8.8, 8.8.4.4", "doh_verify_cert":"1", "wg_public_key":"", "wg_endpoint":"", "wg_port":"51820", "wg_allowed":"0.0.0.0/0", "wg_address":"", "wg_keepalive":"25", "wg_mtu":"1240", "dependency_groups":"{}", "managed_targets":"[]", "terminal_favorites":"[]", "terminal_sets":"{}"}
        defaults.update({k:str(v) for k,v in cfg.items() if k in defaults})
        return defaults

    def save_settings(self):
        if hasattr(self, "inputs"):
            self.settings.update(self.fields())
        if hasattr(self, "wg_inputs"):
            for k,w in self.wg_inputs.items():
                if k != "wg_private_key": self.settings[k] = w.text().strip()
        if hasattr(self, "doh_enabled"):
            self.settings["doh_enabled"] = "1" if self.doh_enabled.isChecked() else "0"
            self.settings["doh_url"] = self.doh_url.text().strip()
            self.settings["doh_bootstrap"] = self.doh_bootstrap.text().strip()
            self.settings["doh_verify_cert"] = "1" if self.doh_verify_cert.isChecked() else "0"
        self.settings["dependency_groups"] = json.dumps(getattr(self, "target_groups", {}), ensure_ascii=False)
        self.settings["managed_targets"] = json.dumps(getattr(self, "targets", []), ensure_ascii=False)
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
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(236)
        sl = QVBoxLayout(sidebar); sl.setContentsMargins(16,22,16,16); sl.setSpacing(8)
        logo = QLabel("◈  MIKROTIK") ; logo.setObjectName("Brand")
        sl.addWidget(logo); sub = QLabel("NETWORK  /  VPN CONTROL"); sub.setObjectName("BrandSub"); sl.addWidget(sub); sl.addSpacing(28)
        self.nav = QListWidget(); self.nav.setObjectName("Nav")
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.nav.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.nav.setWordWrap(False)
        for label in ["01     Обзор", "02     VPN-маршрутизация", "03     Диагностика", "04     Firewall и DNS", "05     DNS / DoH", "06     Резервные копии", "07     Настройки", "08     Терминал", "09     Журнал"]:
            QListWidgetItem(label, self.nav)
        self.nav.setCurrentRow(0); self.nav.currentRowChanged.connect(self.pages_changed)
        sl.addWidget(self.nav,1)
        foot = self.foot = QLabel("ROUTEROS 7  ·  SSH KEY AUTH\nSelective routing workspace"); foot.setObjectName("SidebarFoot"); foot.setWordWrap(True); sl.addWidget(foot)
        main.addWidget(sidebar)
        content = QWidget(); cv = QVBoxLayout(content); cv.setContentsMargins(24,20,24,18); cv.setSpacing(14); main.addWidget(content,1)
        header = QHBoxLayout(); titlebox = QVBoxLayout(); self.page_title=QLabel("Обзор сети"); self.page_title.setObjectName("PageTitle")
        self.page_sub=QLabel("Состояние маршрутизатора и VPN-туннеля"); self.page_sub.setObjectName("Muted")
        titlebox.addWidget(self.page_title); titlebox.addWidget(self.page_sub); header.addLayout(titlebox); header.addStretch()
        self.header_apply_btn=QPushButton("Применить изменения · 0"); self.header_apply_btn.setObjectName("PrimaryButton"); self.header_apply_btn.setEnabled(False); self.header_apply_btn.clicked.connect(self.apply_pending_changes); self.header_apply_btn.setToolTip("Просмотреть команды и применить выбранные подготовленные изменения на MikroTik."); header.addWidget(self.header_apply_btn)
        self.header_cancel_pending_btn=QPushButton("Отменить все"); self.header_cancel_pending_btn.setObjectName("DangerButton"); self.header_cancel_pending_btn.setEnabled(False); self.header_cancel_pending_btn.clicked.connect(self.cancel_all_pending); self.header_cancel_pending_btn.setToolTip("Очистить очередь ещё не применённых изменений."); header.addWidget(self.header_cancel_pending_btn)
        self.auth_btn=QPushButton("Подключиться"); self.auth_btn.setObjectName("PrimaryButton"); self.auth_btn.clicked.connect(self.show_ssh_login); header.addWidget(self.auth_btn)
        self.log_btn=QPushButton("Журнал"); self.log_btn.setObjectName("QuietButton"); self.log_btn.clicked.connect(lambda: self.nav.setCurrentRow(8)); header.addWidget(self.log_btn)
        cv.addLayout(header)
        div=QFrame(); div.setObjectName("Divider"); div.setFixedHeight(1); cv.addWidget(div)
        self.stack=QStackedWidget(); cv.addWidget(self.stack,1)
        self.pages=[]
        self.pages.append(self.page_dashboard()); self.pages.append(self.page_routing()); self.pages.append(self.page_diagnostics()); self.pages.append(self.page_firewall()); self.pages.append(self.page_dns_diagnostics()); self.pages.append(self.page_backups()); self.pages.append(self.page_settings()); self.pages.append(self.page_terminal()); self.pages.append(self.page_logs())
        for p in self.pages: self.stack.addWidget(self.scrolled(p))
        footer=QHBoxLayout()
        self.progress=QProgressBar(); self.progress.setObjectName("BusyProgress"); self.progress.setRange(0,0); self.progress.setFixedWidth(110); self.progress.setTextVisible(False); self.progress.hide(); footer.addWidget(self.progress)
        self.status=QLabel("Готово · Изменения отправляются на роутер только после подтверждения")
        self.status.setObjectName("StatusBar"); footer.addWidget(self.status,1)
        grip=QSizeGrip(root); grip.setFixedSize(18,18); footer.addWidget(grip,0,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignBottom)
        cv.addLayout(footer)
        self.status.setToolTip("Здесь отображаются текущая операция и результат последнего действия.")
        self.auth_btn.setToolTip("Открыть окно SSH-подключения или отключиться от роутера.")
        self.log_btn.setToolTip("Открыть журнал команд, ошибок и действий приложения.")
        for i in range(9):
            action=QAction(self); action.setShortcut(f"Ctrl+{i+1}"); action.triggered.connect(lambda checked=False, row=i:self.nav.setCurrentRow(row)); self.addAction(action)
        log_action=QAction(self); log_action.setShortcut("Ctrl+L"); log_action.triggered.connect(lambda:self.nav.setCurrentRow(8)); self.addAction(log_action)
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
        page.layout().setContentsMargins(4, 4, 12, 22)
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
        hero_actions=QVBoxLayout()
        diag=QPushButton("Обновить состояние"); diag.setObjectName("HeroSecondary"); diag.clicked.connect(self.run_diagnostics)
        hero_actions.addWidget(diag); hero_actions.addStretch(); hl.addLayout(hero_actions)
        l.addWidget(hero)

        # Компактная оперативная панель: только лёгкие read-only запросы, без полной диагностики.
        health=self.panel("Состояние роутера","Оперативные показатели MikroTik · обновление вручную или по желанию каждые 30 секунд")
        health_head=QHBoxLayout()
        self.router_status_stamp=QLabel("Данные ещё не запрашивались"); self.router_status_stamp.setObjectName("Muted")
        self.router_status_refresh=QPushButton("Обновить состояние"); self.router_status_refresh.setObjectName("PrimaryButton")
        self.router_status_refresh.clicked.connect(self.refresh_router_status)
        self.router_status_auto=QCheckBox("Авто · 30 сек"); self.router_status_auto.setChecked(False)
        self.router_status_auto.toggled.connect(self.set_router_status_auto)
        health_head.addWidget(self.router_status_stamp,1); health_head.addWidget(self.router_status_auto); health_head.addWidget(self.router_status_refresh)
        health.layout().addLayout(health_head)
        self.router_health_values={}
        health_grid=QGridLayout(); health_grid.setHorizontalSpacing(18); health_grid.setVerticalSpacing(12)
        for i,(key,label) in enumerate((
            ("identity","УСТРОЙСТВО / ROUTEROS"),("cpu","CPU"),("memory","ПАМЯТЬ"),
            ("uptime","ВРЕМЯ РАБОТЫ"),("temperature","ТЕМПЕРАТУРА"),
            ("wan","WAN"),("lan","LAN"),("wireguard","WIREGUARD"),("internet","ИНТЕРНЕТ / DNS")
        )):
            cell=QFrame(); cell.setObjectName("RouterHealthCell")
            cl=QVBoxLayout(cell); cl.setContentsMargins(12,10,12,10); cl.setSpacing(3)
            cap=QLabel(label); cap.setObjectName("CardTitle")
            val=QLabel("—"); val.setObjectName("RouterHealthValue"); val.setWordWrap(True)
            cl.addWidget(cap); cl.addWidget(val)
            self.router_health_values[key]=val
            health_grid.addWidget(cell,i//3,i%3)
        for c in range(3): health_grid.setColumnStretch(c,1)
        health.layout().addLayout(health_grid)
        l.addWidget(health)

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
        refresh_traffic=QPushButton("Снять 3 замера"); refresh_traffic.clicked.connect(self.refresh_traffic_once)
        traffic_controls.addWidget(self.traffic_auto); traffic_controls.addStretch(); traffic_controls.addWidget(refresh_traffic)
        tp.layout().addLayout(traffic_controls); mid.addWidget(tp,2)
        dp=self.panel("Состояние DNS","Защита от обхода и утечек"); self.dns_ind={}
        for i,(key,title) in enumerate((("overall","Общая защита"),("doh","DoH (DNS-over-HTTPS)"),("redirect","Перехват DNS :53"),("dot","Блокировка DoT/DoQ :853"),("remote","Remote requests"),("fwd","DNS FWD-записи"),("ips","IP в address-list"),("v6","IPv6 default route"))):
            if i:
                sep=QFrame(); sep.setObjectName("Sep"); sep.setFixedHeight(1); dp.layout().addWidget(sep)
            row=QHBoxLayout(); row.setSpacing(10); dot=Dot(); tl=QLabel(title); tl.setObjectName("IndTitle"); vl=QLabel("—"); vl.setObjectName("IndValue"); vl.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(dot); row.addWidget(tl,1); row.addWidget(vl); dp.layout().addLayout(row); self.dns_ind[key]=(dot,vl)
        dp.layout().addStretch(); mid.addWidget(dp,1); l.addLayout(mid)
        normal=self.panel("Обычный трафик · оценка","Скорость WAN за вычетом WireGuard; оценка, не отдельный аппаратный счётчик")
        self.normal_chart=TrafficChart(); normal.layout().addWidget(self.normal_chart,1)
        self.normal_hint=QLabel("Укажи физический WAN-интерфейс в настройках. Автообновление включается отдельно."); self.normal_hint.setObjectName("Muted"); self.normal_hint.setWordWrap(True); normal.layout().addWidget(self.normal_hint)
        l.addWidget(normal)
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
        row=QHBoxLayout(); row.setSpacing(8)
        self.target_input=QLineEdit(); self.target_input.setPlaceholderText("example.com  ·  203.0.113.10  ·  203.0.113.0/24")
        self.target_input.setMinimumWidth(180); self.target_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        add=QPushButton("＋ Добавить цель"); add.setObjectName("PrimaryButton"); add.clicked.connect(self.add_target); self.target_input.returnPressed.connect(self.add_target)
        auto=QPushButton("Автоопределение…"); auto.clicked.connect(self.auto_discover_targets)
        row.addWidget(self.target_input,1); row.addWidget(add,0); row.addWidget(auto,0); p.layout().addLayout(row)
        group_row=QHBoxLayout(); group_row.setSpacing(10)
        group_label=QLabel("Группа для новой цели"); group_label.setMinimumWidth(150)
        self.target_group=QComboBox(); self.target_group.setEditable(True); self.target_group.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        known_groups={"Пользовательские", *PRESETS.keys(), *self.target_groups.values()}
        self.target_group.addItems(sorted(known_groups, key=str.casefold)); self.target_group.setCurrentText("Пользовательские")
        self.target_group.setMinimumWidth(240); self.target_group.setMaximumWidth(360)
        self.target_group.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.target_group.setToolTip("Выбери существующую группу или введи название новой группы.")
        self.target_group.lineEdit().setPlaceholderText("Выбрать или создать группу")
        group_row.addWidget(group_label); group_row.addWidget(self.target_group); group_row.addStretch(1); p.layout().addLayout(group_row)
        row2=QHBoxLayout(); self.preset=QComboBox(); self.preset.addItems(PRESETS.keys()); self.preset.setMinimumWidth(180); load=QPushButton("Загрузить профиль"); load.clicked.connect(self.load_preset); load_all=QPushButton("＋ Все профили"); load_all.setObjectName("PrimaryButton"); load_all.clicked.connect(self.load_all_presets); row2.addWidget(self.preset); row2.addWidget(load); row2.addWidget(load_all)
        import_btn=QPushButton("Импорт"); import_btn.clicked.connect(self.import_targets_file); row2.addWidget(import_btn)
        export_btn=QPushButton("Экспорт"); export_btn.clicked.connect(self.export_targets_file); row2.addWidget(export_btn)
        row2.addStretch()
        self.target_search=QLineEdit(); self.target_search.setObjectName("TargetSearch"); self.target_search.setPlaceholderText("⌕  Поиск группы, домена или IP…"); self.target_search.setMinimumWidth(240); self.target_search.textChanged.connect(self.filter_targets); row2.addWidget(self.target_search,1); p.layout().addLayout(row2)
        tree_tools=QHBoxLayout(); tree_caption=QLabel("СТРУКТУРА МАРШРУТИЗАЦИИ"); tree_caption.setObjectName("TreeCaption"); tree_tools.addWidget(tree_caption); tree_tools.addStretch()
        expand_btn=QPushButton("Развернуть всё"); expand_btn.clicked.connect(lambda:self.target_table.expandAll() if hasattr(self,"target_table") else None)
        collapse_btn=QPushButton("Свернуть всё"); collapse_btn.clicked.connect(lambda:self.target_table.collapseAll() if hasattr(self,"target_table") else None)
        tree_tools.addWidget(expand_btn); tree_tools.addWidget(collapse_btn)
        select_all_btn=QPushButton("Отметить всё"); select_all_btn.clicked.connect(lambda: self.set_all_target_checks(True)); tree_tools.addWidget(select_all_btn)
        clear_checks_btn=QPushButton("Снять отметки"); clear_checks_btn.clicked.connect(lambda: self.set_all_target_checks(False)); tree_tools.addWidget(clear_checks_btn)
        p.layout().addLayout(tree_tools)
        self.target_table=QTreeWidget(); self.target_table.setObjectName("RoutingTree"); self.target_table.setColumnCount(7); self.target_table.setHeaderLabels(["Группа / домен / IP","Тип","Источник","В приложении","На роутере","Состояние","Детали"]); self.target_table.header().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); self.target_table.header().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); self.target_table.header().setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents); self.target_table.header().setSectionResizeMode(3,QHeaderView.ResizeMode.ResizeToContents); self.target_table.header().setSectionResizeMode(4,QHeaderView.ResizeMode.ResizeToContents); self.target_table.header().setSectionResizeMode(5,QHeaderView.ResizeMode.ResizeToContents); self.target_table.header().setSectionResizeMode(6,QHeaderView.ResizeMode.Stretch); self.target_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.target_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection); self.target_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.target_table.itemChanged.connect(self.on_target_item_changed); self.target_table.setAlternatingRowColors(True); self.target_table.setUniformRowHeights(False); self.target_table.setMinimumHeight(340); self.target_table.setIndentation(26); self.target_table.setAnimated(True); self.target_table.setRootIsDecorated(True); self.target_table.setItemsExpandable(True); p.layout().addWidget(self.target_table,1)
        self.targets_empty=QLabel("Пока нет целей. Добавь домен или IP, загрузи профиль либо запусти автоопределение."); self.targets_empty.setObjectName("EmptyState"); self.targets_empty.setWordWrap(True); self.targets_empty.setAlignment(Qt.AlignmentFlag.AlignCenter); p.layout().addWidget(self.targets_empty)
        action_head=QHBoxLayout(); self.selection_hint=QLabel("Отметь галочками несколько групп, доменов или IP либо выдели строки мышью"); self.selection_hint.setObjectName("Muted"); action_head.addWidget(self.selection_hint); action_head.addStretch(); p.layout().addLayout(action_head)
        actions=QHBoxLayout()
        local_remove=QPushButton("Удалить из приложения"); local_remove.setObjectName("DangerButton"); local_remove.clicked.connect(self.remove_local); actions.addWidget(local_remove)
        stage_apply=QPushButton("Применить цели"); stage_apply.setObjectName("PrimaryButton"); stage_apply.clicked.connect(self.stage_apply_targets); actions.addWidget(stage_apply)
        stage_remove=QPushButton("Подготовить удаление на роутере"); stage_remove.setObjectName("DangerButton"); stage_remove.clicked.connect(self.stage_remove_selected); actions.addWidget(stage_remove)
        refresh=QPushButton("Обновить статусы"); refresh.clicked.connect(self.refresh_address_list); actions.addWidget(refresh)
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
        repair_row=QHBoxLayout()
        repair=QPushButton("Подготовить «Исправить всё»"); repair.setObjectName("PrimaryButton"); repair.clicked.connect(self.stage_fix_all)
        clear=QPushButton("Подготовить очистку IP/доменов"); clear.setObjectName("DangerButton"); clear.clicked.connect(self.stage_clear_all)
        repair_row.addWidget(repair); repair_row.addWidget(clear); control.layout().addLayout(repair_row)
        control_note=QLabel("«Исправить всё» предложит Cloudflare DNS (1.1.1.1 и 1.0.0.1), проверит/создаст управляемые NAT и Mangle и включит выборочную маршрутизацию. Очистка удалит управляемые DNS FWD и CIDR-записи приложения; основной маршрут через ZTE не затрагивается.")
        control_note.setObjectName("Muted"); control_note.setWordWrap(True); control.layout().addWidget(control_note)
        l.addWidget(control)
        pending=self.panel("Подготовленные изменения","Действия сначала добавляются в очередь. На роутер они попадут только после отдельного нажатия «Применить изменения».")
        pending_actions_bar=QHBoxLayout()
        self.pending_label=QLabel("Очередь пуста · на роутере ничего не ожидает применения"); self.pending_label.setObjectName("Muted"); self.pending_label.setWordWrap(True)
        pending_actions_bar.addWidget(self.pending_label,1)
        self.cancel_all_pending_btn=QPushButton("Отменить все изменения"); self.cancel_all_pending_btn.setObjectName("DangerButton"); self.cancel_all_pending_btn.clicked.connect(self.cancel_all_pending)
        pending_actions_bar.addWidget(self.cancel_all_pending_btn)
        pending.layout().addLayout(pending_actions_bar)
        self.pending_cards_layout=QVBoxLayout(); self.pending_cards_layout.setSpacing(10)
        pending.layout().addLayout(self.pending_cards_layout)
        l.addWidget(pending)
        return w

    def page_diagnostics(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Диагностика","Одна комплексная проверка: WAN, DNS/DoH, DHCP, WireGuard, маршруты, Mangle, NAT, FastTrack, IPv6 и DNS/HTTPS с этого Windows-ПК. Проверки не меняют конфигурацию MikroTik.")
        row=QHBoxLayout()
        for text,fn in [("Полная диагностика",self.run_diagnostics),("Тест ping через VPN",self.test_vpn),("Ping WAN",self.ping_wan),("Traceroute",self.traceroute)]:
            b=QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        row.addStretch()
        clr=QPushButton("Очистить"); clr.setObjectName("QuietButton"); clr.clicked.connect(lambda:self.diag_text.clear()); row.addWidget(clr)
        cpy=QPushButton("Копировать отчёт"); cpy.setObjectName("QuietButton"); cpy.clicked.connect(lambda:QApplication.clipboard().setText(self.diag_text.toPlainText())); row.addWidget(cpy)
        save=QPushButton("Сохранить .txt"); save.setObjectName("QuietButton"); save.clicked.connect(self.save_diagnostic_report); row.addWidget(save)
        p.layout().addLayout(row)
        client_box=QHBoxLayout()
        self.client_input=QLineEdit(); self.client_input.setPlaceholderText("IP телефона в LAN, например 192.168.0.50")
        self.client_input.setToolTip("Можно указать IP клиента вместе с доменом ниже: тогда диагностика дополнительно снимет conntrack-записи этого клиента к найденным IP сервиса.")
        client_box.addWidget(self.client_input,1)
        for label,fn in [("DHCP-клиенты",self.show_dhcp_clients),("Проверить IP клиента",self.diagnose_client),("Счётчики Mangle/DNS",self.show_policy_counters)]:
            b=QPushButton(label); b.clicked.connect(fn); client_box.addWidget(b)
        p.layout().addLayout(client_box)
        domain_box=QHBoxLayout()
        self.domain_diag_input=QLineEdit(); self.domain_diag_input.setPlaceholderText("Домен для проверки: youtube.com")
        self.domain_diag_input.setToolTip("Если выше указан IPv4 клиента, отчёт дополнительно покажет conntrack-сессии клиента к адресам этого домена. Для достоверного результата создай трафик с устройства во время проверки.")
        domain_box.addWidget(self.domain_diag_input,1)
        domain_test=QPushButton("Проверить DNS → IP → VPN-list"); domain_test.setObjectName("PrimaryButton"); domain_test.clicked.connect(self.diagnose_domain_route)
        domain_box.addWidget(domain_test); p.layout().addLayout(domain_box)
        self.diag_text=QTextEdit(); self.diag_text.setObjectName("DiagView"); self.diag_text.setReadOnly(True); self.diag_text.setAcceptRichText(False); self.diag_text.setPlaceholderText("Результаты диагностики появятся здесь…"); self.diag_text.setMinimumHeight(300); p.layout().addWidget(self.diag_text,1)
        l.addWidget(p,1); return w

    def save_diagnostic_report(self):
        content=self.diag_text.toPlainText().strip()
        if not content:
            QMessageBox.information(self,"Нет отчёта","Сначала запусти полную диагностику.")
            return
        default_name=f"MikroTik-diagnostic-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        path,_=QFileDialog.getSaveFileName(self,"Сохранить диагностический отчёт",str(Path.home()/default_name),"Текстовый отчёт (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(content,encoding="utf-8")
            QMessageBox.information(self,"Отчёт сохранён",f"Диагностический отчёт сохранён:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self,"Не удалось сохранить отчёт",str(exc))

    def page_firewall(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(12)
        head=self.panel("Конструктор Firewall","Filter, NAT и Mangle в таблицах. Изменения сначала попадают в локальную очередь; на MikroTik ничего не отправляется до отдельного применения.")
        top=QHBoxLayout()
        self.fw_search=QLineEdit(); self.fw_search.setPlaceholderText("Поиск по chain, action, адресу, интерфейсу или комментарию…"); self.fw_search.setClearButtonEnabled(True)
        self.fw_search.textChanged.connect(self.filter_firewall_table)
        refresh=QPushButton("⟳ Обновить"); refresh.setObjectName("PrimaryButton"); refresh.clicked.connect(self.refresh_firewall)
        top.addWidget(self.fw_search,1); top.addWidget(refresh); head.layout().addLayout(top)
        self.fw_tabs=QTabWidget(); self.fw_tabs.setObjectName("FirewallTabs"); self.fw_tables={}
        for key,title in (("filter","Filter"),("nat","NAT"),("mangle","Mangle")):
            table=QTableWidget(0,9); table.setObjectName("FirewallTable")
            table.setHorizontalHeaderLabels(["№","Вкл.","Chain","Action","Protocol","Src address","Dst address","Interface","Comment"])
            table.verticalHeader().setVisible(False); table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(8,QHeaderView.ResizeMode.Stretch)
            table.setMinimumHeight(260); self.fw_tables[key]=table; self.fw_tabs.addTab(table,title)
        head.layout().addWidget(self.fw_tabs,1)
        actions=QHBoxLayout()
        add=QPushButton("＋ Добавить правило"); add.setObjectName("PrimaryButton"); add.clicked.connect(self.firewall_add_rule)
        edit=QPushButton("Редактировать"); edit.clicked.connect(self.firewall_edit_rule)
        delete=QPushButton("Удалить"); delete.setObjectName("DangerButton"); delete.clicked.connect(self.firewall_delete_rule)
        actions.addWidget(add); actions.addWidget(edit); actions.addWidget(delete); actions.addStretch(); head.layout().addLayout(actions)
        l.addWidget(head,3)
        queue_panel=self.panel("Очередь изменений","Проверь описание воздействия и команды перед применением.")
        self.fw_queue_view=QPlainTextEdit(); self.fw_queue_view.setObjectName("FirewallQueue"); self.fw_queue_view.setReadOnly(True); self.fw_queue_view.setMinimumHeight(90)
        self.fw_queue_view.setPlaceholderText("Очередь пуста. Добавь или отредактируй правило."); queue_panel.layout().addWidget(self.fw_queue_view)
        qrow=QHBoxLayout()
        clear=QPushButton("Очистить очередь"); clear.clicked.connect(self.firewall_clear_queue)
        preview=QPushButton("Предпросмотр"); preview.clicked.connect(self.firewall_preview_queue)
        apply=QPushButton("Применить изменения"); apply.setObjectName("PrimaryButton"); apply.clicked.connect(self.firewall_apply_queue)
        qrow.addWidget(clear); qrow.addStretch(); qrow.addWidget(preview); qrow.addWidget(apply); queue_panel.layout().addLayout(qrow)
        self.fw_queue=[]; self.fw_data={"filter":[],"nat":[],"mangle":[]}
        l.addWidget(queue_panel,2); self.fw_tabs.currentChanged.connect(self.filter_firewall_table)
        return w

    def page_dns_diagnostics(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(14)
        intro=self.panel("DNS / DoH · центр диагностики","Поэтапная проверка пригодности DoH endpoint непосредственно с MikroTik и доступности DNS для LAN-клиентов. Состояние VPN-маршрутизации показывается отдельно и не блокирует смену DoH.")
        top=QHBoxLayout()
        self.doh_diag_domain=QLineEdit("chatgpt.com"); self.doh_diag_domain.setPlaceholderText("Домен для проверки, например chatgpt.com")
        top.addWidget(self.doh_diag_domain,1)
        domain_btn=QPushButton("Проверить домен"); domain_btn.setObjectName("PrimaryButton"); domain_btn.clicked.connect(self.run_doh_domain_diagnostic)
        top.addWidget(domain_btn); intro.layout().addLayout(top)
        actions=QHBoxLayout()
        full=QPushButton("Полная диагностика DNS / DoH"); full.setObjectName("PrimaryButton"); full.clicked.connect(self.run_doh_diagnostic)
        doh=QPushButton("Проверить DNS и ошибки DoH"); doh.clicked.connect(self.check_doh_config)
        clear=QPushButton("Очистить отчёт"); clear.setObjectName("QuietButton"); clear.clicked.connect(lambda:self.doh_diag_text.clear())
        copy=QPushButton("Копировать"); copy.setObjectName("QuietButton"); copy.clicked.connect(lambda:QApplication.clipboard().setText(self.doh_diag_text.toPlainText()))
        save=QPushButton("Сохранить .txt"); save.setObjectName("QuietButton"); save.clicked.connect(self.save_doh_diagnostic_report)
        actions.addWidget(full); actions.addWidget(doh); actions.addStretch(); actions.addWidget(clear); actions.addWidget(copy); actions.addWidget(save); intro.layout().addLayout(actions); l.addWidget(intro)
        endpoint=self.panel("Независимая проверка DoH endpoint","Проверка с компьютера, где запущено приложение. Отправляет DNS-запрос RFC 8484 (POST application/dns-message) и проверяет TLS, HTTP и DNS-ответ. Активный DoH на MikroTik не переключается.")
        erow=QHBoxLayout(); self.doh_test_endpoint=QLineEdit("https://cloudflare-dns.com/dns-query"); self.doh_test_endpoint.setPlaceholderText("https://dns.google/dns-query")
        erow.addWidget(QLabel("Endpoint")); erow.addWidget(self.doh_test_endpoint,1); endpoint.layout().addLayout(erow); l.addWidget(endpoint)
        note=QLabel("Read-only: настройки роутера не меняются. Главный критерий пригодности кандидата — успешный RFC 8484 POST с самого MikroTik с проверкой TLS-сертификата и корректным DNS-ответом. Дополнительно проверяются LAN DNS UDP/TCP и VPN-маршрутизация. Ответ :resolve и LAN-запрос могут обслуживаться из кэша, поэтому не считаются доказательством выбора upstream.")
        note.setObjectName("InfoNote"); note.setWordWrap(True); l.addWidget(note)
        stages=self.panel("Карта прохождения DNS → VPN","Статусы каждого этапа и автоматическая локализация вероятного места сбоя.")
        self.doh_stage_table=QTableWidget(11,3); self.doh_stage_table.setHorizontalHeaderLabels(["Этап","Статус","Что проверяется"])
        self.doh_stage_table.verticalHeader().setVisible(False); self.doh_stage_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.doh_stage_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.doh_stage_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents); self.doh_stage_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); self.doh_stage_table.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        for i,(name,detail) in enumerate([("DoH endpoint с ПК","Дополнительная независимая проверка RFC 8484 и TLS"),("Текущий DoH с MikroTik","Контрольный тест; отказ старого сервера не запрещает смену"),("Кандидат DoH с MikroTik","Обязательный RFC 8484 POST, TLS и корректный DNS-ответ"),("HTTPS/TLS активного хоста","Дополнительная проверка текущего хоста"),("DNS-резолвер MikroTik","Конфигурация и resolve; возможен ответ из кэша"),("LAN → DNS MikroTik / UDP","Обязательная проверка доступности DNS для клиентов"),("LAN → DNS MikroTik / TCP","Дополнительная проверка TCP/53; не блокирует смену DoH"),("Привязка домена к VPN","Состояние FWD и динамических IP; отдельно от DoH"),("Policy routing","Состояние Mangle; отдельно от DoH"),("WireGuard","Peer, handshake и RX/TX; отдельно от DoH"),("VPN-маршрут","Default route VPN-таблицы; отдельно от DoH")]):
            self.doh_stage_table.setItem(i,0,QTableWidgetItem(name)); self.doh_stage_table.setItem(i,1,QTableWidgetItem("ОЖИДАНИЕ")); self.doh_stage_table.setItem(i,2,QTableWidgetItem(detail))
        self.doh_stage_table.setMinimumHeight(300); stages.layout().addWidget(self.doh_stage_table); l.addWidget(stages)
        self.doh_diagnosis_verdict=QLabel("Запусти полную диагностику — здесь появится предполагаемое место сбоя."); self.doh_diagnosis_verdict.setObjectName("StatusBar"); self.doh_diagnosis_verdict.setWordWrap(True); l.addWidget(self.doh_diagnosis_verdict)
        report=self.panel("Подробный отчёт","Исходные ответы RouterOS и результат независимой проверки DoH.")
        self.doh_diag_text=QTextEdit(); self.doh_diag_text.setObjectName("DiagView"); self.doh_diag_text.setReadOnly(True); self.doh_diag_text.setAcceptRichText(False); self.doh_diag_text.setPlaceholderText("Подключись по SSH и запусти проверку."); self.doh_diag_text.setMinimumHeight(320)
        report.layout().addWidget(self.doh_diag_text,1); l.addWidget(report,1); return w

    def run_doh_diagnostic(self):
        self.run_doh_domain_diagnostic()

    def run_doh_domain_diagnostic(self):
        domain=self.doh_diag_domain.text().strip() if hasattr(self,"doh_diag_domain") else "chatgpt.com"
        if not domain: domain="chatgpt.com"
        try:
            normalized,kind=normalize_target(domain)
            if kind!="Домен": raise ValueError("Введи доменное имя, а не IP-адрес или CIDR.")
            domain=normalized
        except Exception as exc:
            QMessageBox.warning(self,"Некорректный домен",str(exc)); return
        endpoint=self.doh_test_endpoint.text().strip() if hasattr(self,"doh_test_endpoint") else "https://cloudflare-dns.com/dns-query"
        from urllib.parse import urlparse
        parsed=urlparse(endpoint)
        if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password:
            QMessageBox.warning(self,"Некорректный DoH endpoint","Укажи HTTPS URL без логина и пароля."); return
        def job():
            import urllib.request, urllib.error, ssl, struct, secrets, binascii
            parts=[f"DNS / DoH DIAGNOSTIC · {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}",f"Target domain: {domain}",f"Independent DoH endpoint (from this PC): {endpoint}","Protocol: RFC 8484 DNS wire format (POST application/dns-message)","Router configuration changed: no","Router-side HTTPS check is read-only; it does not change the active DoH endpoint.",""]
            doh_result="ERROR"
            try:
                ident=secrets.randbelow(65536)
                qname=b"".join(bytes([len(label)])+label.encode("idna") for label in domain.rstrip(".").split("."))+b"\x00"
                packet=struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+qname+struct.pack("!HH",1,1)
                req=urllib.request.Request(endpoint,data=packet,headers={"Content-Type":"application/dns-message","Accept":"application/dns-message","User-Agent":"MikroTik-VPN-Manager-Diagnostic/1.0"},method="POST")
                with urllib.request.urlopen(req,timeout=12,context=ssl.create_default_context()) as response:
                    answer=response.read(65536)
                    if response.status!=200 or len(answer)<12:
                        raise ValueError(f"Unexpected HTTP/DNS response: HTTP {response.status}, {len(answer)} bytes")
                    rid,flags,qdcount,ancount,nscount,arcount=struct.unpack("!HHHHHH",answer[:12])
                    rcode=flags & 0x000F
                    if rid!=ident: raise ValueError("DNS response ID does not match request")
                    if not (flags & 0x8000): raise ValueError("Response does not have DNS QR flag")
                    if rcode==0 and ancount>0:
                        doh_result="OK"
                    elif rcode==0:
                        doh_result="WARN"
                    else:
                        doh_result="WARN"
                    parts.extend(["▌ Independent DoH test · PC → endpoint","TLS certificate: verified",f"HTTP status: {response.status}",f"DNS response ID: {rid}",f"DNS RCODE: {rcode}",f"Answer records: {ancount}",f"Response bytes: {len(answer)}",f"Response (hex, first 256 bytes): {binascii.hexlify(answer[:256]).decode('ascii')}", ""])
                    if doh_result=="OK":
                        parts.append("DoH endpoint successfully returned a DNS answer using RFC 8484 wire format.")
                    else:
                        parts.append("Endpoint answered, but a positive DNS answer was not confirmed for this name.")
                    parts.append("")
            except urllib.error.HTTPError as exc:
                try: detail=exc.read(2048).decode("utf-8","replace")
                except Exception: detail=""
                doh_result="BAD"
                parts.extend(["▌ Independent DoH test · PC → endpoint",f"HTTP error: {exc.code} {exc.reason}",f"Response body: {detail or '(empty)'}","TLS connection was established far enough to receive an HTTP response; inspect endpoint path and DoH protocol support.",""])
            except Exception as exc:
                doh_result="BAD"
                parts.extend(["▌ Independent DoH test · PC → endpoint","ERROR: "+repr(exc),"TLS / HTTP / DNS wire-format request failed from this PC.",""])
            f=self.settings; alist=f.get("address_list",ADDRESS_LIST_DEFAULT)
            commands=[
                ("DNS configuration","/ip dns print"),
                ("Resolve selected domain",f":put [:resolve {ros_q(domain)}]"),
                ("Resolve google.com",':put [:resolve "google.com"]'),
                ("Resolve cloudflare.com",':put [:resolve "cloudflare.com"]'),
                ("DNS cache",f"/ip dns cache print terse where name~{ros_q(domain)}"),
                ("Managed FWD",f'/ip dns static print terse where comment={ros_q("VPN-MANAGER:"+domain)}'),
                ("Dynamic VPN IPs",f'/ip firewall address-list print terse where list={ros_q(alist)} and comment={ros_q("created for "+domain+".")}'),
                ("VPN address-list entries",f'/ip firewall address-list print count-only where list={ros_q(alist)}'),
                ("Managed Mangle counters",f'/ip firewall mangle print stats where comment={ros_q(MANGLE_COMMENT)}'),
                ("WireGuard peers",f'/interface wireguard peers print detail where interface={ros_q(f["wg_interface"])}'),
                ("VPN default route",f'/ip route print terse where dst-address=0.0.0.0/0 and routing-table={ros_q(f["route_table"])}'),
                ("Recent DNS errors",'/log print without-paging where topics~"dns,error"'),
            ]
            results={}
            try: r=self.router_conn()
            except Exception as exc:
                results["SSH"]="ERROR: "+str(exc)
                parts.extend(["▌ Router connection","ERROR: "+str(exc),""])
            else:
                for title,command in commands:
                    try: out=r.exec(command,timeout=20)
                    except Exception as exc: out="ERROR: "+str(exc)
                    results[title]=out
                    parts.extend([f"▌ {title}",f"$ {command}",out or "(пустой вывод)",""])
            def ok(key):
                v=results.get(key,"")
                return bool(v) and not v.startswith("ERROR:")
            dns_cfg=results.get("DNS configuration","")
            from urllib.parse import urlparse
            active_match=re.search(r"use-doh-server:\s*(https://[^\s]+)",dns_cfg,re.I)
            router_https="NOT_TESTED"
            router_https_detail="Активный DoH URL не найден в /ip dns print."
            if active_match:
                active_url=active_match.group(1).rstrip(",;")
                active_parsed=urlparse(active_url)
                if active_parsed.scheme=="https" and active_parsed.hostname:
                    probe_url=f"https://{active_parsed.hostname}/"
                    probe_cmd=f"/tool fetch url={ros_q(probe_url)} output=none check-certificate=yes as-value"
                    try:
                        probe_out=r.exec(":put ["+probe_cmd+"]",timeout=20)
                        parts.extend(["▌ Router-side DoH host transport check",f"$ :put [{probe_cmd}]",probe_out or "(пустой вывод)",""])
                        if re.search(r"status\s*[:=]\s*finished|finished",probe_out,re.I):
                            router_https="OK"
                            router_https_detail=f"HTTPS/TLS к {active_parsed.hostname} завершён; проверка сертификата включена."
                        else:
                            router_https="WARN"
                            router_https_detail="RouterOS fetch завершился без явного status=finished; смотри сырой вывод."
                    except Exception as exc:
                        router_https="FAIL"
                        router_https_detail=str(exc)
                        parts.extend(["▌ Router-side DoH host transport check",f"$ :put [{probe_cmd}]","ERROR: "+str(exc),""])
            else:
                parts.extend(["▌ Router-side DoH host transport check",router_https_detail,""])
            # Проверяем RFC 8484 непосредственно с MikroTik: POST DNS wire-format и TLS validation.
            def router_doh_probe(url):
                try:
                    pu=urlparse(url)
                    if pu.scheme!="https" or not pu.hostname: raise ValueError("Требуется HTTPS endpoint.")
                    probe_id=secrets.randbelow(65536)
                    qname=b"".join(bytes([len(x)])+x.encode("idna") for x in domain.rstrip(".").split("."))+b"\x00"
                    qpacket=struct.pack("!HHHHHH",probe_id,0x0100,1,0,0,0)+qname+struct.pack("!HH",1,1)
                    qhex=binascii.hexlify(qpacket).decode("ascii")
                    headers="Content-Type: application/dns-message,Accept: application/dns-message"
                    script=(f':local q [:convert from=hex to=raw {ros_q(qhex)}]; '
                            f':local r [/tool fetch url={ros_q(url)} http-method=post '
                            f'http-header-field={ros_q(headers)} http-data=$q output=user as-value check-certificate=yes]; '
                            ':put ("FETCH_STATUS=" . ($r->"status")); '
                            ':put ("HTTP_CODE=" . ($r->"code")); '
                            ':put ("DNS_HEX=" . [:convert from=raw to=hex ($r->"data")])')
                    out=r.exec(script,timeout=25)
                    sm=re.search(r"FETCH_STATUS\s*=\s*(\w+)",out,re.I)
                    cm=re.search(r"HTTP_CODE\s*=\s*(\d+)",out,re.I)
                    hm=re.search(r"DNS_HEX\s*=\s*([0-9a-fA-F]+)",out,re.I)
                    if not sm or sm.group(1).lower()!="finished": raise ValueError("RouterOS fetch не завершился: "+out)
                    if not cm or int(cm.group(1))!=200: raise ValueError("Ожидался HTTP 200: "+out)
                    if not hm: raise ValueError("RouterOS не вернул DNS wire response: "+out)
                    raw=bytes.fromhex(hm.group(1))
                    if len(raw)<12: raise ValueError("DNS-ответ короче заголовка.")
                    rid,flags,_,answers,_,_=struct.unpack("!HHHHHH",raw[:12])
                    rcode=flags & 0x000F
                    if rid!=probe_id or not (flags & 0x8000): raise ValueError("DNS ID/QR не совпали.")
                    if flags & 0x7800: raise ValueError("DNS response содержит неожиданный opcode.")
                    if flags & 0x0200: raise ValueError("DNS response усечён (TC=1).")
                    if rcode!=0 or answers<1: raise ValueError(f"DNS RCODE={rcode}; answers={answers}.")
                    return "OK",f"RFC 8484 POST с RouterOS: TLS certificate verified; HTTP 200; DNS ID matched; QR=1; TC=0; RCODE=0; answers={answers}; response={len(raw)} bytes."
                except Exception as exc:
                    return "FAIL",str(exc)
            active_url=active_match.group(1).rstrip(",;") if active_match else ""
            active_doh_state,active_doh_detail=router_doh_probe(active_url) if active_url else ("FAIL","Активный DoH URL не найден.")
            candidate_doh_state,candidate_doh_detail=router_doh_probe(endpoint)
            parts.extend(["▌ RouterOS → current active DoH · RFC 8484 POST",f"Endpoint: {active_url or '(not configured)'}",active_doh_detail,"",
                          "▌ RouterOS → candidate DoH · RFC 8484 POST",f"Endpoint: {endpoint}",candidate_doh_detail,""])
            resolve_out=results.get("Resolve selected domain","")
            router_resolve_ok=ok("Resolve selected domain") and bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",resolve_out))
            doh_configured=bool(active_match) and "verify-doh-cert: yes" in dns_cfg
            dns_ok=doh_configured and router_resolve_ok
            # Отдельный DNS-запрос с этого ПК непосредственно к LAN DNS MikroTik.
            lan_dns_state="WARN"
            lan_dns_detail="LAN DNS query was not completed."
            try:
                lan_dns=self.settings.get("lan_dns","").strip()
                if not lan_dns:
                    raise ValueError("LAN DNS IP не задан в настройках приложения.")
                query_id=secrets.randbelow(65536)
                qname=b"".join(bytes([len(label)])+label.encode("idna") for label in domain.rstrip(".").split("."))+b"\x00"
                dns_packet=struct.pack("!HHHHHH",query_id,0x0100,1,0,0,0)+qname+struct.pack("!HH",1,1)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns_sock:
                    dns_sock.settimeout(3)
                    dns_sock.sendto(dns_packet,(lan_dns,53))
                    dns_answer,_=dns_sock.recvfrom(4096)
                if len(dns_answer)<12:
                    raise ValueError("DNS-ответ короче заголовка.")
                answer_id,answer_flags,_,answer_count,_,_=struct.unpack("!HHHHHH",dns_answer[:12])
                answer_rcode=answer_flags & 0x000F
                if answer_id!=query_id or not (answer_flags & 0x8000):
                    raise ValueError("Получен некорректный или несоответствующий DNS-ответ.")
                if answer_rcode!=0:
                    raise ValueError(f"DNS RCODE={answer_rcode}.")
                lan_dns_state="OK" if answer_count>0 else "WARN"
                lan_dns_detail=f"Ответ от {lan_dns}:53; RCODE={answer_rcode}; Answer records={answer_count}."
            except Exception as exc:
                lan_dns_detail=str(exc)
            parts.extend(["▌ LAN client → MikroTik DNS / UDP",f"Target: {self.settings.get('lan_dns','(not configured)')}:53/UDP",lan_dns_detail,""])
            lan_dns_tcp_state="WARN"
            lan_dns_tcp_detail="TCP DNS query не выполнен."
            try:
                lan_dns=self.settings.get("lan_dns","").strip()
                if not lan_dns: raise ValueError("LAN DNS IP не задан в настройках приложения.")
                tcp_id=secrets.randbelow(65536)
                tcp_qname=b"".join(bytes([len(label)])+label.encode("idna") for label in domain.rstrip(".").split("."))+b"\x00"
                tcp_packet=struct.pack("!HHHHHH",tcp_id,0x0100,1,0,0,0)+tcp_qname+struct.pack("!HH",1,1)
                with socket.create_connection((lan_dns,53),timeout=4) as dns_tcp:
                    dns_tcp.settimeout(4)
                    dns_tcp.sendall(struct.pack("!H",len(tcp_packet))+tcp_packet)
                    prefix=dns_tcp.recv(2)
                    if len(prefix)!=2: raise ValueError("Не получен TCP DNS length prefix.")
                    expected=struct.unpack("!H",prefix)[0]
                    chunks=[]; remaining=expected
                    while remaining:
                        chunk=dns_tcp.recv(remaining)
                        if not chunk: raise ValueError("TCP DNS соединение закрыто до полного ответа.")
                        chunks.append(chunk); remaining-=len(chunk)
                    tcp_answer=b"".join(chunks)
                if len(tcp_answer)<12: raise ValueError("TCP DNS-ответ короче заголовка.")
                tcp_rid,tcp_flags,_,tcp_count,_,_=struct.unpack("!HHHHHH",tcp_answer[:12])
                tcp_rcode=tcp_flags & 0x000F
                if tcp_rid!=tcp_id or not (tcp_flags & 0x8000): raise ValueError("Некорректный TCP DNS-ответ.")
                if tcp_rcode!=0: raise ValueError(f"TCP DNS RCODE={tcp_rcode}.")
                lan_dns_tcp_state="OK" if tcp_count>0 else "WARN"
                lan_dns_tcp_detail=f"Ответ от {lan_dns}:53/TCP; RCODE={tcp_rcode}; Answer records={tcp_count}."
            except Exception as exc: lan_dns_tcp_detail=str(exc)
            parts.extend(["▌ LAN client → MikroTik DNS / TCP",f"Target: {self.settings.get('lan_dns','(not configured)')}:53/TCP",lan_dns_tcp_detail,""])
            fwd=ok("Managed FWD") and "type=FWD" in results.get("Managed FWD","")
            ips=ok("Dynamic VPN IPs") and "address=" in results.get("Dynamic VPN IPs","")
            mangle=ok("Managed Mangle counters") and "mark-routing" in results.get("Managed Mangle counters","")
            wg=ok("WireGuard peers") and "last-handshake=" in results.get("WireGuard peers","") and "rx=" in results.get("WireGuard peers","")
            route=ok("VPN default route") and bool(re.search(r"\bA",results.get("VPN default route",""))) and "routing-table=" in results.get("VPN default route","") and "gateway=" in results.get("VPN default route","")
            route_state="INFO"
            stages=[("DoH endpoint с ПК","INFO" if doh_result=="OK" else "WARN","Вспомогательная проверка с Windows; не заменяет тест с MikroTik"),
                    ("Текущий DoH с MikroTik","OK" if active_doh_state=="OK" else "INFO",active_doh_detail+" · контрольный тест, не блокирует переход"),
                    ("Кандидат DoH с MikroTik",candidate_doh_state,candidate_doh_detail),
                    ("HTTPS/TLS активного хоста","INFO" if router_https=="OK" else "WARN",router_https_detail),
                    ("DNS-резолвер MikroTik","OK" if dns_ok else "INFO","Текущая конфигурация/resolve; :resolve может использовать кэш и не доказывает upstream"),
                    ("LAN-клиент → DNS MikroTik / UDP",lan_dns_state,lan_dns_detail),
                    ("LAN-клиент → DNS MikroTik / TCP","OK" if lan_dns_tcp_state=="OK" else "WARN",lan_dns_tcp_detail+" · TCP/53 не является обязательным условием DoH"),
                    ("Привязка домена к VPN","INFO","FWD: "+str(fwd)+"; динамические IP: "+str(ips)+" · отдельно от пригодности DoH"),
                    ("Policy routing","INFO","Mangle mark-routing обнаружен: "+str(mangle)+" · отдельно от пригодности DoH"),
                    ("WireGuard","INFO","Peer/handshake/RX-TX обнаружены: "+str(wg)+" · отдельно от пригодности DoH"),
                    ("VPN-маршрут","INFO","Активный default route обнаружен: "+str(route)+" · отдельно от пригодности DoH")]
            self.q.put(("DOH_DIAGSTATUS",stages))
            if candidate_doh_state!="OK":
                verdict="НЕ МЕНЯТЬ DoH: кандидат не прошёл прямой RFC 8484 POST с MikroTik и проверку TLS-сертификата. Исправь endpoint, bootstrap DNS или доступ к HTTPS/443 и повтори тест."
            elif lan_dns_state!="OK":
                verdict="КАНДИДАТ DoH ДОСТУПЕН, НО СМЕНУ ПОКА НЕ РЕКОМЕНДУЮ: прямой тест с MikroTik прошёл, однако LAN-клиент не получил полноценный UDP DNS-ответ от роутера. Сначала проверь DNS-службу LAN."
            else:
                extras=[]
                if active_doh_state!="OK": extras.append("текущий DoH не прошёл контрольный тест")
                if lan_dns_tcp_state!="OK": extras.append("LAN TCP/53 не прошёл (это отдельное предупреждение)")
                if doh_result!="OK": extras.append("Windows-тест endpoint не прошёл/неполон")
                if not dns_ok: extras.append("текущая конфигурация или resolve не подтверждены; resolve может зависеть от кэша")
                verdict="КАНДИДАТ ПРОШЁЛ КЛЮЧЕВЫЕ ПРОВЕРКИ — СМЕНА ТЕХНИЧЕСКИ ОБОСНОВАНА: RouterOS установил TLS-соединение с проверкой сертификата, отправил RFC 8484 POST и получил валидный DNS-ответ; LAN-клиент получил UDP DNS-ответ. Перед переключением создай backup + export, затем примени endpoint и сразу повтори проверку. "+("; ".join(extras)+". " if extras else "")+"Тест подтверждает доступность и совместимость endpoint с RouterOS, но не гарантирует доступность сервиса в будущем и не доказывает upstream для каждого запроса, который мог обслуживаться из кэша."
            parts.extend(["▌ AUTOMATIC ASSESSMENT",verdict,""])
            self.q.put(("DOH_DIAGOUT","\n".join(parts)))
        self.run_job("Диагностика DNS → VPN (read-only)…",job)

    def check_doh_config(self):
        if hasattr(self,"nav"): self.nav.setCurrentRow(4)
        self.run_doh_domain_diagnostic()

    def save_doh_diagnostic_report(self):
        content=self.doh_diag_text.toPlainText().strip()
        if not content:
            QMessageBox.information(self,"Нет отчёта","Сначала запусти диагностику DNS / DoH."); return
        name=f"MikroTik-DNS-DoH-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        path,_=QFileDialog.getSaveFileName(self,"Сохранить отчёт DNS / DoH",str(Path.home()/name),"Текстовый отчёт (*.txt)")
        if not path:return
        try:
            Path(path).write_text(content,encoding="utf-8")
            QMessageBox.information(self,"Отчёт сохранён",f"Отчёт сохранён:\n{path}")
        except Exception as exc: QMessageBox.critical(self,"Ошибка сохранения",str(exc))

    def page_backups(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Резервные копии","Создаёт .backup и текстовый .rsc export на MikroTik, затем скачивает оба файла по SFTP на этот компьютер.")
        self.backup_dir=QLineEdit(str(Path.home()/"Documents"/"MikroTik Backups")); browse=QPushButton("Обзор…"); browse.clicked.connect(self.choose_backup_dir)
        row=QHBoxLayout(); row.addWidget(self.backup_dir,1); row.addWidget(browse); p.layout().addLayout(row)
        b=QPushButton("Создать и скачать backup + export"); b.setObjectName("PrimaryButton"); b.clicked.connect(self.backup_router); p.layout().addWidget(b)
        self.backup_info=QLabel("Перед созданием копии проверь свободное место на компьютере и роутере."); self.backup_info.setObjectName("Muted"); p.layout().addWidget(self.backup_info); p.layout().addStretch(); l.addWidget(p,1); return w

    def page_settings(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0)
        p=self.panel("Сетевые параметры","Здесь находятся параметры LAN, policy routing и WireGuard. SSH-авторизация вынесена в отдельное окно входа.")
        wizard=self.panel("Мастер настройки VPN-маршрутизации","1. Заполни параметры ниже. 2. Сохрани их и проверь роутер. 3. Мастер покажет существующие и недостающие объекты. 4. Подготовь создание и подтверди его в общей очереди.")
        wizard_row=QHBoxLayout()
        self.vpn_setup_status=QLabel("Ожидает проверки · подключись к MikroTik"); self.vpn_setup_status.setObjectName("StatusBar"); self.vpn_setup_status.setWordWrap(True)
        scan_btn=QPushButton("① Проверить роутер"); scan_btn.setObjectName("PrimaryButton"); scan_btn.clicked.connect(self.scan_vpn_setup)
        wizard_row.addWidget(self.vpn_setup_status,1); wizard_row.addWidget(scan_btn); wizard.layout().addLayout(wizard_row)
        self.vpn_setup_report=QPlainTextEdit(); self.vpn_setup_report.setReadOnly(True); self.vpn_setup_report.setMaximumHeight(190); self.vpn_setup_report.setPlaceholderText("Состояние routing table, default route, WireGuard, LAN, DHCP, Mangle и NAT.")
        wizard.layout().addWidget(self.vpn_setup_report)
        self.vpn_setup_stage=QPushButton("② Подготовить создание недостающих правил"); self.vpn_setup_stage.setObjectName("PrimaryButton"); self.vpn_setup_stage.setEnabled(False); self.vpn_setup_stage.clicked.connect(self.stage_vpn_setup)
        wizard.layout().addWidget(self.vpn_setup_stage)
        note=QLabel("Сторонние правила не удаляются и не перезаписываются. При FastTrack, конфликтующем маршруте или стороннем mark-routing мастер остановится. Все изменения сначала попадут в очередь и будут отправлены только после предпросмотра и подтверждения.")
        note.setObjectName("InfoNote"); note.setWordWrap(True); wizard.layout().addWidget(note); l.addWidget(wizard)
        form=QFormLayout(); self.inputs={}; form.setVerticalSpacing(12); form.setHorizontalSpacing(22); form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter); form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        fields=[("LAN bridge / интерфейс","lan_interface"),("LAN subnet","lan_subnet"),("LAN DNS IP","lan_dns"),("Routing table","route_table"),("WireGuard interface","wg_interface"),("WAN interface","wan_interface"),("Address-list","address_list")]
        for label,key in fields:
            e=QLineEdit(self.settings[key]); self.inputs[key]=e
            if key=="key_file":
                wrap=QWidget(); rr=QHBoxLayout(wrap); rr.setContentsMargins(0,0,0,0); rr.addWidget(e,1); bb=QPushButton("Выбрать ключ"); bb.clicked.connect(lambda _=False, x=e:self.choose_key(x)); rr.addWidget(bb); form.addRow(label,wrap)
            else: form.addRow(label,e)
        p.layout().addLayout(form)
        wg=self.panel("Профиль WireGuard / смена VPN-провайдера","Импортируй конфигурацию провайдера .conf или заполни поля вручную. Правила маршрутизации сохраняются.")
        wgform=QFormLayout(); self.wg_inputs={}
        for label,key in [("PrivateKey (секретный)","wg_private_key"),("PublicKey сервера","wg_public_key"),("Endpoint (домен/IP)","wg_endpoint"),("Endpoint port","wg_port"),("AllowedIPs","wg_allowed"),("Address интерфейса","wg_address"),("Persistent keepalive, сек.","wg_keepalive"),("MTU интерфейса","wg_mtu")]:
            e=QLineEdit("" if key=="wg_private_key" else self.settings.get(key,""))
            if key=="wg_private_key": e.setEchoMode(QLineEdit.EchoMode.Password); e.setPlaceholderText("Не сохраняется на диск")
            self.wg_inputs[key]=e; wgform.addRow(label,e)
        wg.layout().addLayout(wgform)
        wgbuttons=QHBoxLayout()
        imp=QPushButton("Импортировать .conf"); imp.clicked.connect(self.import_wireguard_conf)
        applywg=QPushButton("Применить новый VPN-профиль"); applywg.setObjectName("PrimaryButton"); applywg.clicked.connect(self.apply_wireguard_profile)
        wgbuttons.addWidget(imp); wgbuttons.addWidget(applywg); wg.layout().addLayout(wgbuttons)
        doh=self.panel("DNS-over-HTTPS · настройки резолвера","Выбери совместимый с RouterOS DoH-сервис. Пресет подставит HTTPS endpoint и bootstrap DNS IP; оба значения можно проверить и изменить вручную.")
        self.doh_enabled=QCheckBox("Использовать DoH")
        self.doh_enabled.setChecked(self.settings.get("doh_enabled","1")=="1")
        self.doh_preset=QComboBox()
        self.doh_preset.addItems(list(DOH_PRESETS.keys()) + ["Свой endpoint · вручную"])
        self.doh_url=QLineEdit(self.settings.get("doh_url","https://dns.google/dns-query"))
        self.doh_bootstrap=QLineEdit(self.settings.get("doh_bootstrap","8.8.8.8, 8.8.4.4"))
        self.doh_bootstrap.setPlaceholderText("Например: 8.8.8.8, 8.8.4.4")
        selected_preset=next((name for name,(url,_) in DOH_PRESETS.items() if url==self.doh_url.text().strip()),"Свой endpoint · вручную")
        self.doh_preset.setCurrentText(selected_preset)
        self.doh_preset.currentTextChanged.connect(self.select_doh_preset)
        self.doh_verify_cert=QCheckBox("Проверять TLS-сертификат DoH-сервера")
        self.doh_verify_cert.setChecked(self.settings.get("doh_verify_cert","1")=="1")
        dohform=QFormLayout(); dohform.addRow("Готовый пресет",self.doh_preset); dohform.addRow("DoH endpoint URL",self.doh_url); dohform.addRow("Bootstrap DNS · IPv4",self.doh_bootstrap); dohform.addRow("",self.doh_enabled); dohform.addRow("",self.doh_verify_cert); doh.layout().addLayout(dohform)
        dohrow=QHBoxLayout()
        apply_doh=QPushButton("Подготовить применение DoH"); apply_doh.setObjectName("PrimaryButton"); apply_doh.clicked.connect(self.stage_doh_config)
        check_doh=QPushButton("Проверить DoH на роутере"); check_doh.clicked.connect(self.check_doh_config)
        dohrow.addWidget(apply_doh); dohrow.addWidget(check_doh); doh.layout().addLayout(dohrow)
        doh_note=QLabel("Bootstrap DNS используется только для первоначального разрешения доменного имени DoH endpoint. После включения DoH RouterOS отправляет обычные DNS-запросы через выбранный HTTPS-сервис; автоматического отката на bootstrap DNS при отказе DoH нет. Для своего endpoint укажи доступные IPv4 DNS-серверы через запятую. Проверку TLS-сертификата оставляй включённой.")
        doh_note.setObjectName("InfoNote"); doh_note.setWordWrap(True); doh.layout().addWidget(doh_note); l.addWidget(doh)
        warning=QLabel("Будут изменены ключ интерфейса, параметры peer и адрес WG-интерфейса. Mangle, NAT, address-list и default route не меняются. Старый адрес на WG-интерфейсе заменяется, если указан новый Address. DNS из .conf не применяется: DNS-политика MikroTik остаётся прежней.")
        warning.setObjectName("InfoNote"); warning.setWordWrap(True); wg.layout().addWidget(warning); l.addWidget(wg)
        row=QHBoxLayout(); save=QPushButton("Сохранить параметры сети"); save.setObjectName("PrimaryButton"); save.clicked.connect(self.save_settings); row.addWidget(save); p.layout().addLayout(row); p.layout().addStretch(); l.addWidget(p,1); return w

    def scan_vpn_setup(self):
        try:
            self.save_settings(); f=dict(self.settings)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}",f["route_table"]): raise ValueError("Некорректное имя routing table.")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}",f["address_list"]): raise ValueError("Некорректное имя address-list.")
            ipaddress.ip_network(f["lan_subnet"],strict=False); ipaddress.ip_address(f["lan_dns"])
        except Exception as exc:
            QMessageBox.warning(self,"Проверь параметры",str(exc)); return
        self.vpn_setup_status.setText("Проверка выполняется…"); self.vpn_setup_stage.setEnabled(False)
        def job():
            r=self.router_conn(); d={}
            cmds=[
                ("table",f'/routing table print detail where name={ros_q(f["route_table"])}'),
                ("route",f'/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(f["route_table"])}'),
                ("wg",f'/interface wireguard print detail where name={ros_q(f["wg_interface"])}'),
                ("lan",f'/interface print detail where name={ros_q(f["lan_interface"])}'),
                ("dns","/ip dns print"),("dhcp","/ip dhcp-server network print detail"),
                ("mangle",f'/ip firewall mangle print detail where comment={ros_q(MANGLE_COMMENT)}'),
                ("all_mangle","/ip firewall mangle print detail"),("nat","/ip firewall nat print detail"),
                ("fasttrack",'/ip firewall filter print detail where action=fasttrack-connection')]
            for k,c in cmds: d[k]=r.exec(c,timeout=20)
            table=bool(d["table"].strip()); route=bool(d["route"].strip()) and f'gateway={f["wg_interface"]}' in d["route"] and "inactive" not in d["route"].lower()
            wg=bool(d["wg"].strip()); lan=bool(d["lan"].strip()); dns="allow-remote-requests: yes" in d["dns"]
            dhcp=f'dns-server={f["lan_dns"]}' in d["dhcp"].replace(" ","")
            mc=r.exec(f'/ip firewall mangle print count-only where comment={ros_q(MANGLE_COMMENT)}').strip()
            nat=f'out-interface={f["wg_interface"]}' in d["nat"] and "action=masquerade" in d["nat"] and f'src-address={f["lan_subnet"]}' in d["nat"]
            fast=bool(d["fasttrack"].strip()); foreign="action=mark-routing" in d["all_mangle"] and MANGLE_COMMENT not in d["all_mangle"]
            blockers=[]
            for ok,msg in [(wg,"WireGuard-интерфейс не найден"),(lan,"LAN-интерфейс не найден"),(dns,"allow-remote-requests выключен"),(dhcp,f"DHCP не выдаёт DNS {f['lan_dns']}"),(not fast,"Обнаружен FastTrack"),(not foreign,"Обнаружены сторонние mark-routing правила"),(mc in ("0","1"),"Найдено несколько управляемых Mangle-правил"),(not d["route"].strip() or route,"В VPN-таблице есть конфликтующий default route")]:
                if not ok: blockers.append(msg)
            lines=[
                f'{"✓" if table else "＋"} Таблица {f["route_table"]}: {"есть" if table else "будет создана"}',
                f'{"✓" if route else "＋"} Default route через {f["wg_interface"]}: {"активен" if route else "отсутствует"}',
                f'{"✓" if wg else "✕"} WireGuard {f["wg_interface"]}: {"найден" if wg else "НЕ НАЙДЕН"}',
                f'{"✓" if lan else "✕"} LAN {f["lan_interface"]}: {"найден" if lan else "НЕ НАЙДЕН"}',
                f'{"✓" if dns else "✕"} DNS remote requests: {"включён" if dns else "выключен"}',
                f'{"✓" if dhcp else "✕"} DHCP DNS {f["lan_dns"]}: {"совпадает" if dhcp else "не совпадает"}',
                f'{"✓" if mc=="1" else "＋"} Управляемое Mangle: {mc or "0"}',
                f'{"✓" if nat else "＋"} NAT masquerade: {"найден" if nat else "отсутствует"}',
                f'{"⚠" if fast else "✓"} FastTrack: {"обнаружен" if fast else "не обнаружен"}',
                f'{"⚠" if foreign else "✓"} Сторонний mark-routing: {"обнаружен" if foreign else "не обнаружен"}']
            self.q.put(("VPN_SETUP_SCAN",{"lines":lines,"blockers":blockers,"ready":not blockers}))
        self.run_job("Сканирование VPN-маршрутизации…",job)

    def on_vpn_setup_scan(self,payload):
        self.vpn_setup_scan_result=payload
        report="\n".join(payload["lines"])
        if payload["blockers"]: report+="\n\nТРЕБУЕТ ВНИМАНИЯ:\n• "+"\n• ".join(payload["blockers"])
        else: report+="\n\nПрепятствий нет. Можно подготовить создание недостающих объектов."
        self.vpn_setup_report.setPlainText(report)
        self.vpn_setup_status.setText("Проверка завершена · готово к настройке" if payload["ready"] else "Есть препятствия · исправь их и повтори проверку")
        self.vpn_setup_stage.setEnabled(payload["ready"])

    def stage_vpn_setup(self):
        result=getattr(self,"vpn_setup_scan_result",None)
        if not result or not result.get("ready"):
            QMessageBox.warning(self,"Нужна проверка","Сначала выполни проверку роутера."); return
        self.queue_change("setup_vpn_routing","Создать недостающую инфраструктуру VPN-маршрутизации")
        self.vpn_setup_stage.setEnabled(False)
        self.vpn_setup_status.setText("Добавлено в очередь · открой предпросмотр изменений")

    def page_terminal(self):
        w=QWidget(); l=QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(14)
        panel=QFrame(); panel.setObjectName("Panel")
        pl=QVBoxLayout(panel); pl.setContentsMargins(20,20,20,18); pl.setSpacing(14)

        bar=QHBoxLayout(); bar.setSpacing(12)
        heading=QVBoxLayout(); heading.setSpacing(4)
        title=QLabel("RouterOS CLI"); title.setObjectName("SectionTitle")
        subtitle=QLabel("Интерактивная командная строка MikroTik через текущее SSH-подключение")
        subtitle.setObjectName("Muted")
        heading.addWidget(title); heading.addWidget(subtitle); bar.addLayout(heading,1)
        terminal_tag=QLabel("SSH  /  ROUTEROS")
        terminal_tag.setObjectName("TerminalTag")
        bar.addWidget(terminal_tag,0,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
        copy_btn=QPushButton("Копировать вывод"); copy_btn.setObjectName("QuietButton")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.terminal_output.toPlainText()))
        clear_btn=QPushButton("Очистить вывод"); clear_btn.setObjectName("QuietButton")
        clear_btn.clicked.connect(lambda: self.terminal_output.clear())
        bar.addWidget(copy_btn); bar.addWidget(clear_btn); pl.addLayout(bar)

        self.terminal_output=QPlainTextEdit()
        self.terminal_output.setObjectName("TerminalOutput")
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.terminal_output.setPlaceholderText("Здесь появятся команды и ответы RouterOS…")
        self.terminal_output.setMinimumHeight(330)
        self.terminal_output.setStyleSheet("QPlainTextEdit#TerminalOutput { background:#030914; color:#c9d7e8; border:1px solid #263d5d; border-radius:14px; padding:16px; font-family:'Cascadia Mono','Consolas',monospace; font-size:10pt; selection-background-color:#244b82; }")
        pl.addWidget(self.terminal_output,1)

        command_header=QHBoxLayout()
        command_caption=QLabel("КОМАНДА")
        command_caption.setObjectName("TerminalCaption")
        self.terminal_history_hint=QLabel("↑ / ↓  история команд   ·   Enter  выполнить")
        self.terminal_history_hint.setObjectName("TerminalHint")
        self.terminal_risk_badge=QLabel("ОЖИДАНИЕ КОМАНДЫ"); self.terminal_risk_badge.setObjectName("TerminalRiskBadge")
        self.terminal_expert_mode=QCheckBox("Режим эксперта")
        self.terminal_expert_mode.setToolTip("В экспертном режиме подтверждения для изменяющих и неизвестных команд пропускаются. Индикатор риска остаётся активным.")
        self.terminal_expert_mode.setChecked(False)
        self.terminal_expert_mode.toggled.connect(self.update_terminal_command_hint)
        command_header.addWidget(command_caption); command_header.addStretch(1)
        command_header.addWidget(self.terminal_risk_badge); command_header.addWidget(self.terminal_expert_mode); command_header.addWidget(self.terminal_history_hint)
        pl.addLayout(command_header)

        command_row=QHBoxLayout(); command_row.setSpacing(10)
        prompt=QLabel(">")
        prompt.setObjectName("TerminalPrompt")
        self.terminal_input=TerminalCommandInput()
        self.terminal_input.setObjectName("TerminalCommandInput")
        self.terminal_input.setPlaceholderText("/system resource print")
        self.terminal_input.setClearButtonEnabled(True)
        self.terminal_input.set_history(getattr(self,"terminal_history",[]))
        self.terminal_input.returnPressed.connect(self.terminal_execute)
        self.terminal_input.textChanged.connect(self.update_terminal_command_hint)
        self.terminal_input.textChanged.connect(self.update_terminal_parameter_hint)
        self.terminal_completer_model=QStringListModel(self)
        self.terminal_completer=QCompleter(self.terminal_completer_model,self.terminal_input)
        self.terminal_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.terminal_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.terminal_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.terminal_input.setCompleter(self.terminal_completer)
        self.terminal_completer.popup().setObjectName("TerminalCompletionPopup")
        self.terminal_completer.popup().setStyleSheet("""
            QListView#TerminalCompletionPopup { background:#0b1627; color:#dce7f8; border:1px solid #365273;
                border-radius:9px; padding:5px; outline:0; selection-background-color:#244b7b; selection-color:#fff; }
            QListView#TerminalCompletionPopup::item { background:#0b1627; color:#dce7f8; padding:7px 10px; border-bottom:1px solid #1b2d45; }
            QListView#TerminalCompletionPopup::item:hover { background:#172a45; color:#fff; }
            QListView#TerminalCompletionPopup::item:selected { background:#244b7b; color:#fff; }
        """)
        self.terminal_parameter_hint=QLabel("Автодополнение RouterOS появится при вводе раздела.")
        self.terminal_parameter_hint.setObjectName("TerminalHint")
        pl.addWidget(self.terminal_parameter_hint)
        self.terminal_completer_model.setStringList(self.terminal_completion_candidates())
        execute=QPushButton("Выполнить  ↵"); execute.setObjectName("PrimaryButton"); execute.setMinimumWidth(142); execute.clicked.connect(self.terminal_execute)
        command_row.addWidget(prompt); command_row.addWidget(self.terminal_input,1); command_row.addWidget(execute)
        pl.addLayout(command_row)

        quick=self.panel("Избранное и наборы команд","Сохранённые команды только подставляются в строку и не запускаются автоматически.")
        qr=QHBoxLayout()
        self.terminal_favorites=QComboBox()
        fav_add=QPushButton("★ В избранное"); fav_add.clicked.connect(self.add_terminal_favorite)
        fav_use=QPushButton("Вставить"); fav_use.clicked.connect(self.insert_terminal_favorite)
        self.terminal_sets_combo=QComboBox()
        set_add=QPushButton("Сохранить набор"); set_add.clicked.connect(self.add_terminal_set)
        set_use=QPushButton("Вставить набор"); set_use.clicked.connect(self.insert_terminal_set)
        set_del=QPushButton("Удалить набор"); set_del.clicked.connect(self.delete_terminal_set)
        qr.addWidget(self.terminal_favorites,2); qr.addWidget(fav_use); qr.addWidget(fav_add)
        qr.addWidget(self.terminal_sets_combo,1); qr.addWidget(set_use); qr.addWidget(set_add); qr.addWidget(set_del)
        quick.layout().addLayout(qr)
        l.addWidget(panel,1); l.addWidget(quick)
        note=QLabel("Перед выполнением приложение оценивает риск команды. Изменяющие и неизвестные команды требуют подтверждения; опасные операции выделяются отдельно. Режим «Только чтение» блокирует всё, что не распознано как безопасный запрос. Ручной ввод CLI сохранён.")
        note.setObjectName("InfoNote"); note.setWordWrap(True); l.addWidget(note)

        guides=self.panel("Справочник команд RouterOS","Выбери команду, посмотри назначение и типичный результат. Нажатие «Вставить» только переносит текст в CLI.")
        filters=QHBoxLayout()
        self.ros_guide_category=QComboBox()
        self.ros_guide_category.addItems(["Все разделы","Обзор и система","Интерфейсы и IP","Маршрутизация","Firewall и NAT","DNS","WireGuard","Диагностика"])
        self.ros_guide_search=QLineEdit(); self.ros_guide_search.setPlaceholderText("Поиск по названию или команде…"); self.ros_guide_search.setClearButtonEnabled(True)
        filters.addWidget(self.ros_guide_category); filters.addWidget(self.ros_guide_search,1); guides.layout().addLayout(filters)
        guide_split=QSplitter(Qt.Orientation.Horizontal)
        guide_split.setObjectName("RosGuideSplitter")
        guide_split.setStyleSheet("QSplitter#RosGuideSplitter { background:#080f1d; border:0; } QSplitter#RosGuideSplitter::handle { background:#243957; width:2px; }")
        self.ros_guide_list=QListWidget(); self.ros_guide_list.setObjectName("RosGuideList"); self.ros_guide_list.setMinimumWidth(260); self.ros_guide_list.setMaximumWidth(420)
        self.ros_guide_list.setStyleSheet("QListWidget#RosGuideList { background:#0a1424; color:#dce7f8; border:1px solid #2b4163; border-radius:12px; padding:6px; outline:0; } QListWidget#RosGuideList::item { background:transparent; color:#dce7f8; padding:10px 9px; border-radius:7px; border-bottom:1px solid #1b2b43; } QListWidget#RosGuideList::item:hover { background:#142641; } QListWidget#RosGuideList::item:selected { background:#23477b; color:#ffffff; }")
        self.ros_guide_details=QTextEdit(); self.ros_guide_details.setObjectName("RosGuideDetails"); self.ros_guide_details.setReadOnly(True); self.ros_guide_details.setAcceptRichText(False); self.ros_guide_details.setPlaceholderText("Выбери команду слева.")
        self.ros_guide_details.setStyleSheet("QTextEdit#RosGuideDetails { background:#080f1d; color:#dce7f8; border:1px solid #2b4163; border-radius:12px; padding:14px; selection-background-color:#244b82; }")
        guide_split.addWidget(self.ros_guide_list); guide_split.addWidget(self.ros_guide_details); guide_split.setStretchFactor(0,1); guide_split.setStretchFactor(1,2)
        guide_split.setMinimumHeight(230); guides.layout().addWidget(guide_split)
        guide_actions=QHBoxLayout()
        self.ros_guide_insert=QPushButton("Вставить в терминал"); self.ros_guide_insert.setObjectName("PrimaryButton"); self.ros_guide_insert.clicked.connect(self.insert_ros_guide_command)
        guide_copy=QPushButton("Копировать команду"); guide_copy.clicked.connect(self.copy_ros_guide_command)
        guide_actions.addStretch(); guide_actions.addWidget(guide_copy); guide_actions.addWidget(self.ros_guide_insert); guides.layout().addLayout(guide_actions)
        l.addWidget(guides)
        self.ros_guide_category.currentTextChanged.connect(self.filter_ros_guides)
        self.ros_guide_search.textChanged.connect(self.filter_ros_guides)
        self.ros_guide_list.currentItemChanged.connect(self.show_ros_guide_details)
        self.populate_ros_guides()
        self.refresh_terminal_quick_access()
        return w

    def terminal_completion_candidates(self):
        base=["/system resource print","/system identity print","/interface print detail","/ip address print detail",
        "/ip route print detail","/routing table print detail","/routing rule print detail",
        "/ip firewall filter print detail","/ip firewall nat print detail","/ip firewall mangle print detail",
        "/ip firewall address-list print detail","/ip dns print","/ip dns static print detail","/ip dns cache print",
        "/interface wireguard print detail","/interface wireguard peers print detail","/ip neighbor print detail",
        "/ip dhcp-server lease print detail","/ip service print","/user print","/log print",
        "/ping 1.1.1.1 count=4","/resolve example.com","/tool traceroute 1.1.1.1"]
        return sorted(set(base+[x[2] for x in getattr(self,"ros_guides",[])]),key=str.casefold)

    def update_terminal_parameter_hint(self, command):
        if not hasattr(self,"terminal_parameter_hint"): return
        low=command.strip().lower()
        hints=[("/ip firewall filter","Filter: chain, action, protocol, src/dst-address, in/out-interface, comment, disabled."),
        ("/ip firewall nat","NAT: chain, action, protocol, src/dst-address, to-addresses, to-ports, out-interface."),
        ("/ip firewall mangle","Mangle: chain, action, src/dst-address, in/out-interface, connection-mark, new-routing-mark, passthrough."),
        ("/ip route","Route: dst-address, gateway, routing-table, distance, check-gateway, disabled."),
        ("/ip address","IP address: address, network, interface, disabled."),
        ("/ip dns","DNS: servers, use-doh-server, verify-doh-cert, allow-remote-requests."),
        ("/interface wireguard","WireGuard: name, listen-port, mtu; peer: public-key, endpoint-address/port, allowed-address, persistent-keepalive.")]
        hint=next((v for k,v in hints if low.startswith(k)),None)
        self.terminal_parameter_hint.setText(hint or "Автодополнение по справочнику RouterOS. Выбор подсказки не выполняет команду.")

    def refresh_terminal_quick_access(self):
        if not hasattr(self,"terminal_favorites"): return
        try: fav=json.loads(self.settings.get("terminal_favorites","[]"))
        except Exception: fav=[]
        self.terminal_favorites.clear()
        for item in fav if isinstance(fav,list) else []:
            if isinstance(item,dict) and item.get("name") and item.get("command"): self.terminal_favorites.addItem(item["name"],item["command"])
        try: sets=json.loads(self.settings.get("terminal_sets","{}"))
        except Exception: sets={}
        self.terminal_sets_combo.clear()
        for name in sorted(sets if isinstance(sets,dict) else {}): self.terminal_sets_combo.addItem(name)

    def add_terminal_favorite(self):
        command=self.terminal_input.text().strip()
        if not command: return
        name,ok=QInputDialog.getText(self,"Избранное","Название команды:",text=command[:48])
        if not ok or not name.strip(): return
        try: fav=json.loads(self.settings.get("terminal_favorites","[]"))
        except Exception: fav=[]
        fav=[x for x in fav if x.get("command")!=command]; fav.append({"name":name.strip(),"command":command})
        self.settings["terminal_favorites"]=json.dumps(fav,ensure_ascii=False); self.save_settings(); self.refresh_terminal_quick_access()

    def insert_terminal_favorite(self):
        command=self.terminal_favorites.currentData()
        if command: self.terminal_input.setText(command); self.terminal_input.setFocus()

    def add_terminal_set(self):
        name,ok=QInputDialog.getText(self,"Набор команд","Название набора:")
        if not ok or not name.strip(): return
        raw,ok=QInputDialog.getMultiLineText(self,"Команды набора","Одна команда на строку. Набор не запускается автоматически:")
        if not ok: return
        commands=[x.strip() for x in raw.splitlines() if x.strip() and not x.strip().startswith("#")]
        if not commands: return
        try: sets=json.loads(self.settings.get("terminal_sets","{}"))
        except Exception: sets={}
        sets[name.strip()]=commands; self.settings["terminal_sets"]=json.dumps(sets,ensure_ascii=False)
        self.save_settings(); self.refresh_terminal_quick_access(); self.terminal_sets_combo.setCurrentText(name.strip())

    def insert_terminal_set(self):
        name=self.terminal_sets_combo.currentText()
        try: sets=json.loads(self.settings.get("terminal_sets","{}"))
        except Exception: sets={}
        commands=sets.get(name,[])
        if not commands: return
        if len(commands)==1: chosen=commands[0]
        else:
            chosen,ok=QInputDialog.getItem(self,"Выбрать команду из набора",f"Набор «{name}» · {len(commands)} команд:",commands,0,False)
            if not ok: return
        self.terminal_input.setText(chosen); self.terminal_input.setFocus()

    def delete_terminal_set(self):
        name=self.terminal_sets_combo.currentText()
        if not name: return
        if QMessageBox.question(self,"Удалить набор",f"Удалить «{name}»?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        try: sets=json.loads(self.settings.get("terminal_sets","{}"))
        except Exception: sets={}
        sets.pop(name,None); self.settings["terminal_sets"]=json.dumps(sets,ensure_ascii=False)
        self.save_settings(); self.refresh_terminal_quick_access()

    def populate_ros_guides(self):
        self.ros_guides = [
            ("Обзор и система","Версия RouterOS","/system resource print","Показывает версию RouterOS, архитектуру, uptime, объём RAM и загрузку CPU.","Только чтение","В выводе ищи version, uptime, cpu-load, free-memory и total-memory."),
            ("Обзор и система","Идентификатор роутера","/system identity print","Показывает системное имя устройства.","Только чтение","Обычно выводит name= и текущее имя MikroTik."),
            ("Обзор и система","Список пользователей","/user print","Показывает локальные учётные записи и группы пользователей.","Только чтение","Не показывает пароли. Проверяй наличие лишних учётных записей и чрезмерных прав."),
            ("Обзор и система","Активные подключения","/ip service print","Показывает включённые управляющие службы и их порты.","Только чтение","Проверь, какие сервисы доступны и ограничено ли поле address."),
            ("Интерфейсы и IP","Список интерфейсов","/interface print detail","Подробный список физических и виртуальных интерфейсов.","Только чтение","Флаги R обычно означают running; проверь имена LAN, WAN и WireGuard."),
            ("Интерфейсы и IP","IP-адреса интерфейсов","/ip address print detail","Показывает IP-адреса и интерфейсы, к которым они привязаны.","Только чтение","Сверь адреса и префиксы с планом сети."),
            ("Интерфейсы и IP","Состояние DHCP-клиента","/ip dhcp-client print detail","Показывает DHCP-клиенты, их интерфейсы и полученные параметры.","Только чтение","Ищи status=bound и корректный gateway."),
            ("Маршрутизация","Таблица маршрутов IPv4","/ip route print detail","Показывает маршруты, шлюзы, таблицы и флаги активности.","Только чтение","Проверь активный default route (0.0.0.0/0), gateway и routing-table."),
            ("Маршрутизация","Таблицы маршрутизации","/routing table print detail","Показывает созданные таблицы policy routing.","Только чтение","Убедись, что используемая таблица существует и имеет fib=yes."),
            ("Маршрутизация","Правила routing rules","/routing rule print detail","Показывает правила выбора таблиц маршрутизации.","Только чтение","Полезно при поиске конфликта между routing rules и mangle."),
            ("Firewall и NAT","Правила Filter","/ip firewall filter print stats","Показывает фильтрующие правила и счётчики пакетов/байт.","Только чтение","Смотри порядок правил, chain, action и растущие counters."),
            ("Firewall и NAT","Правила NAT","/ip firewall nat print stats","Показывает NAT-правила и счётчики.","Только чтение","Для masquerade проверь chain=srcnat, out-interface и счётчики."),
            ("Firewall и NAT","Правила Mangle","/ip firewall mangle print stats","Показывает правила обработки пакетов и счётчики.","Только чтение","Для policy routing проверь mark-routing, условия совпадения и packets/bytes."),
            ("Firewall и NAT","FastTrack","/ip firewall filter print detail where action=fasttrack-connection","Находит правила FastTrack, которые могут влиять на policy routing.","Только чтение","Проверь, не обходят ли FastTrack-пакеты требуемую обработку mangle."),
            ("DNS","Настройки DNS","/ip dns print","Показывает DNS-серверы, DoH и параметры DNS-службы.","Только чтение","Проверь servers, use-doh-server, verify-doh-cert и allow-remote-requests."),
            ("DNS","Статические DNS-записи","/ip dns static print detail","Показывает статические DNS-записи, включая FWD.","Только чтение","Ищи name, type, address-list и match-subdomain."),
            ("DNS","DNS-кэш","/ip dns cache print","Показывает записи, находящиеся в DNS-кэше.","Только чтение","Кэш динамический; отсутствие записи не доказывает отсутствие DNS-запросов."),
            ("WireGuard","Интерфейсы WireGuard","/interface wireguard print detail","Показывает WireGuard-интерфейсы и их параметры без приватного ключа.","Только чтение","Проверь listen-port, mtu и наличие нужного интерфейса."),
            ("WireGuard","Peers WireGuard","/interface wireguard peers print detail","Показывает peer, endpoint, allowed-address и состояние handshake.","Только чтение","Смотри last-handshake, rx и tx; публичный ключ не является секретом."),
            ("Диагностика","Ping адреса","/ping 1.1.1.1 count=4","Отправляет четыре ICMP-запроса к публичному IPv4-адресу.","Только чтение","Проверь packet-loss и время ответа; ICMP может фильтроваться."),
            ("Диагностика","DNS resolve","/resolve example.com","Разрешает доменное имя средствами RouterOS.","Только чтение","Показывает IP-адрес или ошибку разрешения имени."),
            ("Диагностика","Traceroute","/tool traceroute 1.1.1.1","Показывает маршрут до указанного IPv4-адреса.","Только чтение","Звёздочки не всегда означают обрыв: промежуточные узлы могут не отвечать."),
            ("Диагностика","Соседи L2","/ip neighbor print detail","Показывает обнаруженные устройства в локальном сегменте.","Только чтение","Состав зависит от включённых discovery-протоколов и интерфейсов."),
            ("Firewall и NAT","Отключить правило по номеру","/ip firewall filter disable [find where comment=\"УКАЖИ_КОММЕНТАРИЙ\"]","Отключает найденное правило Filter по комментарию. Замени placeholder на точный комментарий.","ИЗМЕНЯЕТ КОНФИГУРАЦИЮ","Перед запуском проверь точное совпадение find и сделай backup; не отключай правила управления/защиты наугад."),
            ("DNS","Очистить DNS-кэш","/ip dns cache flush","Очищает динамический DNS-кэш роутера.","ИЗМЕНЯЕТ СОСТОЯНИЕ","Не удаляет статические DNS-записи, но временно заставляет имена разрешаться заново."),
        ]
        self.filter_ros_guides()
        if hasattr(self,"terminal_completer_model"): self.terminal_completer_model.setStringList(self.terminal_completion_candidates())

    def filter_ros_guides(self):
        if not hasattr(self,"ros_guide_list"): return
        category=self.ros_guide_category.currentText()
        needle=self.ros_guide_search.text().strip().casefold()
        current=self.ros_guide_list.currentItem()
        current_command=current.data(Qt.ItemDataRole.UserRole) if current else None
        self.ros_guide_list.clear()
        selected=None
        for entry in self.ros_guides:
            cat,name,command,description,risk,result=entry
            if category!="Все разделы" and category!=cat: continue
            if needle and needle not in " ".join(entry).casefold(): continue
            item=QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole,entry)
            if risk.startswith("ИЗМЕНЯЕТ"): item.setForeground(QColor("#fbbf24"))
            self.ros_guide_list.addItem(item)
            if current_command and command==current_command: selected=item
        if selected: self.ros_guide_list.setCurrentItem(selected)
        elif self.ros_guide_list.count(): self.ros_guide_list.setCurrentRow(0)
        else: self.ros_guide_details.clear(); self.ros_guide_insert.setEnabled(False)

    def show_ros_guide_details(self,item,_previous=None):
        if not item:
            self.ros_guide_details.clear(); self.ros_guide_insert.setEnabled(False); return
        cat,name,command,description,risk,result=item.data(Qt.ItemDataRole.UserRole)
        self.ros_guide_details.setPlainText(f"{name}\nРаздел: {cat}\nТип: {risk}\n\nКоманда:\n{command}\n\nНазначение:\n{description}\n\nЧто смотреть в результате:\n{result}")
        self.ros_guide_insert.setEnabled(True)

    def insert_ros_guide_command(self):
        item=self.ros_guide_list.currentItem()
        if not item: return
        entry=item.data(Qt.ItemDataRole.UserRole)
        self.terminal_input.setText(entry[2]); self.terminal_input.setFocus(); self.terminal_input.end(False)

    def copy_ros_guide_command(self):
        item=self.ros_guide_list.currentItem()
        if item: QApplication.clipboard().setText(item.data(Qt.ItemDataRole.UserRole)[2])


    def update_terminal_command_hint(self, *_):
        if not hasattr(self,"terminal_risk_badge"): return
        command=self.terminal_input.text().strip()
        if not command:
            self.terminal_risk_badge.setText("ОЖИДАНИЕ КОМАНДЫ")
            self.terminal_risk_badge.setStyleSheet("color:#91a9cc;background:#142238;border:1px solid #304764;border-radius:8px;padding:5px 9px;font-size:8pt;font-weight:800")
            return
        level,label,_reason=classify_routeros_command(command)
        colors={"read":("#8ce9c5","#10372f","#267a62"),"change":("#ffd58a","#3b2b12","#a87527"),"critical":("#ffb3bd","#431b25","#a64254"),"unknown":("#ffd58a","#3b2b12","#a87527")}
        fg,bg,border=colors.get(level,("#91a9cc","#142238","#304764"))
        suffix=" · ЭКСПЕРТ" if self.terminal_expert_mode.isChecked() and level in ("change","critical","unknown") else ""
        self.terminal_risk_badge.setText(label.upper()+suffix)
        self.terminal_risk_badge.setStyleSheet(f"color:{fg};background:{bg};border:1px solid {border};border-radius:8px;padding:5px 9px;font-size:8pt;font-weight:800")

    def terminal_execute(self):
        if self.busy:
            self.status.setText("●  Дождись завершения текущей операции.")
            return
        command=self.terminal_input.text().strip()
        if not command: return
        level,risk_label,risk_reason=classify_routeros_command(command)
        if level=="empty": return
        if level in ("change","critical","unknown") and not self.terminal_expert_mode.isChecked():
            details={"change":"Команда изменяет конфигурацию или состояние устройства.","critical":"Команда может нарушить доступ к роутеру, изменить критичные сетевые настройки или привести к потере данных.","unknown":"Команда не распознана как безопасная. Считай её потенциально изменяющей до проверки."}[level]
            box=QtMessageBox(self)
            box.setIcon(QtMessageBox.Icon.Warning if level!="critical" else QtMessageBox.Icon.Critical)
            box.setWindowTitle("Подтверждение команды RouterOS")
            box.setText(f"Категория риска: {risk_label}")
            box.setInformativeText(details+"\n\n"+risk_reason+"\n\nКоманда будет отправлена без автоматического изменения её текста.")
            box.setDetailedText(command)
            box.setStandardButtons(QtMessageBox.StandardButton.Yes|QtMessageBox.StandardButton.No)
            box.setDefaultButton(QtMessageBox.StandardButton.No)
            box.button(QtMessageBox.StandardButton.Yes).setText("Выполнить")
            box.button(QtMessageBox.StandardButton.No).setText("Отмена")
            if box.exec()!=QtMessageBox.StandardButton.Yes:
                self.log("Выполнение команды отменено пользователем.")
                return
        if not hasattr(self,"terminal_history"):
            self.terminal_history=[]
        if not self.terminal_history or self.terminal_history[-1] != command:
            self.terminal_history.append(command)
            self.terminal_history=self.terminal_history[-200:]
        self.terminal_input.set_history(self.terminal_history)
        self.terminal_input.history_index=len(self.terminal_history)
        self.terminal_input.draft=""
        self.terminal_input.clear()
        stamp=datetime.now().strftime("%H:%M:%S")
        self.terminal_output.appendPlainText(f"\n[{stamp}] $ {command}")
        self.terminal_output.moveCursor(QTextCursor.MoveOperation.End)
        self.terminal_history_hint.setText(f"↑ / ↓  история команд · {len(self.terminal_history)}")
        def job():
            try:
                r=self.router_conn()
                result=r.exec(command,timeout=60)
                self.q.put(("TERMOUT",result or "(пустой вывод)"))
            except Exception as e:
                self.q.put(("TERMOUT","ОШИБКА: "+str(e)))
        self.run_job("RouterOS CLI: "+command,job)

    def pages_changed(self,index):
        titles=[("Обзор сети","Состояние маршрутизатора и VPN-туннеля"),("VPN-маршрутизация","Домены, IPv4 и сети, направляемые через WireGuard"),("Диагностика","Проверки соединения и сетевой доступности"),("Конструктор Firewall","Filter, NAT и Mangle · просмотр и управление правилами"),("Диагностика DNS / DoH","Проверка резолвера, DNS FWD, IP-адресов и VPN-маршрута"),("Резервные копии","Локальное сохранение конфигурации MikroTik"),("Настройки","SSH и профиль VPN-провайдера"),("Терминал RouterOS","Интерактивная командная строка MikroTik через SSH"),("Журнал операций","История действий, команд и ошибок приложения")]
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
                elif kind=="CONNECTED": QTimer.singleShot(700, self.refresh_traffic_once); QTimer.singleShot(1000, self.refresh_router_status); self.auth_btn.setText("SSH подключён · Выйти"); self.auth_btn.setObjectName("DangerButton"); self.auth_btn.style().unpolish(self.auth_btn); self.auth_btn.style().polish(self.auth_btn); self.foot.setText(f"ROUTEROS 7  ·  SSH KEY AUTH\n{self.settings['host']}:{self.settings['port']}"); self.reset_traffic(True); self.log(f"SSH fingerprint {payload['fp']} ({'known' if payload['known'] else 'new key saved'})")
                elif kind=="ERROR": self.busy=False; self.progress.hide(); self.log("ОШИБКА: "+str(payload)); self.diag_block("Ошибка",str(payload),True,True); QMessageBox.critical(self,"Ошибка",str(payload))
                elif kind=="PENDING_CLEARED": self.pending_actions=[]; self.update_pending_ui()
                elif kind=="DONE": self.busy=False; self.progress.hide(); self.log("Операция завершена.")
                elif kind=="TRAFFIC": self.on_traffic(payload)
                elif kind=="ROUTER_STATUS": self.on_router_status(payload)
                elif kind=="WG_APPLIED": self.save_settings(); self.wg_inputs["wg_private_key"].clear()
                elif kind=="TARGETS": self.on_targets(payload)
                elif kind=="DISCOVERY_DNS_CACHE":
                    dialog, output = payload
                    if dialog and dialog.isVisible():
                        dialog.import_router_dns_cache(output)
                elif kind=="MANGLE_STATUS": self.on_mangle_status(payload)
                elif kind=="DIAGBEGIN": self.diag_begin(payload)
                elif kind=="DIAGOUT": self.diag_block(*payload)
                elif kind=="DOH_DIAGOUT":
                    self.doh_diag_text.setPlainText(str(payload)); self.doh_diag_text.moveCursor(QTextCursor.MoveOperation.Start)
                elif kind=="DOH_DIAGSTATUS":
                    for i,(name,state,detail) in enumerate(payload):
                        self.doh_stage_table.setItem(i,0,QTableWidgetItem(name))
                        cell=QTableWidgetItem(state); cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        cell.setForeground(QColor(TONES["ok"] if state=="OK" else TONES["bad"] if state=="FAIL" else TONES["info"] if state=="INFO" else TONES["warn"]))
                        self.doh_stage_table.setItem(i,1,cell); self.doh_stage_table.setItem(i,2,QTableWidgetItem(detail))
                    failed=[x[0] for x in payload if x[1]=="FAIL"]; warns=[x[0] for x in payload if x[1]=="WARN"]
                    if failed: self.doh_diagnosis_verdict.setText("КАНДИДАТ НЕ ПРОШЁЛ ОБЯЗАТЕЛЬНЫЙ ЭТАП: "+", ".join(failed)+" · смотри автоматический вывод ниже.")
                    elif warns: self.doh_diagnosis_verdict.setText("КЛЮЧЕВЫЕ ПРОВЕРКИ ПРОШЛИ; есть отдельные предупреждения: "+", ".join(warns)+".")
                    else: self.doh_diagnosis_verdict.setText("Ключевые проверки DoH прошли. VPN-маршрутизация оценивается отдельно.")
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
                elif kind=="FW_DATA": self.on_firewall_data(*payload)
                elif kind=="FW_APPLIED": self.firewall_applied()
                elif kind=="TERMOUT":
                    cursor=self.terminal_output.textCursor()
                    cursor.movePosition(QTextCursor.MoveOperation.End)
                    cursor.insertBlock()
                    fmt=QTextCharFormat()
                    is_error=str(payload).startswith("ОШИБКА:")
                    fmt.setForeground(QColor("#fb7185" if is_error else "#c9d7e8"))
                    cursor.setCharFormat(fmt)
                    cursor.insertText(str(payload))
                    self.terminal_output.setTextCursor(cursor)
                    self.terminal_output.ensureCursorVisible()
                elif kind=="DISCONNECTED":
                    self.auth_btn.setText("Войти по SSH"); self.auth_btn.setObjectName("PrimaryButton"); self.auth_btn.style().unpolish(self.auth_btn); self.auth_btn.style().polish(self.auth_btn)
                    self.router_state=None; self.render_targets(); self.reset_traffic(); self.mangle_status.setText("●  Статус: не проверен (нет SSH)"); self.mangle_status.setStyleSheet(f"color:{TONES['muted']};font-weight:700"); self.foot.setText("ROUTEROS 7  ·  SSH KEY AUTH\nSelective routing workspace")
                    for k in self.dns_ind: self.set_ind(k,"off","—")
                    for value in self.router_health_values.values(): value.setText("—")
                    self.router_status_stamp.setText("Нет SSH-подключения")
                    self.router_status_timer.stop()
                    self.router_status_auto.setChecked(False)
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
        self.set_ind("v6","ok" if v6 else "warn","нет" if v6 else "есть · возможен обход IPv4")
        fwd_count=result.get("DNS FWD count","0")
        self.set_ind("fwd","ok" if int(fwd_count or 0)>0 else "warn",f"{fwd_count} записей" if int(fwd_count or 0)>0 else "нет записей")
        ip_count=result.get("VPN address-list count","0")
        self.set_ind("ips","ok" if int(ip_count or 0)>0 else "warn",f"{ip_count} IP" if int(ip_count or 0)>0 else "пока пуст")
        good=[doh,red=="UDP + TCP",dot=="TCP/853 + UDP/853",rem]
        n=sum(1 for x in good if x)
        self.set_ind("overall","ok" if n==4 else ("bad" if n==0 else "warn"),"Защищён" if n==4 else ("Не защищён" if n==0 else f"Частично · {n}/4"))

    # ---------- оперативное состояние роутера ----------
    def set_router_status_auto(self, enabled):
        if enabled:
            self.router_status_timer.start()
            self.refresh_router_status()
            self.log("Автообновление оперативного состояния включено: интервал 30 секунд.")
        else:
            self.router_status_timer.stop()
            self.log("Автообновление оперативного состояния выключено.")

    def refresh_router_status(self):
        if self.busy or self.router_status_busy:
            return
        if not self.router or not self.router.client:
            self.router_status_stamp.setText("Сначала подключись по SSH")
            return
        self.router_status_busy = True
        self.router_status_refresh.setEnabled(False)
        def work():
            try:
                r=self.router_conn()
                commands = {
                    "resource": "/system resource print",
                    "identity": "/system identity print",
                    "interfaces": "/interface print detail",
                    "addresses": "/ip address print terse",
                    "peers": f"/interface wireguard peers print detail where interface={ros_q(self.settings.get('wg_interface',''))}",
                    "routes": "/ip route print detail where dst-address=0.0.0.0/0",
                    "ping": "/ping 1.1.1.1 count=3",
                    "dns": "/resolve example.com"
                }
                result={}
                for key,command in commands.items():
                    try:
                        result[key]=r.exec(command,10 if key=="ping" else 8)
                    except Exception as exc:
                        result[key]="ERROR: "+str(exc)
                self.q.put(("ROUTER_STATUS",result))
            except Exception as exc:
                self.q.put(("ROUTER_STATUS",{"error":str(exc)}))
            finally:
                self.router_status_busy=False
        threading.Thread(target=work,daemon=True).start()

    def on_router_status(self, data):
        self.router_status_refresh.setEnabled(True)
        if data.get("error"):
            self.router_status_stamp.setText("Ошибка обновления · "+datetime.now().strftime("%H:%M:%S"))
            self.router_health_values["identity"].setText(data["error"])
            return

        def field(block,key):
            match=re.search(r"(?im)^\s*"+re.escape(key)+r"\s*:\s*(.*?)\s*$",block or "")
            return match.group(1).strip() if match else ""

        resource=data.get("resource","")
        identity=field(data.get("identity",""),"name") or self.settings.get("host","MikroTik")
        version=field(resource,"version")
        uptime=field(resource,"uptime")
        cpu=field(resource,"cpu-load")
        temp=field(resource,"cpu-temperature") or field(resource,"board-temperature") or field(resource,"temperature")
        total_raw=field(resource,"total-memory"); free_raw=field(resource,"free-memory")
        memory=f"{free_raw} свободно / {total_raw}" if total_raw and free_raw else "Нет данных"
        self.router_health_values["identity"].setText(identity+(f" · RouterOS {version}" if version else ""))
        self.router_health_values["cpu"].setText(f"{cpu}%" if cpu else "Нет данных")
        self.router_health_values["memory"].setText(memory)
        self.router_health_values["uptime"].setText(uptime or "Нет данных")
        self.router_health_values["temperature"].setText(temp or "Не поддерживается / нет датчика")

        iface_lines=re.findall(r'(?m)^\s*\d+\s+([A-Z]*)\s+.*?\bname="?([^"\s]+)',data.get("interfaces",""))
        iface_state={name:("UP" if "R" in flags else "DOWN") for flags,name in iface_lines}
        addresses=parse_terse(data.get("addresses",""))
        def interface_summary(name):
            if not name: return "Не задан"
            state=iface_state.get(name,"не найден")
            ips=sorted({x["f"].get("address","") for x in addresses if x["f"].get("interface")==name and x["f"].get("address")})
            return state+(" · "+", ".join(ips) if ips else " · IP не назначен")
        self.router_health_values["wan"].setText(interface_summary(self.settings.get("wan_interface","WAN")))
        self.router_health_values["lan"].setText(interface_summary(self.settings.get("lan_interface","")))

        peer_text=data.get("peers","")
        handshake=re.search(r"(?i)\blast-handshake\s*[:=]\s*([^\s]+)",peer_text)
        rx=re.search(r"(?i)\brx\s*[:=]\s*(\d+)",peer_text)
        tx=re.search(r"(?i)\btx\s*[:=]\s*(\d+)",peer_text)
        hs=handshake.group(1).strip() if handshake else "нет данных"
        self.router_health_values["wireguard"].setText(f"{hs} · RX {human_bytes(int(rx.group(1)))} / TX {human_bytes(int(tx.group(1)))}" if rx and tx else hs)

        route_text=data.get("routes","")
        default_route=bool(re.search(r"(?m)^\s*\d+\s+.*?dst-address=0\.0\.0\.0/0",route_text))
        route_state="default route найден" if default_route else "default route не подтверждён"
        ping=data.get("ping","")
        loss=re.search(r"packet-loss=([0-9]+)%",ping)
        internet=(f"Ping 1.1.1.1 · loss {loss.group(1)}%" if loss else ("Ping не выполнен" if "ERROR:" in ping else "Ping: нет ответа"))
        dns=data.get("dns","")
        dns_state="DNS OK" if dns and "ERROR:" not in dns else "DNS ошибка"
        self.router_health_values["internet"].setText(f"{internet} · {dns_state} · {route_state}")
        self.last_router_status=data
        self.router_status_stamp.setText("Обновлено "+datetime.now().strftime("%H:%M:%S")+" · только чтение")
        self.log("Оперативное состояние роутера обновлено (read-only).")

    # ---------- трафик WireGuard ----------
    def reset_traffic(self,connected=False):
        self.tr_rx.clear(); self.tr_tx.clear(); self.tr_prev=None; self.normal_rx.clear(); self.normal_tx.clear(); self.wan_prev=None
        if hasattr(self,"normal_chart"): self.normal_chart.set_data([],[])
        self.chart.msg="Нажми «Снять 3 замера» для построения графика" if connected else "Нет данных — подключись к роутеру"; self.chart.set_data([],[])
        for v in self.tr_labels.values(): v.setText("—")
        self.tr_panel.sub_label.setText("Ожидание данных от peer…" if connected else "Ожидание подключения к роутеру…")

    def set_traffic_auto(self,enabled):
        if enabled:
            self.traffic_timer.start(); self.poll_traffic()
            self.log("Автообновление счётчиков WireGuard включено: интервал 5 секунд.")
        else:
            self.traffic_timer.stop(); self.log("Автообновление счётчиков WireGuard отключено.")

    def refresh_traffic_once(self):
        if not self.router:
            self.chart.msg = "Сначала подключись к MikroTik по SSH"
            self.chart.update()
            return
        self.chart.msg = "Снимаю первый замер…"
        self.chart.update()
        self.poll_traffic()
        # Для графика нужны две точки скорости, то есть три замера счётчиков.
        QTimer.singleShot(1800, self.poll_traffic)
        QTimer.singleShot(3600, self.poll_traffic)

    def poll_traffic(self):
        r=self.router
        if self.tr_busy or not r or not r.client: return
        self.tr_busy=True; wg=self.settings.get("wg_interface",""); wan=self.settings.get("wan_interface","WAN")
        def work():
            try:
                out=r.exec(f"/interface wireguard peers print detail where interface={ros_q(wg)}",8)
                rx=sum(int(x) for x in re.findall(r"\brx=(\d+)",out)); tx=sum(int(x) for x in re.findall(r"\btx=(\d+)",out))
                hs=re.findall(r"last-handshake=(\S+)",out); peers=out.count("public-key=")
                wan_rx=wan_tx=None
                try:
                    mon=r.exec(f"/interface monitor-traffic interface={ros_q(wan)} once",5)
                    mr=re.search(r"rx-bits-per-second:\s*(\d+)",mon); mt=re.search(r"tx-bits-per-second:\s*(\d+)",mon)
                    if mr and mt: wan_rx=int(mr.group(1)); wan_tx=int(mt.group(1))
                except Exception: pass
                self.q.put(("TRAFFIC",(time.monotonic(),rx,tx,hs[0] if hs else None,peers,wan_rx,wan_tx)))
            except Exception: self.q.put(("TRAFFIC",None))
            finally: self.tr_busy=False
        threading.Thread(target=work,daemon=True).start()

    def on_traffic(self,payload):
        if payload is None:
            if not self.tr_rx: self.chart.msg="Нет ответа от роутера…"; self.chart.update()
            return
        t,rx,tx,hs,peers,wan_rx,wan_tx=payload
        if self.tr_prev:
            pt,prx,ptx=self.tr_prev; dt=t-pt
            if dt>0.5: self.tr_rx.append(max(0,rx-prx)/dt); self.tr_tx.append(max(0,tx-ptx)/dt)
        self.tr_prev=(t,rx,tx)
        if wan_rx is not None and wan_tx is not None:
            # monitor-traffic уже возвращает текущие bit/s; переводим в byte/s и вычитаем WG.
            wg_rx_rate=self.tr_rx[-1] if self.tr_rx else 0
            wg_tx_rate=self.tr_tx[-1] if self.tr_tx else 0
            self.normal_rx.append(max(0,wan_rx/8-wg_rx_rate))
            self.normal_tx.append(max(0,wan_tx/8-wg_tx_rate))
            self.normal_chart.msg="Нужны повторные замеры WAN" if len(self.normal_rx)<2 else ""; self.normal_chart.set_data(self.normal_rx,self.normal_tx)
            self.normal_hint.setText(f"Обычный трафик (оценка) · RX {fmt_bits(self.normal_rx[-1]*8)} · TX {fmt_bits(self.normal_tx[-1]*8)}. WAN включает VPN-инкапсуляцию, поэтому из него вычитаются счётчики WG.")
        if self.tr_rx:
            self.tr_labels["rx"].setText(fmt_bits(self.tr_rx[-1]*8)); self.tr_labels["tx"].setText(fmt_bits(self.tr_tx[-1]*8))
            self.tr_labels["peak"].setText(fmt_bits(max(self.tr_rx+self.tr_tx)*8))
        self.tr_labels["total"].setText(f"{human_bytes(rx)} / {human_bytes(tx)}")
        self.tr_panel.sub_label.setText(f"Peers: {peers} · последний handshake: {hs or 'нет'} · обновление каждые 5 с")
        self.chart.msg="Нужен второй замер для расчёта скорости" if len(self.tr_rx)<2 else ""; self.chart.set_data(self.tr_rx,self.tr_tx)

    # ---------- статусы VPN-целей ----------
    def fetch_targets(self,r,cached=None):
        alist=self.settings["address_list"]
        if cached is None:
            dns=parse_terse(r.exec('/ip dns static print terse where comment~"VPN-MANAGER:"'))
            dns_cache=parse_terse(r.exec('/ip dns cache print terse'))
            managed_al=parse_terse(r.exec('/ip firewall address-list print terse where comment~"VPN-MANAGER-CIDR:"'))
            all_al=parse_terse(r.exec(f'/ip firewall address-list print terse where list={ros_q(alist)}'))
        else:
            # Reuse evidence from the full diagnostic instead of issuing the
            # same RouterOS reads a second time after the report is complete.
            dns=parse_terse(cached.get("DNS static FWD",""))
            dns_cache=parse_terse(cached.get("DNS cache",""))
            managed_al=parse_terse(cached.get("Managed CIDR address-list",""))
            all_al=parse_terse(cached.get("VPN address-list",""))
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
                found[target]=("Домен","X" in it["flags"],"I" in it["flags"],detail,bool(in_address_list),len(cache_ips),sorted(cache_ips),sorted(in_address_list))
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
            if len(f)<6 or not f[5]: return ("FWD есть · нет DNS A-запроса от клиентов","info")
            return ("DNS A получен · IP в address-list","ok") if f[4] else ("DNS A получен · IP не попал в список","warn")
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
        self.diag_text.verticalScrollBar().setValue(0)

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
        head="#fb7185" if error else "#7db0ff"; body="#fda4af" if error else "#b9c8de"
        self.diag_text.append(f'<div style="margin-top:16px;color:{head};font-weight:700">▌ {esc(title)} <span style="color:#5f7499;font-weight:400">· {datetime.now().strftime("%H:%M:%S")}</span></div><pre style="color:{body};margin:4px 0 0 0">{esc(text or "(пустой вывод)")}</pre>')
        sb=self.diag_text.verticalScrollBar()
        if follow: sb.setValue(sb.maximum())
        else: sb.setValue(0)

    def diag_run(self,title,command,timeout=30):
        self.q.put(("DIAGBEGIN",title))
        try:
            r=self.router_conn(); out=self.cmd(r,command,timeout)
            self.q.put(("DIAGOUT",(f"{title} · {command}",out,False,False)))
        except Exception as exc:
            self.q.put(("DIAGOUT",(title,"ERROR: "+str(exc),True,False)))

    def run_diag_commands(self,title,commands,job_label):
        """Run a focused read-only diagnostic and render every result in the Diagnostics report."""
        def job():
            self.q.put(("DIAGBEGIN",title))
            try:
                r=self.router_conn()
            except Exception as exc:
                self.q.put(("DIAGOUT",("SSH / подключение","ERROR: "+str(exc),True,False)))
                return
            for name,command,timeout in commands:
                try:
                    output=self.cmd(r,command,timeout)
                    error=output.strip().startswith("ERROR:")
                except Exception as exc:
                    output="ERROR: "+str(exc); error=True
                self.q.put(("DIAGOUT",(f"{name} · {command}",output,error,False)))
        self.run_job(job_label,job)

    def run_job(self,label,fn):
        if self.busy:
            self.status.setText("Уже выполняется другая операция · дождись её завершения.")
            return
        # Snapshot widget values on the GUI thread; worker threads never read Qt widgets.
        if hasattr(self, "inputs"):
            self.settings.update(self.fields())
            if hasattr(self,"wg_inputs"):
                for k,w in self.wg_inputs.items():
                    if k != "wg_private_key": self.settings[k] = w.text().strip()
            if hasattr(self, "passphrase"): self.passphrase_value = self.passphrase.text()
        self.busy=True; self.progress.show(); self.status.setText("Выполняется: "+label); self.log(label)
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
        r=RouterConnection(f["host"], port, f["username"], getattr(self, "auth_method_value", f.get("auth_method", "key")), f.get("key_file", ""), getattr(self, "passphrase_value", ""), getattr(self, "password_value", ""), self.q)
        known,fp=r.connect(); self.router=r; self.q.put(("CONNECTED",{"known":known,"fp":fp})); return r

    def show_ssh_login(self):
        self.log("SSH UI: обработчик кнопки подключения вызван")
        self.status.setText("Открывается окно SSH-подключения…")
        try:
            transport = self.router.client.get_transport() if self.router and self.router.client else None
            if transport and transport.is_active() and transport.is_authenticated():
                answer = QMessageBox.question(
                    self, "SSH подключение", "SSH уже подключён. Отключиться от MikroTik?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self.disconnect_router()
                return

            class FramelessSSHDialog(QDialog):
                def __init__(self, parent=None):
                    super().__init__(parent)
                    self._drag_offset = None

                def mousePressEvent(self, event):
                    if event.button() == Qt.MouseButton.LeftButton:
                        self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                    super().mousePressEvent(event)

                def mouseMoveEvent(self, event):
                    if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
                        self.move(event.globalPosition().toPoint() - self._drag_offset)
                    super().mouseMoveEvent(event)

                def mouseReleaseEvent(self, event):
                    self._drag_offset = None
                    super().mouseReleaseEvent(event)

            dialog = FramelessSSHDialog(self)
            dialog.setObjectName("SSHLoginDialog")
            dialog.setWindowTitle("MikroTik VPN Manager — SSH")
            dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
            dialog.setModal(True)
            dialog.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
            dialog.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
            dialog.setMinimumWidth(540)
            dialog.setStyleSheet(self.styleSheet() + """
                QDialog#SSHLoginDialog { background: #080f1d; border:1px solid #315078; border-radius:20px; }
                QPushButton#SSHModeButton { background:transparent; border:0; color:#8fa7c8; min-height:38px; font-weight:700; }
                QPushButton#SSHModeButton:checked { color:#ffffff; }
                QFrame#SSHModeTrack { background:#081321; border:1px solid #263c5a; border-radius:12px; }
                QFrame#SSHModeIndicator { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #397cf0,stop:1 #2459c0); border:1px solid #75aaff; border-radius:9px; }
                QPushButton#SSHClose { background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12); color:#c8d8ef; border-radius:9px; min-width:32px; max-width:32px; min-height:32px; max-height:32px; font-size:14pt; }
                QDialog#SSHLoginDialog QLabel { background: transparent; }
                QFrame#SSHHeader { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #17366d,stop:.58 #10264b,stop:1 #111d35); border:1px solid #31558b; border-radius:17px; }
                QLabel#SSHBrandMark { background:#3978ed; color:white; border-radius:13px; font-size:20pt; font-weight:800; min-width:48px; max-width:48px; min-height:48px; max-height:48px; qproperty-alignment:AlignCenter; }
                QLabel#SSHOverline { color:#8db8ff; font-size:8pt; font-weight:800; }
                QLabel#SSHHeading { color:#fff; font-size:17pt; font-weight:750; }
                QLabel#SSHDescription { color:#b5c8e5; font-size:9pt; }
                QFrame#SSHSection { background:#0d1728; border:1px solid #243650; border-radius:15px; }
                QLabel#SSHSectionTitle { color:#e5eefc; font-size:10pt; font-weight:700; }
                QLabel#SSHFieldLabel { color:#8fa7c8; font-size:8pt; font-weight:700; }
                QLineEdit,QComboBox { background:#080f1b; border:1px solid #2a3d59; border-radius:9px; color:#edf4ff; padding:0 12px; min-height:40px; }
                QLineEdit:focus,QComboBox:focus { border:1px solid #5d96ff; background:#0b1729; }
                QPushButton#SSHBrowse { background:#172944; border:1px solid #345174; color:#d9e8ff; border-radius:9px; min-height:40px; padding:0 14px; }
                QLabel#SSHSecurityNote { background:#10233b; border:1px solid #284c78; border-radius:11px; color:#a9c8f2; padding:11px 13px; font-size:8pt; }
                QPushButton#SSHCancel { background:#142033; border:1px solid #2b3d57; color:#c1cfe2; border-radius:10px; min-height:42px; padding:0 18px; }
                QPushButton#SSHConnect { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #4b91ff,stop:1 #2862d7); border:1px solid #75aaff; color:white; border-radius:10px; min-height:42px; padding:0 22px; font-weight:750; }
            """)

            outer = QVBoxLayout(dialog)
            outer.setContentsMargins(22, 22, 22, 20)
            outer.setSpacing(15)

            header = QFrame()
            header.setObjectName("SSHHeader")
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(18, 18, 20, 18)
            header_layout.setSpacing(15)
            mark = QLabel("◈")
            mark.setObjectName("SSHBrandMark")
            header_layout.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)
            intro = QVBoxLayout()
            intro.setSpacing(5)
            overline = QLabel("MIKROTIK VPN MANAGER  /  SECURE ACCESS")
            overline.setObjectName("SSHOverline")
            heading = QLabel("Подключение по SSH")
            heading.setObjectName("SSHHeading")
            description = QLabel("Выбери способ авторизации и укажи параметры доступа.")
            description.setObjectName("SSHDescription")
            description.setWordWrap(True)
            intro.addWidget(overline)
            intro.addWidget(heading)
            intro.addWidget(description)
            header_layout.addLayout(intro, 1)
            close_button = QPushButton("×")
            close_button.setObjectName("SSHClose")
            close_button.setCursor(Qt.CursorShape.PointingHandCursor)
            close_button.clicked.connect(dialog.reject)
            header_layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignTop)
            outer.addWidget(header)

            section = QFrame()
            section.setObjectName("SSHSection")
            section_layout = QVBoxLayout(section)
            section_layout.setContentsMargins(18, 16, 18, 18)
            section_layout.setSpacing(11)
            section_title = QLabel("ПАРАМЕТРЫ ДОСТУПА")
            section_title.setObjectName("SSHSectionTitle")
            section_layout.addWidget(section_title)

            form = QFormLayout()
            form.setContentsMargins(0, 3, 0, 0)
            form.setHorizontalSpacing(16)
            form.setVerticalSpacing(10)

            def field_label(caption):
                label = QLabel(caption.upper())
                label.setObjectName("SSHFieldLabel")
                return label

            host = QLineEdit(self.settings.get("host", ""))
            host.setPlaceholderText("192.168.0.2 или router.example")
            port = QLineEdit(self.settings.get("port", "2313"))
            port.setMaximumWidth(125)
            user = QLineEdit(self.settings.get("username", "pwned"))

            auth_mode = QComboBox()
            auth_mode.addItem("Приватный SSH-ключ", "key")
            auth_mode.addItem("Пароль пользователя MikroTik", "password")
            saved_mode = self.settings.get("auth_method", "key")
            auth_mode.setCurrentIndex(max(0, auth_mode.findData(saved_mode)))

            mode_switch = QFrame()
            mode_switch.setObjectName("SSHModeTrack")
            mode_switch.setFixedHeight(48)
            switch_layout = QHBoxLayout(mode_switch)
            switch_layout.setContentsMargins(4, 4, 4, 4)
            switch_layout.setSpacing(2)
            password_tab = QPushButton("Пароль")
            key_tab = QPushButton("SSH-ключ")
            for tab in (password_tab, key_tab):
                tab.setObjectName("SSHModeButton")
                tab.setCheckable(True)
                tab.setCursor(Qt.CursorShape.PointingHandCursor)
                switch_layout.addWidget(tab, 1)
            mode_indicator = QFrame(mode_switch)
            mode_indicator.setObjectName("SSHModeIndicator")
            mode_indicator.lower()
            mode_animation = QPropertyAnimation(mode_indicator, b"geometry", dialog)
            mode_animation.setDuration(230)
            mode_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            section_layout.addWidget(mode_switch)

            key = QLineEdit(self.settings.get("key_file", ""))
            key.setPlaceholderText("Путь к приватному SSH-ключу")
            key_row = QWidget()
            key_layout = QHBoxLayout(key_row)
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.setSpacing(8)
            key_layout.addWidget(key, 1)
            browse = QPushButton("Обзор…")
            browse.setObjectName("SSHBrowse")
            browse.clicked.connect(lambda: self.choose_key(key))
            key_layout.addWidget(browse)

            phrase = QLineEdit()
            phrase.setEchoMode(QLineEdit.EchoMode.Password)
            phrase.setPlaceholderText("Если приватный ключ защищён паролем")
            password = QLineEdit()
            password.setEchoMode(QLineEdit.EchoMode.Password)
            password.setPlaceholderText("Пароль SSH-пользователя MikroTik")

            form.addRow(field_label("Адрес маршрутизатора"), host)
            form.addRow(field_label("SSH-порт"), port)
            form.addRow(field_label("Пользователь"), user)
            key_label = field_label("Приватный ключ")
            phrase_label = field_label("Passphrase ключа")
            password_label = field_label("Пароль пользователя")
            form.addRow(key_label, key_row)
            form.addRow(phrase_label, phrase)
            form.addRow(password_label, password)
            section_layout.addLayout(form)
            outer.addWidget(section)

            def update_auth_fields(*_, animate=True):
                use_key = auth_mode.currentData() == "key"
                key_label.setVisible(use_key)
                key_row.setVisible(use_key)
                phrase_label.setVisible(use_key)
                phrase.setVisible(use_key)
                password_label.setVisible(not use_key)
                password.setVisible(not use_key)
                password_tab.setChecked(not use_key)
                key_tab.setChecked(use_key)
                mode_switch.update()
                target_x = 4 + (mode_switch.width() - 8) // 2 if use_key else 4
                target = mode_indicator.geometry()
                target.setX(target_x)
                target.setY(4)
                target.setWidth(max(0, (mode_switch.width() - 8) // 2))
                target.setHeight(mode_switch.height() - 8)
                mode_animation.stop()
                if animate and mode_switch.width() > 20:
                    mode_animation.setStartValue(mode_indicator.geometry())
                    mode_animation.setEndValue(target)
                    mode_animation.start()
                else:
                    mode_indicator.setGeometry(target)
                dialog.adjustSize()

            password_tab.clicked.connect(lambda: auth_mode.setCurrentIndex(auth_mode.findData("password")))
            key_tab.clicked.connect(lambda: auth_mode.setCurrentIndex(auth_mode.findData("key")))
            auth_mode.currentIndexChanged.connect(update_auth_fields)
            initial_key_mode = auth_mode.currentData() == "key"
            key_label.setVisible(initial_key_mode)
            key_row.setVisible(initial_key_mode)
            phrase_label.setVisible(initial_key_mode)
            phrase.setVisible(initial_key_mode)
            password_label.setVisible(not initial_key_mode)
            password.setVisible(not initial_key_mode)
            password_tab.setChecked(not initial_key_mode)
            key_tab.setChecked(initial_key_mode)
            QTimer.singleShot(0, lambda: update_auth_fields(animate=False))

            security = QLabel("◉  При первом подключении проверь fingerprint SSH-сервера. Пароль не сохраняется в файле настроек приложения.")
            security.setObjectName("SSHSecurityNote")
            security.setWordWrap(True)
            outer.addWidget(security)

            buttons = QHBoxLayout()
            buttons.addStretch()
            cancel = QPushButton("Отмена")
            cancel.setObjectName("SSHCancel")
            connect = QPushButton("Подключиться  →")
            connect.setObjectName("SSHConnect")
            connect.setDefault(True)
            buttons.addWidget(cancel)
            buttons.addWidget(connect)
            outer.addLayout(buttons)
            cancel.clicked.connect(dialog.reject)

            def do_login():
                h, u = host.text().strip(), user.text().strip()
                k = key.text().strip()
                mode = auth_mode.currentData()
                try:
                    p = int(port.text().strip())
                    if not h or not u:
                        raise ValueError("Укажите адрес маршрутизатора и имя пользователя.")
                    if not 1 <= p <= 65535:
                        raise ValueError("SSH-порт должен быть от 1 до 65535.")
                    if mode == "key" and (not k or not Path(k).is_file()):
                        raise ValueError("Укажите существующий файл приватного SSH-ключа.")
                    if mode == "password" and not password.text():
                        raise ValueError("Введите пароль пользователя MikroTik.")
                except Exception as exc:
                    QMessageBox.warning(dialog, "Проверьте данные", str(exc))
                    return
                self.settings.update({"host": h, "port": str(p), "username": u, "auth_method": mode})
                if mode == "key":
                    self.settings["key_file"] = k
                    self.passphrase_value = phrase.text()
                    self.password_value = ""
                else:
                    self.passphrase_value = ""
                    self.password_value = password.text()
                self.auth_method_value = mode
                self.save_settings()
                dialog.accept()

            connect.clicked.connect(do_login)
            for widget in (host, port, user, key, phrase, password):
                widget.returnPressed.connect(do_login)

            dialog.resize(620, 650)
            self.log("SSH UI: диалог с выбором способа авторизации создан, вызывается exec()")
            self.status.setText("Ожидание параметров SSH-подключения…")
            result = dialog.exec()
            self.log(f"SSH UI: диалог закрыт, код результата {result}")
            if result == QDialog.DialogCode.Accepted:
                self.connect_router()
            else:
                self.status.setText("Подключение отменено")
        except Exception as exc:
            import traceback
            self.log("SSH UI ERROR: " + traceback.format_exc())
            QMessageBox.critical(self, "Ошибка окна SSH-подключения",
                                 f"Не удалось открыть окно подключения.\\n\\n{type(exc).__name__}: {exc}")
            self.status.setText("Ошибка открытия окна SSH-подключения")

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
        return r.exec(command,timeout)

    def diagnostics(self,r,run_ping=False,silent=False,domain=None):
        """
        Read-only, layered diagnostics. Every command is executed once per run;
        raw evidence and the interpreted result are kept in the same report.
        """
        f=self.settings
        if not silent:
            self.q.put(("DIAGBEGIN","Расширенная диагностика сети · только чтение"))

        checks = {
            "Router identity": "/system identity print",
            "System resources": "/system resource print",
            "Clock": "/system clock print",
            "Interfaces": "/interface print terse",
            "WAN interface": f"/interface monitor-traffic interface={ros_q(f['wan_interface'])} once",
            "Main default route": "/ip route print detail where dst-address=0.0.0.0/0 and routing-table=main",
            "VPN default route": f"/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(f['route_table'])}",
            "DNS configuration": "/ip dns print",
            "DNS resolve Cloudflare": ':put [:resolve "cloudflare.com"]',
            "DNS resolve YouTube": ':put [:resolve "youtube.com"]',
            "DHCP network": "/ip dhcp-server network print detail",
            "DHCP leases": '/ip dhcp-server lease print where status=bound',
            "WireGuard interface": f"/interface wireguard print detail where name={ros_q(f['wg_interface'])}",
            "WireGuard addresses": f"/ip address print detail where interface={ros_q(f['wg_interface'])}",
            "WireGuard peers": f"/interface wireguard peers print detail where interface={ros_q(f['wg_interface'])}",
            "VPN interface ping": f"/tool ping address=1.1.1.1 interface={ros_q(f['wg_interface'])} count=3",
            "Managed Mangle": f'/ip firewall mangle print terse where comment={ros_q(MANGLE_COMMENT)}',
            "Managed NAT": "/ip firewall nat print terse",
            "DNS redirect NAT": '/ip firewall nat print terse where comment~"DNS-REDIRECT"',
            "Firewall filter": "/ip firewall filter print terse",
            "DNS static FWD": '/ip dns static print terse where comment~"VPN-MANAGER:"',
            "DNS cache": "/ip dns cache print terse",
            "Managed CIDR address-list": '/ip firewall address-list print terse where comment~"VPN-MANAGER-CIDR:"',
            "VPN address-list": f"/ip firewall address-list print terse where list={ros_q(f['address_list'])}",
            "IPv6 settings": "/ipv6 settings print",
            "IPv6 addresses": "/ipv6 address print detail",
            "IPv6 routes": "/ipv6 route print detail where active",
            "IPv6 default route": "/ipv6 route print detail where dst-address=::/0 and active",
            "IPv6 firewall": "/ipv6 firewall filter print detail",
            "IPv6 Neighbor Discovery / Router Advertisements": "/ipv6 nd print detail",
            "Managed Mangle counters": f'/ip firewall mangle print stats detail where comment={ros_q(MANGLE_COMMENT)}',
            "FastTrack counters": "/ip firewall filter print stats detail where action=fasttrack-connection",
            "Recent network errors": '/log print without-paging where topics~"error|warning|dns|wireguard"',
            "WAN ping": "/tool ping address=1.1.1.1 count=3",
        }
        if domain:
            checks.update({
                "Selected domain DNS resolve": f":put [:resolve {ros_q(domain)}]",
                "Selected domain DNS cache": f"/ip dns cache print terse where name~{ros_q(domain)}",
                "Selected domain managed FWD": f"/ip dns static print terse where comment={ros_q('VPN-MANAGER:'+domain)}",
                "Selected domain dynamic IPs": f"/ip firewall address-list print terse where list={ros_q(f['address_list'])} and comment={ros_q('created for '+domain+'.')}",
            })
        raw={}
        for title,command in checks.items():
            try:
                raw[title]=self.cmd(r,command,timeout=18)
            except Exception as exc:
                raw[title]="ERROR: "+str(exc)

        # RouterOS v7 route-table inspection for IPv4 addresses returned by the selected domain.
        # This is not packet-level proof: actual LAN forwarding also depends on Mangle,
        # address-list membership and FastTrack state.
        route_probe_ips=[]
        if domain:
            for source_key in ("Selected domain DNS resolve","Selected domain DNS cache","Selected domain dynamic IPs"):
                source_value=raw.get(source_key,"")
                if source_value.startswith("ERROR:"):
                    continue
                for candidate in re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])",source_value):
                    try:
                        ipaddress.IPv4Address(candidate)
                        if candidate not in route_probe_ips:
                            route_probe_ips.append(candidate)
                    except ValueError:
                        pass
        for probe_ip in route_probe_ips[:5]:
            for table_name,table_value in (("main","main"),("vpn",f["route_table"])):
                key=f"Route lookup {probe_ip} · {table_name}"
                command=f"/ip route print detail where {probe_ip} in dst-address and active and routing-table={ros_q(table_value)}"
                try:
                    raw[key]=self.cmd(r,command,timeout=18)
                except Exception as exc:
                    raw[key]="ERROR: "+str(exc)

        # Redact credentials from the report as well as the operation log.
        # WireGuard private/preshared keys must never be exported with diagnostics.
        for key,value in raw.items():
            value=re.sub(r'(?im)((?:private|preshared)-key\s*[:=]\s*)("[^"]*"|\S+)',r'\1[СКРЫТО]',value)
            raw[key]=value

        # Client-side checks run on the Windows PC where this app is running.
        # They are deliberately separated from router-side checks: Windows may use
        # a different resolver (VPN client, DoH app, or manually configured DNS).
        local={}
        try:
            answers=socket.getaddrinfo("youtube.com",443,type=socket.SOCK_STREAM)
            local["Windows DNS"]="; ".join(sorted({x[4][0] for x in answers})) or "Адреса не получены"
        except Exception as exc:
            local["Windows DNS"]="ERROR: "+str(exc)
        try:
            with socket.create_connection(("youtube.com",443),timeout=4):
                local["Windows TCP 443"]="Соединение с youtube.com:443 установлено"
        except Exception as exc:
            local["Windows TCP 443"]="ERROR: "+str(exc)
        try:
            with socket.create_connection(("1.1.1.1",443),timeout=4):
                local["Windows TCP 1.1.1.1:443"]="Прямое TCP-соединение с 1.1.1.1:443 установлено"
        except Exception as exc:
            local["Windows TCP 1.1.1.1:443"]="ERROR: "+str(exc)

        def failed(key):
            value=raw.get(key,"")
            return value.startswith("ERROR:")
        def has(key, pattern):
            return re.search(pattern,raw.get(key,""),re.I|re.S) is not None
        def nonempty(key):
            value=raw.get(key,"").strip()
            return bool(value) and not value.startswith("ERROR:")
        findings=[]
        def add(level,area,cause,evidence,action):
            findings.append({"level":level,"area":area,"cause":cause,"evidence":evidence,"action":action})

        if local["Windows DNS"].startswith("ERROR:"):
            add("warn","DNS на Windows-клиенте","Windows не смог разрешить youtube.com",local["Windows DNS"],"Проверь DNS-серверы Windows, VPN-клиент, DoH/DoT в браузере и DNS-настройки сетевого адаптера.")
        else:
            add("ok","DNS на Windows-клиенте","Windows получил DNS-ответ для youtube.com",local["Windows DNS"],"Это результат локального resolver Windows; он может отличаться от DNS MikroTik.")
        if local["Windows TCP 443"].startswith("ERROR:"):
            add("warn","HTTPS на Windows-клиенте","Windows не установил TCP-соединение с youtube.com:443",local["Windows TCP 443"],"Сравни с прямым TCP к 1.1.1.1:443, DNS на роутере и WAN ping. Проверь локальный firewall, прокси/VPN-клиент и доступность HTTPS.")
        else:
            add("ok","HTTPS на Windows-клиенте","TCP/443 до youtube.com доступен",local["Windows TCP 443"],"TCP-соединение установлено; это ещё не проверка TLS, HTTP или воспроизведения видео.")
        if local["Windows TCP 1.1.1.1:443"].startswith("ERROR:"):
            add("warn","HTTPS по IP на Windows-клиенте","Windows не установил прямое TCP-соединение с 1.1.1.1:443",local["Windows TCP 1.1.1.1:443"],"Если одновременно не работает TCP/443 к домену, ищи общий сбой маршрута/Firewall/прокси. Если IP доступен, а домен нет — проверь DNS.")
        else:
            add("ok","HTTPS по IP на Windows-клиенте","Прямое TCP-соединение с 1.1.1.1:443 доступно",local["Windows TCP 1.1.1.1:443"],"Внешний TCP/443 доступен независимо от DNS; TLS/HTTP этим тестом не проверяются.")

        # SSH and basic router response are implicit preconditions: this function
        # is only entered after an authenticated SSH session has been obtained.
        if failed("System resources"):
            add("info","Ресурсы роутера","Не удалось выполнить проверку system resource",raw["System resources"],"Проверь права SSH и совместимость команды; ошибка чтения не означает отказ роутера.")
        else:
            cpu=re.search(r"cpu-load:\s*(\d+)%",raw["System resources"],re.I)
            if cpu and int(cpu.group(1))>=90:
                add("warn","Производительность",f"Высокая загрузка CPU: {cpu.group(1)}%",raw["System resources"],"Проверь процессы и нагрузку; повтори диагностику после снижения нагрузки.")
        if failed("Main default route"):
            add("info","WAN / основной маршрут","Проверка default route не выполнилась",raw["Main default route"],"Проверь совместимость команды и права SSH; отсутствие вывода из-за ошибки не доказывает отсутствие маршрута.")
        elif not nonempty("Main default route"):
            add("bad","WAN / основной маршрут","Не найден основной IPv4 default route в таблице main","/ip route print не вернул default route для main","Проверь WAN, DHCP/адрес шлюза и default route. VPN-таблицу пока не трогай.")
        elif "inactive" in raw["Main default route"].lower():
            add("bad","WAN / основной маршрут","Основной default route найден, но помечен inactive",raw["Main default route"],"Проверь доступность шлюза и состояние WAN-интерфейса.")
        if failed("WAN interface"):
            add("info","WAN-интерфейс","Проверка monitor-traffic не выполнилась",raw["WAN interface"],"Проверь имя WAN-интерфейса и поддержку команды на этой версии RouterOS.")
        elif not nonempty("WAN interface"):
            add("warn","WAN-интерфейс","Monitor-traffic не вернул данные",raw["WAN interface"],"Проверь имя WAN-интерфейса в настройках приложения.")
        if failed("WAN ping"):
            add("info","Доступ в интернет через WAN","Ping-тест не выполнился как команда",raw["WAN ping"],"Это не доказательство отсутствия интернета: проверь права/синтаксис и сопоставь с другими тестами.")
        elif not nonempty("WAN ping") or "received=0" in raw["WAN ping"].lower() or "packet-loss=100%" in raw["WAN ping"].lower():
            add("warn","Проверка WAN по ICMP","Роутер не получил ICMP-ответы от 1.1.1.1; это само по себе не доказывает отсутствие интернета",raw["WAN ping"],"Сопоставь с DNS и Windows TCP/443. ICMP может фильтроваться провайдером или удалённым узлом.")
        else:
            add("ok","Доступ в интернет через WAN","Проверочный IP доступен с роутера",raw["WAN ping"],"Основной WAN-путь отвечает.")
        if failed("DNS resolve Cloudflare"):
            add("info","DNS / DoH","Команда проверки cloudflare.com не выполнилась",raw["DNS resolve Cloudflare"],"Проверь синтаксис/права; для подтверждения DNS используй также вывод /ip dns и тест с Windows.")
        elif not nonempty("DNS resolve Cloudflare"):
            add("bad","DNS / DoH","RouterOS не вернул адрес cloudflare.com",raw["DNS resolve Cloudflare"],"Проверь use-doh-server, verify-doh-cert, bootstrap DNS и доступ роутера к HTTPS/443.")
        if failed("DNS resolve YouTube"):
            add("info","DNS / домены","Команда проверки youtube.com не выполнилась",raw["DNS resolve YouTube"],"Проверь синтаксис/права и DNS static FWD.")
        elif not nonempty("DNS resolve YouTube"):
            add("warn","DNS / домены","RouterOS не вернул адрес youtube.com",raw["DNS resolve YouTube"],"Сравни результат с cloudflare.com. Проверь DNS static FWD для домена и доступность DoH.")
        if domain:
            selected=raw.get("Selected domain DNS resolve","")
            if failed("Selected domain DNS resolve"):
                add("info","Выбранный домен",f"Проверка {domain} не выполнилась",selected,"Проверь синтаксис команды и права SSH.")
            elif not nonempty("Selected domain DNS resolve"):
                add("warn","Выбранный домен",f"RouterOS не разрешил {domain}",selected,"Проверь DNS/DoH и управляемую FWD-запись для этого домена.")
            if not failed("Selected domain managed FWD") and domain not in raw.get("Selected domain managed FWD",""):
                add("warn","Выбранный домен",f"На роутере не найдена управляемая FWD-запись для {domain}",raw.get("Selected domain managed FWD",""),"Проверь, добавлен ли домен в список VPN-целей и применены ли изменения.")
            if not failed("Selected domain dynamic IPs") and not raw.get("Selected domain dynamic IPs","").strip():
                add("info","Выбранный домен",f"Для {domain} пока не найдено динамических IP в address-list",raw.get("Selected domain dynamic IPs",""),"Сделай DNS-запрос с LAN-клиента к этому домену и повтори диагностику. Это не обязательно ошибка, если клиент ещё не запрашивал домен.")
        if failed("DNS configuration"):
            add("info","DNS configuration","Не удалось прочитать DNS-конфигурацию",raw["DNS configuration"],"Проверь права SSH и повтори проверку после устранения ошибки команды.")
        else:
            if not has("DNS configuration",r"allow-remote-requests:\s*yes"):
                add("warn","DNS для LAN","allow-remote-requests не включён",raw["DNS configuration"],"Проверь, должен ли MikroTik обслуживать DNS-запросы LAN-клиентов.")
            if not has("DNS configuration",r"use-doh-server:\s*https://") or not has("DNS configuration",r"verify-doh-cert:\s*yes"):
                add("warn","DNS-over-HTTPS","DoH endpoint или проверка TLS-сертификата не подтверждены",raw["DNS configuration"],"Проверь URL DoH и verify-doh-cert=yes. Не отключай проверку TLS ради обхода ошибки.")
        if failed("DHCP network"):
            add("info","DHCP / LAN","Не удалось прочитать DHCP network",raw["DHCP network"],"Проверь права SSH и синтаксис команды.")
        elif not has("DHCP network",re.escape(f["lan_subnet"])):
            add("warn","DHCP / LAN","В DHCP network не найдена ожидаемая LAN-подсеть",raw["DHCP network"],"Сверь lan_subnet приложения с DHCP network на MikroTik.")
        elif not has("DHCP network",r"dns-server=.*\b"+re.escape(f.get("lan_ip","192.168.0.2"))+r"\b"):
            add("info","DHCP / DNS","Не удалось подтвердить, что DHCP выдаёт адрес MikroTik как DNS",raw["DHCP network"],"Проверь dns-server в DHCP network и DNS-настройки клиента.")
        wg=raw["WireGuard peers"]
        handshake=re.search(r"last-handshake=(\S+)",wg,re.I)
        if failed("WireGuard peers"):
            add("info","WireGuard","Не удалось прочитать peer",wg,"Проверь права SSH и синтаксис команды; handshake пока не оценён.")
        elif not handshake or handshake.group(1).lower() in ("never","0s"):
            add("bad","WireGuard","Нет подтверждённого handshake peer",wg,"Проверь endpoint, UDP-порт, ключи, peer allowed-address и доступность сервера VPN.")
        else:
            add("ok","WireGuard",f"Handshake peer: {handshake.group(1)}",wg,"Туннель установил связь; дополнительно проверяем передачу трафика.")
        if failed("WireGuard interface"):
            add("info","WireGuard interface","Не удалось прочитать интерфейс WireGuard",raw["WireGuard interface"],"Проверь имя интерфейса и права SSH.")
        elif not nonempty("WireGuard interface"):
            add("bad","WireGuard interface","Интерфейс WireGuard не найден",raw["WireGuard interface"],"Сверь имя интерфейса в настройках приложения с RouterOS.")
        if failed("VPN default route"):
            add("info","Policy routing","Не удалось прочитать VPN default route",raw["VPN default route"],"Проверь права SSH и имя routing table.")
        elif not nonempty("VPN default route") or "inactive" in raw["VPN default route"].lower() or f"gateway={f['wg_interface']}" not in raw["VPN default route"]:
            add("bad","Policy routing","Нет активного default route через ожидаемый WireGuard-интерфейс в VPN-таблице",raw["VPN default route"],"Проверь routing table, gateway=WireGuard и флаг активности маршрута.")
        if failed("VPN interface ping"):
            add("info","Трафик через WireGuard","Проба ping через WG не выполнилась",raw["VPN interface ping"],"Проверь поддержку параметра interface в этой версии RouterOS. Это не доказывает отказ туннеля.")
        elif not nonempty("VPN interface ping") or "received=0" in raw["VPN interface ping"].lower() or "packet-loss=100%" in raw["VPN interface ping"].lower():
            add("warn","Трафик через WireGuard","Проверочный ping через интерфейс WireGuard не подтвердился",raw["VPN interface ping"],"Если handshake есть, проверь удалённый AllowedIPs/маршрут, NAT на VPN-сервере и ICMP-фильтрацию.")
        else:
            add("ok","Трафик через WireGuard","Проверочный ping через WireGuard получил ответ",raw["VPN interface ping"],"Туннель передаёт тестовый трафик.")
        mangle=raw["Managed Mangle"]
        mangle_entries=parse_terse(mangle) if not failed("Managed Mangle") else []
        managed_mangle=next((x for x in mangle_entries if x["f"].get("comment")==MANGLE_COMMENT),None)
        if failed("Managed Mangle"):
            add("info","Mangle / policy routing","Не удалось прочитать управляемое правило",mangle,"Проверь права SSH и команду /ip firewall mangle print terse.")
        elif managed_mangle is None:
            add("bad","Mangle / policy routing","Управляемое правило маркировки не найдено",mangle,"Проверь наличие правила VPN-MANAGER-DOMAIN-ROUTE.")
        elif "X" in managed_mangle["flags"]:
            add("bad","Mangle / policy routing","Управляемое правило Mangle отключено",mangle,"Включай правило только после проверки VPN default route и NAT.")
        elif managed_mangle["f"].get("action")!="mark-routing" or managed_mangle["f"].get("new-routing-mark")!=f["route_table"]:
            add("bad","Mangle / policy routing","Правило найдено, но параметры mark-routing не совпадают с профилем",mangle,"Проверь action, new-routing-mark, passthrough, chain и address-list.")
        else:
            add("ok","Mangle / policy routing","Управляемое правило найдено",mangle,"Сверь счётчики packets/bytes во время тестового обращения к домену.")

        if domain:
            if not route_probe_ips:
                add("info","Фактический маршрут домена",f"Для {domain} не удалось получить IPv4 из DNS-ответа; route lookup не выполнен",raw.get("Selected domain DNS resolve",""),"Сделай DNS-запрос с клиента и повтори проверку. Для IPv6 нужен отдельный анализ IPv6-маршрутизации.")
            for probe_ip in route_probe_ips[:5]:
                vpn_key=f"Route lookup {probe_ip} · vpn"
                vpn_route=raw.get(vpn_key,"")
                if vpn_route.startswith("ERROR:"):
                    add("info","Фактический маршрут домена",f"Не удалось проверить активный маршрут {probe_ip} в таблице {f['route_table']}",vpn_route,"Проверь поддержку фильтрации по адресу и routing-table в RouterOS.")
                elif not vpn_route.strip():
                    add("warn","Фактический маршрут домена",f"Для {probe_ip} не найден активный маршрут в VPN-таблице {f['route_table']}",vpn_route,"Проверь default route и более специфичные маршруты в VPN-таблице.")
                elif f["wg_interface"].lower() in vpn_route.lower():
                    add("ok","Фактический маршрут домена",f"Активный маршрут {probe_ip} в VPN-таблице указывает на {f['wg_interface']}",vpn_route,"Это подтверждает маршрут внутри VPN-таблицы. Для подтверждения прохождения LAN-пакетов дополнительно нужны срабатывание Mangle и динамическая запись IP в address-list.")
                else:
                    add("warn","Фактический маршрут домена",f"Маршрут {probe_ip} в VPN-таблице найден, но WireGuard-интерфейс {f['wg_interface']} в next-hop не подтверждён",vpn_route,"Проверь gateway/immediate-gw и более специфичные маршруты VPN-таблицы.")

        nat=raw["Managed NAT"]
        if failed("Managed NAT"):
            add("info","NAT через WireGuard","Не удалось прочитать NAT-правила",nat,"Проверь права SSH и совместимость команды /ip firewall nat print terse.")
        else:
            nat_entries=parse_terse(nat)
            wg_nat=next((x for x in nat_entries
                         if "X" not in x["flags"]
                         and x["f"].get("chain")=="srcnat"
                         and x["f"].get("action")=="masquerade"
                         and x["f"].get("out-interface")==f["wg_interface"]
                         and x["f"].get("src-address")==f["lan_subnet"]),None)
            if wg_nat:
                managed=wg_nat["f"].get("comment")==NAT_COMMENT
                label="Управляемое masquerade-правило найдено" if managed else "Подходящее masquerade-правило найдено (создано вне приложения)"
                add("ok","NAT через WireGuard",label,nat,"Проверь счётчики этого правила при реальном трафике.")
            elif not nat.strip():
                add("warn","NAT через WireGuard","RouterOS не вернул NAT-правила",nat,"Проверь таблицу /ip firewall nat и параметры src-address/out-interface.")
            else:
                add("bad","NAT через WireGuard","Не найдено активное masquerade-правило с ожидаемыми LAN и WireGuard-интерфейсом",nat,"Сверь точные src-address и out-interface в полном выводе NAT; правило может быть настроено с другим именем интерфейса или подсетью.")

        filt=raw["Firewall filter"]
        filter_entries=parse_terse(filt) if not failed("Firewall filter") else []
        active_fasttrack=any(x["f"].get("action")=="fasttrack-connection" and "X" not in x["flags"] for x in filter_entries)
        fasttrack_counter_entries=parse_terse(raw["FastTrack counters"]) if not failed("FastTrack counters") else []
        fasttrack_entries=[x for x in fasttrack_counter_entries if x["f"].get("action")=="fasttrack-connection" and "X" not in x["flags"]]
        if not fasttrack_entries:
            fasttrack_entries=[x for x in filter_entries if x["f"].get("action")=="fasttrack-connection" and "X" not in x["flags"]]
        if active_fasttrack:
            ft_summary=[]
            for entry in fasttrack_entries:
                fields=entry["f"]
                ft_summary.append("comment="+fields.get("comment","(без комментария)")+
                                  ", chain="+fields.get("chain","?")+
                                  ", packets="+fields.get("packets","?")+
                                  ", bytes="+fields.get("bytes","?"))
            add("warn","Firewall / FastTrack",f"Активно FastTrack-правил: {len(fasttrack_entries)}; оно может обходить часть policy routing","\n".join(ft_summary) or filt,"Проверь, исключены ли соединения, которым нужен policy routing, до FastTrack. Сверь счётчики до/после теста. Наличие FastTrack само по себе не доказывает обход VPN.")
        elif not failed("Firewall filter"):
            add("ok","Firewall / FastTrack","Активных FastTrack-правил не обнаружено",filt,"Повторная проверка нужна после изменения Firewall.")
        if failed("Firewall filter"):
            add("info","DNS security","Не удалось прочитать filter-правила; состояние блокировок DoT/DoQ не подтверждено",filt,"Проверь права SSH и повтори /ip firewall filter print terse.")
        else:
            def active_drop(protocol,port,comment):
                return any("X" not in x["flags"]
                           and x["f"].get("chain")=="forward"
                           and x["f"].get("action")=="drop"
                           and x["f"].get("protocol")==protocol
                           and x["f"].get("dst-port")==str(port)
                           and comment in x["f"].get("comment","")
                           for x in filter_entries)
            dot_ok=active_drop("tcp",853,"BLOCK-DOT")
            doq_ok=active_drop("udp",853,"BLOCK-DOQ")
            if dot_ok:
                add("ok","Блокировка DoT","Активное правило BLOCK-DOT для TCP/853 найдено",filt,"Счётчики правила подтвердят, что клиенты действительно пытались использовать DoT.")
            else:
                add("warn","Блокировка DoT","Активное правило BLOCK-DOT для TCP/853 не найдено",filt,"Проверь /ip firewall filter: chain=forward protocol=tcp dst-port=853 action=drop и comment BLOCK-DOT.")
            if doq_ok:
                add("ok","Блокировка DoQ","Активное правило BLOCK-DOQ для UDP/853 найдено",filt,"Счётчики правила подтвердят, что клиенты действительно пытались использовать DoQ.")
            else:
                add("warn","Блокировка DoQ","Активное правило BLOCK-DOQ для UDP/853 не найдено",filt,"Проверь /ip firewall filter: chain=forward protocol=udp dst-port=853 action=drop и comment BLOCK-DOQ.")

        dns_redirect=raw["DNS redirect NAT"]
        if failed("DNS redirect NAT"):
            add("info","DNS redirect","Не удалось прочитать DNS redirect NAT",dns_redirect,"Проверь права SSH и команду /ip firewall nat print terse.")
        else:
            redirect_entries=parse_terse(dns_redirect)
            udp53=any(x["f"].get("protocol")=="udp" and x["f"].get("dst-port")=="53" and x["f"].get("action")=="redirect" and x["f"].get("chain")=="dstnat" and "X" not in x["flags"] for x in redirect_entries)
            tcp53=any(x["f"].get("protocol")=="tcp" and x["f"].get("dst-port")=="53" and x["f"].get("action")=="redirect" and x["f"].get("chain")=="dstnat" and "X" not in x["flags"] for x in redirect_entries)
            if not udp53 or not tcp53:
                missing=("UDP/53" if not udp53 else "")+(" и " if not udp53 and not tcp53 else "")+("TCP/53" if not tcp53 else "")
                add("warn","DNS redirect",f"Не подтверждён redirect {missing} на DNS MikroTik",dns_redirect,"Проверь отдельные правила redirect для UDP/53 и TCP/53, а также порядок и исключения.")
            else:
                add("ok","DNS redirect","Redirect UDP/53 и TCP/53 обнаружен",dns_redirect,"Проверь счётчики этих правил после DNS-запроса клиента.")
        if not nonempty("DNS static FWD"):
            add("info","DNS FWD","Управляемые DNS static записи не найдены",raw["DNS static FWD"],"Это нормально, если список доменов пуст; иначе проверь импорт и применение целей.")
        if failed("IPv6 settings"):
            add("info","IPv6 settings","Не удалось прочитать глобальные настройки IPv6",raw["IPv6 settings"],"Проверь доступность меню /ipv6 settings и права SSH.")
        elif has("IPv6 settings",r"disable-ipv6:\s*yes"):
            add("ok","IPv6 settings","IPv6 глобально отключён в RouterOS",raw["IPv6 settings"],"Проверь также настройки IPv6 на клиентах и наличие других маршрутизаторов в LAN.")
        else:
            add("info","IPv6 settings","IPv6 не подтверждён как глобально отключённый",raw["IPv6 settings"],"Сопоставь настройки IPv6 с default route и IPv6 firewall; отсутствие default route не исключает другие IPv6-пути.")
        ipv6_addresses=raw.get("IPv6 addresses","")
        ipv6_global=bool(re.search(r"address=(?!fe80:|::1|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)[0-9a-f:]+",ipv6_addresses,re.I))
        ipv6_route=raw.get("IPv6 default route","")
        ipv6_nd=raw.get("IPv6 Neighbor Discovery / Router Advertisements","")
        if failed("IPv6 addresses") or failed("IPv6 firewall") or failed("IPv6 Neighbor Discovery / Router Advertisements"):
            add("info","IPv6 security","Не все проверки IPv6-адресов, firewall и Router Advertisements удалось выполнить",
                "\n".join(x for x in (ipv6_addresses,raw.get("IPv6 firewall",""),ipv6_nd) if x.startswith("ERROR:")),
                "Проверь доступность /ipv6 address, /ipv6 firewall filter и /ipv6 nd. Не считай IPv6 безопасным только потому, что одна команда не выполнилась.")
        elif ipv6_global and nonempty("IPv6 default route"):
            add("warn","IPv6 / возможный обход VPN","Обнаружен глобальный IPv6-адрес и IPv6 default route; IPv4 policy routing не охватывает этот путь",
                ipv6_addresses+"\n"+ipv6_route+"\nIPv6 firewall:\n"+raw.get("IPv6 firewall","")+"\nND/RA:\n"+ipv6_nd,
                "Проверь, получают ли LAN-клиенты IPv6 через RA, и отдельно спроектируй IPv6 policy routing или контролируемую блокировку IPv6. Ничего автоматически не отключать.")
        elif nonempty("IPv6 default route"):
            add("warn","IPv6","Обнаружен IPv6 default route; IPv4 policy routing не управляет им автоматически",ipv6_route,"Проверь IPv6 DNS, адреса клиентов, firewall и RA отдельно.")
        else:
            add("info","IPv6","IPv6 default route не обнаружен в выводе; это не исключает локальные IPv6-маршруты или другой маршрутизатор",ipv6_addresses+"\n"+ipv6_nd,"Сверь IPv6-настройки на клиенте и объявления Router Advertisement в LAN.")
        if not failed("Recent network errors") and raw["Recent network errors"].strip():
            add("info","Журнал RouterOS","В журнале есть сетевые ошибки/предупреждения",raw["Recent network errors"],"Сопоставь timestamp записи со временем отказа; старые записи сами по себе не доказывают текущую неисправность.")

        # A command failure is reported as an unsupported/permission-limited check,
        # not automatically treated as proof that the underlying subsystem is down.
        for title,value in raw.items():
            if value.startswith("ERROR:"):
                add("info","Проверка не выполнена",title+": команда завершилась ошибкой",value,"Проверь совместимость команды с версией RouterOS и права пользователя. Это не равнозначно отказу сервиса.")

        critical=sum(1 for x in findings if x["level"]=="bad")
        warnings=sum(1 for x in findings if x["level"]=="warn")
        passed=sum(1 for x in findings if x["level"]=="ok")
        overall="КРИТИЧЕСКАЯ ПРОБЛЕМА" if critical else ("ЕСТЬ ПРЕДУПРЕЖДЕНИЯ" if warnings else "КРИТИЧЕСКИХ ОТКЛОНЕНИЙ НЕ НАЙДЕНО")
        dns_text=raw["DNS configuration"]
        doh_ok=has("DNS configuration",r"use-doh-server:\s*https://") and has("DNS configuration",r"verify-doh-cert:\s*yes")
        remote_ok=has("DNS configuration",r"allow-remote-requests:\s*yes")
        redirect_entries=parse_terse(raw["DNS redirect NAT"]) if not failed("DNS redirect NAT") else []
        redirect_udp=any(x["f"].get("chain")=="dstnat" and x["f"].get("action")=="redirect" and x["f"].get("protocol")=="udp" and x["f"].get("dst-port")=="53" and "X" not in x["flags"] for x in redirect_entries)
        redirect_tcp=any(x["f"].get("chain")=="dstnat" and x["f"].get("action")=="redirect" and x["f"].get("protocol")=="tcp" and x["f"].get("dst-port")=="53" and "X" not in x["flags"] for x in redirect_entries)
        filter_entries=parse_terse(raw["Firewall filter"]) if not failed("Firewall filter") else []
        dot_ok=any(x["f"].get("chain")=="forward" and x["f"].get("action")=="drop" and x["f"].get("protocol")=="tcp" and x["f"].get("dst-port")=="853" and "BLOCK-DOT" in x["f"].get("comment","") and "X" not in x["flags"] for x in filter_entries)
        doq_ok=any(x["f"].get("chain")=="forward" and x["f"].get("action")=="drop" and x["f"].get("protocol")=="udp" and x["f"].get("dst-port")=="853" and "BLOCK-DOQ" in x["f"].get("comment","") and "X" not in x["flags"] for x in filter_entries)
        fwd_entries=parse_terse(raw["DNS static FWD"]) if not failed("DNS static FWD") else []
        managed_fwd_count=len([x for x in fwd_entries if "VPN-MANAGER:" in x["f"].get("comment","")])
        ip_entries=parse_terse(raw["VPN address-list"]) if not failed("VPN address-list") else []
        managed_ip_count=len([x for x in ip_entries if "X" not in x["flags"]])
        ipv6_present=nonempty("IPv6 default route") and not failed("IPv6 default route")
        dns_flags=[doh_ok,redirect_udp and redirect_tcp,dot_ok and doq_ok,remote_ok]
        dns_count=sum(bool(x) for x in dns_flags)
        result={
            "Маршрутизатор":raw["Router identity"].replace("name:","").strip() or "ответ получен",
            "Проверяемый домен":domain or "не задан",
            "Итог диагностики":overall,
            "Проблемы":str(critical),
            "Предупреждения":str(warnings),
            "Успешные проверки":str(passed),
            "WireGuard handshake":handshake.group(1) if handshake else "не подтверждён",
            "VPN default route":"найден" if nonempty("VPN default route") and "inactive" not in raw["VPN default route"].lower() and f"gateway={f['wg_interface']}" in raw["VPN default route"] else "не подтверждён",
            "DoH":"включён" if doh_ok else "не подтверждён",
            "DNS redirect UDP/TCP":"UDP + TCP" if redirect_udp and redirect_tcp else ("UDP" if redirect_udp else ("TCP" if redirect_tcp else "не обнаружен")),
            "DoT/DoQ block":"TCP/853 + UDP/853" if dot_ok and doq_ok else ("TCP/853" if dot_ok else ("UDP/853" if doq_ok else "не обнаружена")),
            "Remote requests":"включён" if remote_ok else "выключен",
            "DNS FWD":"есть" if managed_fwd_count else "нет",
            "DNS FWD count":str(managed_fwd_count),
            "VPN address-list":"есть" if managed_ip_count else "нет",
            "VPN address-list count":str(managed_ip_count),
            "IPv6 default route":"обнаружен" if ipv6_present else "не обнаружен",
            "DNS security":f"{dns_count}/4 обязательных проверок подтверждены; DoH, redirect :53, DoT/DoQ :853 и remote requests",
            "WAN ping":"успешен" if "received=0" not in raw["WAN ping"].lower() and not failed("WAN ping") else "не прошёл / нет данных",
            "VPN ping":"успешен" if "received=0" not in raw["VPN interface ping"].lower() and not failed("VPN interface ping") else "не прошёл / нет данных",
            "Windows DNS":"ошибка" if local["Windows DNS"].startswith("ERROR:") else "ответ получен",
            "Windows TCP 443":"недоступен" if local["Windows TCP 443"].startswith("ERROR:") else "доступен",
            "Windows TCP 1.1.1.1:443":"недоступен" if local["Windows TCP 1.1.1.1:443"].startswith("ERROR:") else "доступен",
        }
        self.q.put(("DIAG",(result,silent)))
        if not silent:
            # One report contains verdicts first, followed by the exact evidence
            # collected in this run. No need to re-run commands to inspect a finding.
            summary=[f"ИТОГ: {overall}",f"Проблем: {critical} · предупреждений: {warnings} · успешных проверок: {passed}",""]
            for item in findings:
                marker={"bad":"[ОШИБКА]","warn":"[ВНИМАНИЕ]","ok":"[OK]","info":"[ИНФО]"}.get(item["level"],"[?]")
                summary += [f"{marker} {item['area']}: {item['cause']}",f"  Действие: {item['action']}"]
                if item["level"] in ("bad","warn"):
                    summary.append(f"  Доказательство: {item['evidence'][:1200]}")
                summary.append("")
            self.q.put(("DIAGOUT",("Автоматический разбор · выводы и рекомендации","\n".join(summary),False,True)))
            self.q.put(("DIAGOUT",("Проверки на этом Windows-компьютере","\n".join(f"{k}: {v}" for k,v in local.items()),False,True)))
            for title,value in raw.items():
                self.q.put(("DIAGOUT",(title+" · собранное доказательство",value,False,False)))
        self.q.put(("LOG",f"Расширенная диагностика завершена: {critical} проблем, {warnings} предупреждений, {passed} успешных проверок. Все проверки read-only; конфигурация роутера не изменялась."))
        try:
            self.fetch_targets(r,raw)
        except Exception as exc:
            self.q.put(("LOG","Обновление статусов VPN-целей из собранного отчёта: "+str(exc)))
    def refresh_dashboard(self):
        if self.busy or not self.router: return
        def job(): self.diagnostics(self.router_conn(),False,True)
        self.run_job("Обновление dashboard…",job)

    def run_diagnostics(self):
        domain=""
        if hasattr(self,"domain_diag_input"):
            candidate=self.domain_diag_input.text().strip()
            if candidate:
                try:
                    normalized,kind=normalize_target(candidate)
                    if kind=="Домен": domain=normalized
                    else: raise ValueError("Для диагностики домена введи доменное имя, не IP/CIDR.")
                except Exception as exc:
                    QMessageBox.warning(self,"Некорректный домен",str(exc))
                    return
        self.run_job("Полная диагностика…",lambda:self.diagnostics(self.router_conn(),False,False,domain or None))

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
        self.log_view.setPlainText("\n".join(x for x in self.log_lines if q in x.lower()))
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def export_log_page(self):
        path,_=QFileDialog.getSaveFileName(self,"Экспорт журнала",str(Path.home()/"mikrotik-vpn-manager.log"),"Log files (*.log *.txt)")
        if path:
            Path(path).write_text("\n".join(self.log_lines),encoding="utf-8")
            self.log(f"Журнал экспортирован: {path}")

    def clear_log_page(self):
        if QMessageBox.question(self,"Очистить журнал","Удалить все записи текущего сеанса?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        self.log_lines.clear(); self.filter_log_page()
    
    def import_wireguard_conf(self):
        path,_=QFileDialog.getOpenFileName(self,"Импорт WireGuard-конфигурации",str(Path.home()),"WireGuard config (*.conf);;All files (*.*)")
        if not path: return
        try:
            raw=Path(path).read_text(encoding="utf-8-sig")
            sections=re.split(r"(?im)^\s*\[([^]]+)\]\s*$",raw)
            data={}
            for i in range(1,len(sections),2):
                section=sections[i].strip().lower(); block=sections[i+1]; vals={}
                for line in block.splitlines():
                    line=line.split("#",1)[0].strip()
                    if "=" in line:
                        k,v=line.split("=",1); vals[k.strip().lower()]=v.strip()
                data[section]=vals
            interface=data.get("interface",{}); peers=data.get("peer",{})
            if len(re.findall(r"(?im)^\s*\[Peer\]\s*$",raw)) != 1: raise ValueError("Поддерживается .conf с одним блоком [Peer].")
            if not interface.get("privatekey") or not peers.get("publickey") or not peers.get("endpoint"):
                raise ValueError("В .conf должны быть Interface: PrivateKey и Peer: PublicKey, Endpoint.")
            endpoint=peers["endpoint"]
            if endpoint.startswith("[") and "]:" in endpoint:
                host,port=endpoint[1:].split("]:",1)
            elif ":" in endpoint: host,port=endpoint.rsplit(":",1)
            else: raise ValueError("Endpoint должен содержать порт, например vpn.example:51820")
            values={"wg_private_key":interface["privatekey"],"wg_public_key":peers["publickey"],"wg_endpoint":host,"wg_port":port,
                    "wg_allowed":peers.get("allowedips","0.0.0.0/0"),"wg_address":interface.get("address","").split(",")[0].strip(),
                    "wg_keepalive":("0" if peers.get("persistentkeepalive","25").lower()=="off" else peers.get("persistentkeepalive","25")),"wg_mtu":interface.get("mtu",self.wg_inputs["wg_mtu"].text() or "1240")}
            for k,v in values.items():
                if k in self.wg_inputs: self.wg_inputs[k].setText(v)
            self.log(f"Импортирован WireGuard-профиль: {Path(path).name}. Проверь параметры перед применением.")
            QMessageBox.information(self,"Профиль загружен","Конфигурация прочитана. Проверь поля и нажми «Применить новый VPN-профиль».")
        except Exception as e: QMessageBox.critical(self,"Ошибка импорта",str(e))

    def apply_wireguard_profile(self):
        cfg={k:w.text().strip() for k,w in self.wg_inputs.items()}
        try:
            if len(base64.b64decode(cfg["wg_private_key"],validate=True))!=32: raise ValueError("PrivateKey должен быть корректным WireGuard-ключом (32 байта Base64).")
            if len(base64.b64decode(cfg["wg_public_key"],validate=True))!=32: raise ValueError("PublicKey должен быть корректным WireGuard-ключом.")
            try: ipaddress.ip_address(cfg["wg_endpoint"])
            except ValueError:
                if not re.fullmatch(r"[A-Za-z0-9.-]+",cfg["wg_endpoint"]): raise ValueError("Endpoint: укажи домен или IP без порта.")
            port=int(cfg["wg_port"])
            if not 1<=port<=65535: raise ValueError("Endpoint port должен быть от 1 до 65535.")
            keep=int(cfg["wg_keepalive"] or "0")
            if not 0<=keep<=65535: raise ValueError("Persistent keepalive должен быть от 0 до 65535 секунд.")
            allowed=[x.strip() for x in cfg["wg_allowed"].split(",") if x.strip()]
            if not allowed: raise ValueError("AllowedIPs не может быть пустым.")
            for net in allowed: ipaddress.ip_network(net,strict=False)
            if cfg["wg_address"]: ipaddress.ip_interface(cfg["wg_address"])
            mtu=int(cfg["wg_mtu"])
            if not 576<=mtu<=9000: raise ValueError("MTU должен быть в диапазоне 576–9000.")
            self.pending_wg_config=cfg
        except Exception as e: QMessageBox.warning(self,"Проверь WireGuard-профиль",str(e)); return
        if QMessageBox.question(self,"Сменить VPN-провайдера",
            "Применить новый WireGuard-профиль? Будут заменены ключ интерфейса, параметры peer и адрес WG-интерфейса (если указан). Правила маршрутизации, NAT, address-list и таблица vpn останутся без изменений.",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:
            self.pending_wg_config=None; return
        self.run_job("Применение нового WireGuard-профиля…",self._apply_wireguard_profile)

    def _apply_wireguard_profile(self):
        cfg=self.pending_wg_config
        if not cfg: raise RuntimeError("Профиль WireGuard не выбран.")
        r=self.router_conn(); wg=self.settings["wg_interface"]; q=ros_q
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}",wg): raise ValueError("Некорректное имя WireGuard-интерфейса.")
        exists=r.exec(f"/interface wireguard print count-only where name={q(wg)}").strip()
        if exists!="1": raise RuntimeError(f"Ожидался один WireGuard-интерфейс {wg}, найдено: {exists}.")
        peer_count=r.exec(f"/interface wireguard peers print count-only where interface={q(wg)}").strip()
        if peer_count not in ("0","1"): raise RuntimeError(f"На интерфейсе {wg} найдено peer: {peer_count}. Автоматически не выбираю, какой заменять.")
        peer_fields=f"public-key={q(cfg['wg_public_key'])} endpoint-address={q(cfg['wg_endpoint'])} endpoint-port={int(cfg['wg_port'])} allowed-address={q(cfg['wg_allowed'])} persistent-keepalive={int(cfg['wg_keepalive'])}s"
        if peer_count=="1": r.exec(f"/interface wireguard peers set [find where interface={q(wg)}] {peer_fields}",10)
        else: r.exec(f"/interface wireguard peers add interface={q(wg)} {peer_fields}",10)
        r.exec(f"/interface wireguard set [find where name={q(wg)}] private-key={q(cfg['wg_private_key'])} mtu={int(cfg['wg_mtu'])}",10)
        self.q.put(("LOG",f"Обновлены ключ и peer интерфейса {wg}; private-key скрыт в журнале."))
        if cfg["wg_address"]:
            addr=ipaddress.ip_interface(cfg["wg_address"])
            family="/ip address" if addr.version==4 else "/ipv6 address"
            r.exec(f"{family} remove [find where interface={q(wg)}]",10)
            r.exec(f"{family} add address={q(cfg['wg_address'])} interface={q(wg)} comment={q('VPN-MANAGER:WireGuard address')}",10)
        self.q.put(("LOG","Профиль применён. Mangle, NAT, address-list и default route не изменялись."))
        self.fetch_mangle_status(r)
        self.pending_wg_config=None
        self.q.put(("WG_APPLIED",None))

    def test_vpn(self):
        self.nav.setCurrentRow(2)
        iface=ros_q(self.settings["wg_interface"])
        self.run_diag_commands("Тест доступности через WireGuard",[
            ("Ping 1.1.1.1 через WireGuard",f"/tool ping address=1.1.1.1 interface={iface} count=5",25),
            ("Состояние WireGuard peer",f"/interface wireguard peers print detail where interface={iface}",20),
            ("VPN default route",f"/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(self.settings['route_table'])}",20),
        ],"Тест ping через VPN…")

    def ping_wan(self):
        self.run_diag_commands("Ping WAN · основной маршрут",[
            ("Ping 1.1.1.1 через основной маршрут","/tool ping address=1.1.1.1 count=5",25),
            ("Основной default route","/ip route print detail where dst-address=0.0.0.0/0 and routing-table=main",20),
        ],"Ping WAN…")

    def traceroute(self):
        command="/tool traceroute address=1.1.1.1 max-hops=12 count=1 timeout=1s use-dns=no"
        self.run_diag_commands("Traceroute через основной маршрут",[
            ("Traceroute 1.1.1.1",command,30),
        ],"Traceroute 1.1.1.1…")

    def show_dhcp_clients(self):
        self.run_diag_commands("DHCP-клиенты и ARP",[
            ("DHCP leases","/ip dhcp-server lease print detail",25),
            ("ARP clients",f'/ip arp print detail where interface={ros_q(self.settings["lan_interface"])}',20),
        ],"Получение списка LAN-клиентов…")

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
        self.run_diag_commands(f"Проверка LAN-клиента {ip}",[
            ("DHCP lease",f"/ip dhcp-server lease print detail where address={ip}",20),
            ("ARP entry",f"/ip arp print detail where address={ip}",20),
            ("Ping клиента с роутера",f"/tool ping address={ip} count=4",25),
            ("Conntrack-сессии клиента",f'/ip firewall connection print detail where src-address~{ros_q(ip)}',20),
            ("Mangle counters",f'/ip firewall mangle print stats detail where comment={ros_q(MANGLE_COMMENT)}',20),
            ("FastTrack rules and counters",'/ip firewall filter print stats detail where action=fasttrack-connection',20),
            ("IPv6 neighbors",'/ipv6 neighbor print detail',20),
            ("DNS redirect counters",'/ip firewall nat print stats detail where comment~"DNS-REDIRECT"',20),
            ("Client DNS cache",'/ip dns cache print detail where name~"youtube|discord|chatgpt|netflix|google"',20),
        ],f"Проверка IP клиента {ip}…")

    def diagnose_domain_route(self):
        raw=self.domain_diag_input.text().strip()
        try:
            domain,kind=normalize_target(raw)
            if kind!="Домен": raise ValueError("Введи доменное имя, а не IP/CIDR.")
            client_ip=""
            client_raw=self.client_input.text().strip()
            if client_raw:
                parsed_client=ipaddress.ip_address(client_raw)
                if parsed_client.version!=4 or parsed_client not in ipaddress.ip_network(self.settings["lan_subnet"],strict=False):
                    raise ValueError("IP клиента должен быть IPv4-адресом из LAN-подсети приложения.")
                client_ip=str(parsed_client)
        except Exception as e:
            QMessageBox.warning(self,"Некорректные параметры",str(e)); return
        def job():
            r=self.router_conn()
            commands=[
                ("DNS resolve через RouterOS",f":put [:resolve {ros_q(domain)}]"),
                ("DNS cache для домена",f"/ip dns cache print detail where name~{ros_q(domain)}"),
                ("Динамические IP, созданные DNS FWD",f"/ip firewall address-list print detail where list={ros_q(self.settings['address_list'])} and comment={ros_q('created for '+domain+'.')}"),
                ("Состояние управляемого FWD",f"/ip dns static print detail where comment={ros_q('VPN-MANAGER:'+domain)}"),
                ("Счётчики managed Mangle",f'/ip firewall mangle print stats detail where comment="{MANGLE_COMMENT}"'),
                ("WireGuard peer counters",f"/interface wireguard peers print detail where interface={ros_q(self.settings['wg_interface'])}"),
                ("VPN default route",f"/ip route print detail where routing-table={ros_q(self.settings['route_table'])}"),
                ("IPv6 settings", "/ipv6 settings print"),
                ("IPv6 default route", "/ipv6 route print detail where dst-address=::/0 and disabled=no"),
                ("FastTrack counters", "/ip firewall filter print stats detail"),
            ]
            self.q.put(("DIAGBEGIN",f"Диагностика маршрута домена {domain}"))
            resolved_ips=[]
            for title,command in commands:
                try: out=self.cmd(r,command,timeout=20)
                except Exception as e: out="ERROR: "+str(e)
                self.q.put(("DIAGOUT",(title+" · "+command,out,False,True)))
                if title=="DNS resolve через RouterOS" and not out.startswith("ERROR:"):
                    for candidate in re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])",out):
                        try:
                            ipaddress.IPv4Address(candidate)
                            if candidate not in resolved_ips: resolved_ips.append(candidate)
                        except ValueError:
                            pass
            for probe_ip in resolved_ips[:5]:
                for table_name,table_value in (("main","main"),("vpn",self.settings["route_table"])):
                    command=f"/ip route print detail where {probe_ip} in dst-address and active and routing-table={ros_q(table_value)}"
                    try: out=self.cmd(r,command,timeout=20)
                    except Exception as e: out="ERROR: "+str(e)
                    self.q.put(("DIAGOUT",(f"Активный маршрут {probe_ip} · {table_name} · {command}",out,False,True)))
                if client_ip:
                    command=f'/ip firewall connection print detail where src-address~{ros_q(client_ip)} and dst-address~{ros_q(probe_ip)}'
                    try: out=self.cmd(r,command,timeout=20)
                    except Exception as e: out="ERROR: "+str(e)
                    self.q.put(("DIAGOUT",(f"Conntrack клиента {client_ip} → {probe_ip} · {command}",out,False,True)))
                    if re.search(r"fasttrack=(?:yes|true)",out,re.I):
                        self.q.put(("DIAGOUT",("ВНИМАНИЕ · FastTrack для потока клиента",f"В conntrack обнаружен fasttrack=yes для {client_ip} → {probe_ip}. Это прямое свидетельство FastTrack для найденной записи соединения.",True,True)))
                    elif not out.startswith("ERROR:") and out.strip():
                        self.q.put(("DIAGOUT",("Conntrack · состояние потока",f"Запись соединения найдена для {client_ip} → {probe_ip}. Отсутствие поля fasttrack в выводе не является доказательством, что соединение не ускоряется.",False,True)))
            if client_ip:
                command=f'/ip firewall connection print count-only where src-address~{ros_q(client_ip)}'
                try: out=self.cmd(r,command,timeout=20)
                except Exception as e: out="ERROR: "+str(e)
                self.q.put(("DIAGOUT",(f"Активные conntrack-записи клиента {client_ip} · {command}",out,False,True)))
            if not resolved_ips:
                self.q.put(("DIAGOUT",("Проверка активного маршрута","IPv4 из DNS-ответа не получен; route lookup не выполнялся. Для IPv6 требуется отдельная проверка.",False,True)))
            self.q.put(("LOG",f"Собраны DNS/address-list/Mangle/WireGuard/route-table evidence для {domain}. Счётчики Mangle и peer глобальные, не per-domain."))
        self.run_job(f"Проверка маршрута домена {domain}…",job)

    def show_policy_counters(self):
        self.run_diag_commands("Счётчики Mangle / NAT / DNS",[
            ("Mangle counters",f'/ip firewall mangle print stats detail where comment={ros_q(MANGLE_COMMENT)}',20),
            ("Managed NAT counters",f'/ip firewall nat print stats detail where comment={ros_q(NAT_COMMENT)}',20),
            ("DNS redirect counters",'/ip firewall nat print stats detail where comment~"DNS-REDIRECT"',20),
            ("DNS filter counters",'/ip firewall filter print stats detail where comment~"BLOCK-DOT|BLOCK-DOQ"',20),
            ("VPN address-list",f'/ip firewall address-list print detail where list={ros_q(self.settings["address_list"])}',20),
            ("DNS cache",'/ip dns cache print count-only',20),
        ],"Сбор счётчиков Mangle/DNS…")

    def set_managed_mangle(self,enabled):
        action="mangle_enable" if enabled else "mangle_disable"
        title="Включить выборочную VPN-маршрутизацию" if enabled else "Отключить выборочную VPN-маршрутизацию"
        self.queue_change(action,title)


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
                self.targets.append((target,kind)); self.target_groups[target]="Импорт"; existing.add(target); added+=1
            self.save_settings(); self.render_targets()
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
        try:
            stored=json.loads(self.settings.get("managed_targets", "[]"))
            self.targets=[(str(t), str(k)) for t,k in stored if isinstance(t,str) and isinstance(k,str)]
        except Exception:
            self.targets=[]
        self.render_targets()
    def add_target(self):
        try:
            t,k=normalize_target(self.target_input.text())
            group=self.target_group.currentText().strip() if hasattr(self,"target_group") else "Пользовательские"
            if not group:
                group="Пользовательские"
            if len(group)>64 or any(ord(ch)<32 for ch in group):
                raise ValueError("Название группы должно содержать не более 64 обычных символов.")
        except Exception as e:
            QMessageBox.warning(self,"Некорректная цель или группа",str(e)); return
        existing=next((x for x in self.targets if x[0]==t),None)
        changed=False
        if existing is None:
            self.targets.append((t,k)); changed=True
        if self.target_groups.get(t)!=group:
            self.target_groups[t]=group; changed=True
        if hasattr(self,"target_group") and self.target_group.findText(group)<0:
            self.target_group.addItem(group)
        if changed:
            self.save_settings(); self.render_targets()
            self.log(f"Цель {t} добавлена/перемещена в группу «{group}».")
        self.target_input.clear()
    def auto_discover_targets(self):
        dlg = AutoDiscoveryDialog(self, self.request_discovery_dns_cache)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        existing = {target for target, _kind in self.targets}
        added = 0
        for target, kind, group in dlg.selected_target_records():
            if target not in existing:
                self.targets.append((target, kind))
                self.target_groups[target] = group
                existing.add(target)
                added += 1
            elif group:
                self.target_groups[target] = group
        self.save_settings()
        self.render_targets()
        self.log(f"Автоопределение: добавлено {added} целей; IP добавляются только по отдельному флажку.")
        if added:
            QMessageBox.information(self, "Зависимости добавлены", f"Добавлено целей: {added}.\nОни пока находятся только в приложении. Для отправки на MikroTik используй «Подготовить применение» и затем подтверди очередь изменений.")
        else:
            QMessageBox.information(self, "Новых целей нет", "Выбранные домены/IP уже присутствуют в списке или ничего не выбрано.")

    def request_discovery_dns_cache(self, dialog):
        if self.busy:
            return
        command = "/ip dns cache print detail without-paging"
        def job():
            router = self.router_conn()
            output = self.cmd(router, command, 30)
            self.q.put(("DISCOVERY_DNS_CACHE", (dialog, output)))
        self.run_job("Загрузка DNS-кэша MikroTik для автоопределения…", job)

    def load_all_presets(self):
        n=0
        for items in PRESETS.values():
            for raw in items:
                try: t,k=normalize_target(raw)
                except Exception: continue
                if not any(x[0]==t for x in self.targets): self.targets.append((t,k)); self.target_groups[t]=next((name for name, values in PRESETS.items() if raw in values), "Профили"); n+=1
        self.save_settings(); self.render_targets(); self.log(f"Все профили ({len(PRESETS)}): добавлено {n} целей, дубликаты пропущены")

    def load_preset(self):
        name=self.preset.currentText(); n=0
        if hasattr(self,"target_group"):
            self.target_group.setCurrentText(name)
        for raw in PRESETS[name]:
            try: t,k=normalize_target(raw)
            except: continue
            if not any(x[0]==t for x in self.targets): self.targets.append((t,k)); self.target_groups[t]=name; n+=1
        self.save_settings(); self.render_targets(); self.log(f"Профиль {name}: добавлено {n} целей в группу «{name}»")
    def render_targets(self):
        if not hasattr(self,"target_table"): return
        found=self.router_state["found"] if self.router_state else {}
        local={t for t,_ in self.targets}
        rows=[(t,k,True) for t,k in self.targets]+[(t,f[0],False) for t,f in found.items() if t not in local]
        rows.sort(key=lambda row:(self.target_groups.get(row[0], "На роутере" if not row[2] else "Пользовательские").casefold(),row[0].casefold()))
        self.target_table.clear()
        if hasattr(self,"targets_empty"): self.targets_empty.setVisible(not rows)
        self.target_table.setVisible(bool(rows))
        groups={}
        self._updating_target_checks = True
        for t,k,is_local in rows:
            f=found.get(t)
            group=self.target_groups.get(t,"Пользовательские") if is_local else "На роутере"
            if group not in groups:
                root=QTreeWidgetItem([f"▰  {group}","Группа",f"{sum(1 for _t,_k,_local in rows if (self.target_groups.get(_t, 'Пользовательские') if _local else 'На роутере') == group)} целей","","","",""])
                root.setData(0,Qt.ItemDataRole.UserRole,("group",group))
                root.setFlags(root.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                root.setCheckState(0, Qt.CheckState.Unchecked)
                root.setToolTip(0,"Поставь галочку, чтобы выбрать всю группу. Затем нажми нужное действие удаления.")
                font=root.font(0); font.setBold(True); root.setFont(0,font)
                root.setExpanded(True)
                groups[group]=root
                self.target_table.addTopLevelItem(root)
            parent=groups[group]
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
            values=(f"   ◦  {t}",k,source,local_label,remote,target_state,detail)
            item=QTreeWidgetItem(list(values))
            item.setData(0,Qt.ItemDataRole.UserRole,t)
            item.setData(0,Qt.ItemDataRole.UserRole+1,k)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setToolTip(0,"Поставь галочку для выбора этой цели. Можно отметить несколько целей из разных групп.")
            item.setForeground(4,QBrush(QColor(TONES[remote_tone])))
            item.setForeground(5,QBrush(QColor(TONES[state_tone])))
            for col in (4,5):
                ft=item.font(col); ft.setBold(True); item.setFont(col,ft)
            parent.addChild(item)
            # DNS cache addresses are shown as informational children of their domain.
            # They are not independent routing targets and are never selected for apply/remove.
            if k=="Домен" and f is not None:
                resolved=f[6] if len(f)>6 else []
                matched=set(f[7]) if len(f)>7 else set()
                for ip in resolved:
                    in_list=ip in matched
                    ip_item=QTreeWidgetItem([f"      ↳  {ip}","DNS IP","DNS cache","Автоопределено","В address-list" if in_list else "Не в address-list","Справочно","DNS-ответ домена; может быть общим CDN-адресом"])
                    ip_item.setData(0,Qt.ItemDataRole.UserRole,None)
                    ip_item.setToolTip(0,"Информационная DNS-запись. Для маршрутизации добавь IP отдельно как самостоятельную цель.")
                    ip_item.setForeground(4,QBrush(QColor(TONES["ok" if in_list else "muted"])))
                    ip_item.setForeground(5,QBrush(QColor(TONES["muted"])))
                    item.addChild(ip_item)
        self._updating_target_checks = False
        self.filter_targets(self.target_search.text() if hasattr(self,"target_search") else "")
        if hasattr(self,"active_table"): self.render_active()

    def filter_targets(self,text):
        if not hasattr(self,"target_table"): return
        needle=text.casefold().strip()
        for gi in range(self.target_table.topLevelItemCount()):
            group=self.target_table.topLevelItem(gi)
            group_visible=not needle or needle in group.text(0).casefold()
            visible_children=0
            for di in range(group.childCount()):
                node=group.child(di)
                own_match=not needle or any(needle in node.text(c).casefold() for c in range(node.columnCount()))
                child_match=False
                for ii in range(node.childCount()):
                    child=node.child(ii)
                    match=not needle or any(needle in child.text(c).casefold() for c in range(child.columnCount()))
                    child.setHidden(bool(needle) and not (own_match or match))
                    child_match=child_match or match
                node.setHidden(bool(needle) and not (group_visible or own_match or child_match))
                if not node.isHidden(): visible_children+=1
            group.setHidden(bool(needle) and not (group_visible or visible_children))
            if needle and visible_children: group.setExpanded(True)

    def set_all_target_checks(self, checked):
        if not hasattr(self, "target_table"):
            return
        self._updating_target_checks = True
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for index in range(self.target_table.topLevelItemCount()):
            group = self.target_table.topLevelItem(index)
            group.setCheckState(0, state)
            for child_index in range(group.childCount()):
                group.child(child_index).setCheckState(0, state)
        self._updating_target_checks = False

    def on_target_item_changed(self, item, column):
        """Keep group checkboxes in sync with their child targets."""
        if column != 0 or getattr(self, "_updating_target_checks", False):
            return
        marker = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(marker, tuple) and marker and marker[0] == "group":
            checked = item.checkState(0) == Qt.CheckState.Checked
            self._updating_target_checks = True
            for index in range(item.childCount()):
                child = item.child(index)
                child.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
            self._updating_target_checks = False

    def selected_targets(self):
        """Collect all checked and row-selected targets, expanding selected groups."""
        selected=[]
        if not hasattr(self,"target_table"): return selected
        selected_items = self.target_table.selectedItems()
        def walk(item, inherited=False):
            marker = item.data(0, Qt.ItemDataRole.UserRole)
            is_group = isinstance(marker, tuple) and marker and marker[0] == "group"
            chosen = inherited or item in selected_items or item.checkState(0) == Qt.CheckState.Checked
            target = item.data(0, Qt.ItemDataRole.UserRole)
            kind = item.data(0, Qt.ItemDataRole.UserRole+1)
            if target and kind and chosen and (target,kind) not in selected:
                selected.append((target,kind))
            for index in range(item.childCount()):
                walk(item.child(index), chosen if is_group else False)
        for index in range(self.target_table.topLevelItemCount()):
            walk(self.target_table.topLevelItem(index))
        return selected

    def remove_local(self):
        """Immediately remove selected local targets; group selection removes all its members."""
        if not hasattr(self, "target_table"):
            return

        selected_items = self.target_table.selectedItems()
        current_item = self.target_table.currentItem()
        selected = set()
        selected_group_names = set()

        def row_is_selected(item):
            return item is current_item or item.isSelected() or item.checkState(0) == Qt.CheckState.Checked

        for index in range(self.target_table.topLevelItemCount()):
            group_item = self.target_table.topLevelItem(index)
            marker = group_item.data(0, Qt.ItemDataRole.UserRole)
            if not (isinstance(marker, tuple) and len(marker) == 2 and marker[0] == "group"):
                continue

            group_name = str(marker[1])
            group_chosen = row_is_selected(group_item)
            if group_chosen:
                selected_group_names.add(group_name)

            for child_index in range(group_item.childCount()):
                child = group_item.child(child_index)
                target = child.data(0, Qt.ItemDataRole.UserRole)
                kind = child.data(0, Qt.ItemDataRole.UserRole + 1)
                if target and kind and (group_chosen or row_is_selected(child)):
                    if (target, kind) in self.targets:
                        selected.add((target, kind))

        # Resolve selected groups against the complete local configuration,
        # including entries not currently visible in the filtered tree.
        for target, kind in self.targets:
            if self.target_groups.get(target, "Пользовательские") in selected_group_names:
                selected.add((target, kind))

        if not selected:
            self.log("Удаление из приложения: нет выбранных локальных целей.")
            QMessageBox.information(
                self, "Нечего удалять",
                "Выдели строку группы/цели мышью или поставь галочку. "
                "Будут удалены только локальные записи; MikroTik не изменится."
            )
            return

        selected = sorted(selected, key=lambda record: record[0].casefold())
        selected_set = set(selected)
        removed_groups = {
            self.target_groups.get(target, "Пользовательские")
            for target, _kind in selected
        }

        before = len(self.targets)
        self.targets = [record for record in self.targets if record not in selected_set]
        removed = before - len(self.targets)
        for target, _kind in selected:
            self.target_groups.pop(target, None)

        remaining_groups = set(self.target_groups.values())
        if hasattr(self, "target_group"):
            for index in range(self.target_group.count() - 1, -1, -1):
                group_name = self.target_group.itemText(index)
                if (group_name not in remaining_groups and group_name not in PRESETS
                        and group_name != "Пользовательские"):
                    self.target_group.removeItem(index)

        self.save_settings()
        self.render_targets()
        self.log(
            f"Удалено из приложения: {removed} целей. Группы: "
            f"{', '.join(sorted(removed_groups, key=str.casefold))}. "
            "Конфигурация MikroTik не изменялась."
        )
        self.statusBar().showMessage(f"Из приложения удалено целей: {removed}", 6000)

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
        dlg=QDialog(self); dlg.resize(1000,720)
        lay=QVBoxLayout(dlg); lay.setContentsMargins(14,12,14,14); lay.setSpacing(12)
        add_dialog_chrome(dlg,lay,"Предпросмотр изменений")
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

    def pending_action_details(self,a):
        """Пояснение, команды RouterOS и проверки для одной операции."""
        k=a["kind"]; f=dict(self.settings); f.update(self.fields() if hasattr(self,"inputs") else {}); commands=[]; checks=[]
        if k=="setup_vpn_routing":
            commands=[f'/routing table print detail where name={ros_q(f["route_table"])}',f'/routing table add name={ros_q(f["route_table"])} fib  # если отсутствует',f'/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(f["route_table"])}',f'/ip route add dst-address=0.0.0.0/0 gateway={ros_q(f["wg_interface"])} routing-table={ros_q(f["route_table"])} comment="VPN-MANAGER-DEFAULT"  # если отсутствует',mangle_cmd(f),nat_cmd(f)]
            description="Проверить LAN/DNS/DHCP/WireGuard и отсутствие конфликтов; создать только отсутствующие routing table, default route, Mangle и NAT."
            checks=["Таблица VPN существует","Default route активен через WireGuard","Mangle направляет выбранные цели в VPN-таблицу","NAT masquerade работает через WireGuard","Проверить ping и доступ с LAN-клиента"]
        elif k=="apply_targets":
            commands += ["/ip dns print", "/ip dhcp-server network print detail", f'/ip route print detail where routing-table={ros_q(f["route_table"])}', "/ip firewall filter print detail", "/ip firewall mangle print detail", "/ip firewall nat print detail", "# Условно добавляются, если управляемые правила отсутствуют", mangle_cmd(f), nat_cmd(f)]
            commands += [target_cmd(f,t,kind) for t,kind in a.get("targets",[])] + ["/ip dns cache flush"]
            description=f"Проверить prerequisites и добавить {len(a.get('targets',[]))} VPN-целей. Недостающие управляемые Mangle/NAT создаются; сторонние правила не перезаписываются."
            checks=["allow-remote-requests включён",f"DHCP выдаёт LAN DNS {f['lan_dns']}",f"В таблице {f['route_table']} активен default route через {f['wg_interface']}","Нет FastTrack и конфликтующих сторонних mark-routing правил","Проверить DNS FWD/address-list; для доменов дождаться DNS-запроса клиента"]
        elif k=="remove_selected":
            for t,kind in a.get("targets",[]):
                comment=f"VPN-MANAGER:{t}" if kind=="Домен" else f"VPN-MANAGER-CIDR:{t}"
                path="/ip dns static" if kind=="Домен" else "/ip firewall address-list"
                commands.append(f'{path} remove [find where comment={ros_q(comment)}]')
            commands.append("/ip dns cache flush")
            description=f"Удалить {len(a.get('targets',[]))} выбранных управляемых записей. Другие записи не затрагиваются."
            checks=["Проверить, что выбранные записи исчезли","Убедиться, что нужные цели не удалены по ошибке"]
        elif k in ("mangle_enable","mangle_disable"):
            verb="enable" if k=="mangle_enable" else "disable"
            commands=[f'/ip firewall mangle print detail where comment={ros_q(MANGLE_COMMENT)}',f'/ip firewall mangle {verb} [find where comment={ros_q(MANGLE_COMMENT)}]']
            description="Включить выборочную маршрутизацию через WireGuard." if verb=="enable" else "Отключить выборочную маршрутизацию; трафик вернётся к обычному выбору маршрута."
            checks=["Найдено ровно одно управляемое Mangle-правило","Проверить статус правила и доступность нужных сайтов"]
        elif k=="doh_config":
            if a.get("enabled"):
                bootstrap=a.get("bootstrap","").strip()
                if bootstrap:
                    ips=[str(ipaddress.ip_address(x.strip())) for x in bootstrap.split(",") if x.strip()]
                    commands.append(f'/ip dns set servers={",".join(ips)}')
                commands += [f'/ip dns set use-doh-server={ros_q(a["url"])} verify-doh-cert=yes',"/ip dns cache flush"]
                description=f"Включить DoH {a['url']}, проверку TLS-сертификата и указанные bootstrap DNS."
            else:
                commands=['/ip dns set use-doh-server="" verify-doh-cert=no',"/ip dns cache flush"]
                description="Отключить DoH; RouterOS будет использовать обычные DNS-серверы из параметра servers."
            checks=["Проверить /ip dns print: endpoint, servers, verify-doh-cert","Проверить разрешение нескольких доменов","Убедиться, что LAN-клиенты получают DNS-ответы"]
        elif k=="fix_all":
            commands += ["/ip dns print", "/ip dhcp-server network print detail", f'/ip route print detail where routing-table={ros_q(f["route_table"])}', "/ip firewall filter print detail", "/ip firewall mangle print detail", "/ip firewall nat print detail", "# Условно создаются отсутствующие правила", mangle_cmd(f), nat_cmd(f)]
            if a.get("enabled"):
                bootstrap=a.get("bootstrap","").strip()
                if bootstrap:
                    ips=[str(ipaddress.ip_address(x.strip())) for x in bootstrap.split(",") if x.strip()]
                    commands.append(f'/ip dns set servers={",".join(ips)}')
                commands.append(f'/ip dns set use-doh-server={ros_q(a["url"])} verify-doh-cert=yes')
            else: commands.append('/ip dns set use-doh-server="" verify-doh-cert=no')
            commands += [f'/ip firewall mangle enable [find where comment={ros_q(MANGLE_COMMENT)}]',"/ip dns cache flush"]
            description="Проверить prerequisites, создать недостающие NAT/Mangle, применить выбранную политику DoH и включить VPN-маршрутизацию."
            checks=["Все проверки prepare_router пройдены","Проверить /ip dns print и DNS-разрешение","Проверить Mangle enabled и NAT masquerade через WireGuard","Проверить VPN-маршрут и доступность LAN-клиентов"]
        elif k=="clear_all":
            commands=['/ip dns static remove [find where comment~"VPN-MANAGER:"]',f'/ip firewall address-list remove [find where list={ros_q(f["address_list"])} and comment~"VPN-MANAGER-CIDR:"]',"/ip dns cache flush"]
            description="Удалить управляемые DNS FWD и CIDR/IP-записи. Локальный список целей, Mangle и NAT останутся."
            checks=["Проверить DNS static и address-list","Убедиться, что сторонние записи сохранены"]
        else:
            description=a["title"]; checks=["Проверить результат операции в журнале и соответствующем разделе"]
        return description,commands,checks

    def cancel_pending_action(self,index):
        if 0 <= index < len(self.pending_actions):
            removed=self.pending_actions.pop(index); self.update_pending_ui()
            self.log(f"Отменено из очереди: {removed['title']}. На роутер ничего не отправлялось.")

    def cancel_all_pending(self):
        """Clear the local pending queue immediately; no router commands are sent."""
        count = len(self.pending_actions)
        self.pending_actions.clear()
        self.update_pending_ui()
        if count:
            self.log(f"Очередь очищена: отменено операций — {count}. На роутер ничего не отправлялось.")
            if hasattr(self, "statusBar"):
                self.statusBar().showMessage(f"Отменено изменений: {count}", 6000)
        else:
            self.log("Очередь изменений уже пуста.")

    def update_pending_ui(self):
        if hasattr(self,"pending_label"):
            self.pending_label.setText("Очередь пуста · на роутере ничего не ожидает применения" if not self.pending_actions else f"Подготовлено операций: {len(self.pending_actions)} · ещё не отправлены на роутер")
        if hasattr(self,"pending_cards_layout"):
            while self.pending_cards_layout.count():
                item=self.pending_cards_layout.takeAt(0); widget=item.widget()
                if widget: widget.deleteLater()
            for index,a in enumerate(self.pending_actions):
                description,commands,checks=self.pending_action_details(a)
                card=QFrame(); card.setObjectName("Panel"); cl=QVBoxLayout(card); cl.setContentsMargins(14,12,14,12); cl.setSpacing(7)
                top=QHBoxLayout(); heading=QLabel(f"{index+1}. {a['title']}"); heading.setObjectName("SectionTitle")
                remove=QPushButton("Отменить это изменение"); remove.setObjectName("DangerButton"); remove.clicked.connect(lambda checked=False,i=index:self.cancel_pending_action(i))
                top.addWidget(heading,1); top.addWidget(remove); cl.addLayout(top)
                info=QLabel(description); info.setObjectName("Muted"); info.setWordWrap(True); cl.addWidget(info)
                cl.addWidget(QLabel("КОМАНДЫ ROUTEROS"))
                view=QPlainTextEdit(); view.setReadOnly(True); view.setMaximumHeight(min(180,max(76,22*min(len(commands),8)))); view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
                view.setPlainText("\n".join(commands) if commands else "# Команды не сформированы"); cl.addWidget(view)
                check=QLabel("Проверить после применения:\n• "+"\n• ".join(checks)); check.setObjectName("Muted"); check.setWordWrap(True); cl.addWidget(check)
                self.pending_cards_layout.addWidget(card)
        if hasattr(self,"header_apply_btn"):
            self.header_apply_btn.setText(f"Применить изменения · {len(self.pending_actions)}"); self.header_apply_btn.setEnabled(bool(self.pending_actions))
        if hasattr(self,"header_cancel_pending_btn"): self.header_cancel_pending_btn.setEnabled(bool(self.pending_actions))
        if hasattr(self,"cancel_all_pending_btn"): self.cancel_all_pending_btn.setEnabled(bool(self.pending_actions))

    def queue_change(self,kind,title,**data):
        self.pending_actions.append({"kind":kind,"title":title,**data}); self.update_pending_ui()
        self.log(f"Подготовлено: {title}. На роутер пока ничего не отправлено.")

    def stage_apply_targets(self):
        if not self.targets:
            QMessageBox.information(self,"Список пуст","Добавь цели для маршрутизации."); return
        self.queue_change("apply_targets",f"Применить цели ({len(self.targets)})",targets=list(self.targets))

    def stage_remove_selected(self):
        selected=self.selected_targets()
        if not selected:
            QMessageBox.information(self,"Не выбрано","Выбери группу, домен или IP-цель в дереве."); return
        self.queue_change("remove_selected",f"Удалить выбранные записи ({len(selected)})",targets=selected)

    def select_doh_preset(self,name):
        preset=DOH_PRESETS.get(name)
        if preset:
            self.doh_url.setText(preset[0])
            self.doh_bootstrap.setText(preset[1])

    def stage_doh_config(self):
        enabled=self.doh_enabled.isChecked()
        url=self.doh_url.text().strip()
        verify=self.doh_verify_cert.isChecked()
        bootstrap=self.doh_bootstrap.text().strip()
        if enabled:
            from urllib.parse import urlparse
            parsed=urlparse(url)
            if parsed.scheme!="https" or not parsed.netloc or parsed.username or parsed.password:
                QMessageBox.warning(self,"Некорректный DoH URL","Укажи полный HTTPS URL, например https://dns.google/dns-query")
                return
            if not verify:
                QMessageBox.warning(self,"Небезопасная настройка","Для DoH оставь включённой проверку TLS-сертификата.")
                return
            try:
                ips=[ipaddress.ip_address(x.strip()) for x in bootstrap.split(",") if x.strip()]
                if not ips or any(ip.version!=4 for ip in ips): raise ValueError()
            except ValueError:
                QMessageBox.warning(self,"Некорректный Bootstrap DNS","Укажи один или несколько корректных IPv4-адресов через запятую.")
                return
            bootstrap=", ".join(str(ip) for ip in ips)
        self.settings.update({"doh_enabled":"1" if enabled else "0","doh_url":url,"doh_bootstrap":bootstrap,"doh_verify_cert":"1" if verify else "0"})
        self.save_settings()
        self.queue_change("doh_config","Настроить DoH: "+(url if enabled else "отключить"),enabled=enabled,url=url,bootstrap=bootstrap,verify=verify)

    def check_doh_config(self):
        def job():
            r=self.router_conn()
            commands=[
                ("DNS configuration","/ip dns print"),
                ("Resolve chatgpt.com",':put [:resolve "chatgpt.com"]'),
                ("Resolve google.com",':put [:resolve "google.com"]'),
                ("DNS cache",'/ip dns cache print terse where name~"chatgpt|google"'),
                ("DNS errors",'/log print without-paging where topics~"dns,error"'),
            ]
            parts=[]
            for title,command in commands:
                try: out=r.exec(command,timeout=18)
                except Exception as exc: out="ERROR: "+str(exc)
                parts.append("$ "+command+"\n"+title+"\n"+out)
            self.q.put(("DIAGOUT",("Проверка DoH на MikroTik","\n\n".join(parts),False,True)))
        self.run_job("Проверка DoH на MikroTik…",job)

    def stage_fix_all(self):
        enabled=self.doh_enabled.isChecked()
        url=self.doh_url.text().strip()
        verify=self.doh_verify_cert.isChecked()
        bootstrap=self.doh_bootstrap.text().strip()
        if enabled:
            from urllib.parse import urlparse
            parsed=urlparse(url)
            if parsed.scheme!="https" or not parsed.netloc or parsed.username or parsed.password or not verify:
                QMessageBox.warning(self,"Проверь DoH","Нужен корректный HTTPS URL и включённая проверка TLS-сертификата.")
                return
            try:
                ips=[ipaddress.ip_address(x.strip()) for x in bootstrap.split(",") if x.strip()]
                if not ips or any(ip.version!=4 for ip in ips): raise ValueError()
            except ValueError:
                QMessageBox.warning(self,"Некорректный Bootstrap DNS","Укажи один или несколько корректных IPv4-адресов через запятую.")
                return
            bootstrap=", ".join(str(ip) for ip in ips)
        self.settings.update({"doh_enabled":"1" if enabled else "0","doh_url":url,"doh_bootstrap":bootstrap,"doh_verify_cert":"1" if verify else "0"})
        self.save_settings()
        self.queue_change("fix_all","Исправить VPN/DNS и применить выбранную политику DoH",enabled=enabled,url=url,bootstrap=bootstrap,verify=verify)

    def stage_clear_all(self):
        if QMessageBox.question(self,"Очистка VPN-целей","Удалить все DNS FWD и CIDR/IP-записи, созданные этим приложением? Локальный список целей сохранится для повторного применения.",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
        self.queue_change("clear_all","Удалить все управляемые DNS FWD и CIDR/IP-записи")

    def apply_pending_changes(self):
        if not self.pending_actions:return
        actions=list(self.pending_actions)
        dlg=QDialog(self); dlg.setObjectName("ApplyChangesDialog"); dlg.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True); dlg.setStyleSheet("QDialog#ApplyChangesDialog { background-color:#080f1d; color:#e8effb; } QWidget#ApplyChangesBody { background-color:#080f1d; color:#e8effb; } QScrollArea { background:transparent; border:0; } QScrollArea QWidget { background-color:#080f1d; color:#e8effb; }"); dlg.resize(980,760)
        lay=QVBoxLayout(dlg); lay.setContentsMargins(14,12,14,14); lay.setSpacing(12)
        add_dialog_chrome(dlg,lay,"Проверка и применение изменений")
        title=QLabel(f"Проверь операции · {len(actions)}"); title.setObjectName("SectionTitle")
        note=QLabel("Каждое изменение показано отдельным блоком: пояснение, команды RouterOS и что проверить после применения. До подтверждения команды не отправляются.")
        note.setObjectName("Muted"); note.setWordWrap(True); lay.addWidget(title); lay.addWidget(note)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame)
        body=QWidget(); body.setObjectName("ApplyChangesBody"); body.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True); body.setAutoFillBackground(True); body_layout=QVBoxLayout(body); body_layout.setContentsMargins(2,2,8,2); body_layout.setSpacing(12)
        selection_checks=[]
        for index,a in enumerate(actions):
            description,commands,checks=self.pending_action_details(a)
            card=QFrame(); card.setObjectName("Panel"); cl=QVBoxLayout(card); cl.setContentsMargins(14,12,14,12); cl.setSpacing(8)
            top=QHBoxLayout()
            choose=QCheckBox("Выбрать")
            choose.setToolTip("Отметить это изменение для массовой отмены.")
            selection_checks.append((a,choose))
            heading=QLabel(f"{index+1}. {a['title']}"); heading.setObjectName("SectionTitle")
            remove=QPushButton("Отменить этот блок"); remove.setObjectName("DangerButton")
            remove.clicked.connect(lambda checked=False,action=a:(self.cancel_pending_action(self.pending_actions.index(action)) if action in self.pending_actions else None,dlg.reject()))
            top.addWidget(choose); top.addWidget(heading,1); top.addWidget(remove); cl.addLayout(top)
            info=QLabel(description); info.setObjectName("Muted"); info.setWordWrap(True); cl.addWidget(info)
            label=QLabel("КОМАНДЫ ROUTEROS"); label.setObjectName("CardTitle"); cl.addWidget(label)
            view=QPlainTextEdit(); view.setReadOnly(True); view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap); view.setPlainText("\n".join(commands) if commands else "# Команды не сформированы")
            view.setMinimumHeight(90); view.setMaximumHeight(min(230,max(100,22*min(len(commands),9)))); view._highlighter=RouterOSHighlighter(view.document()); cl.addWidget(view)
            check=QLabel("Что проверить после применения:\n• "+"\n• ".join(checks)); check.setObjectName("Muted"); check.setWordWrap(True); cl.addWidget(check)
            body_layout.addWidget(card)
        body_layout.addStretch(); scroll.setWidget(body); lay.addWidget(scroll,1)
        footer=QHBoxLayout()
        cancel_selected=QPushButton("Отменить выбранные изменения"); cancel_selected.setObjectName("DangerButton")
        def cancel_selected_actions():
            chosen=[action for action,check in selection_checks if check.isChecked()]
            if not chosen:
                QMessageBox.information(dlg,"Ничего не выбрано","Отметь флажками одно или несколько изменений.")
                return
            chosen_ids={id(action) for action in chosen}
            before=len(self.pending_actions)
            self.pending_actions=[action for action in self.pending_actions if id(action) not in chosen_ids]
            removed=before-len(self.pending_actions)
            self.update_pending_ui()
            self.log(f"Отменено выбранных изменений: {removed}. На роутер ничего не отправлялось.")
            dlg.reject()
        cancel_selected.clicked.connect(cancel_selected_actions)
        cancel_all=QPushButton("Отменить все изменения"); cancel_all.setObjectName("DangerButton")
        def cancel_all_from_preview():
            self.cancel_all_pending()
            dlg.reject()
        cancel_all.clicked.connect(cancel_all_from_preview)
        close=QPushButton("Закрыть"); apply=QPushButton("Применить оставшиеся · "+str(len(actions))); apply.setObjectName("PrimaryButton")
        close.clicked.connect(dlg.reject); apply.clicked.connect(dlg.accept)
        footer.addWidget(cancel_selected); footer.addWidget(cancel_all); footer.addStretch(); footer.addWidget(close); footer.addWidget(apply); lay.addLayout(footer)
        fit_controls(dlg,40)
        if dlg.exec()!=QDialog.DialogCode.Accepted:return
        if len(self.pending_actions)!=len(actions) or any(x is not y for x,y in zip(self.pending_actions,actions)):
            QMessageBox.information(self,"Очередь обновлена","Состав очереди изменился. Открой предпросмотр ещё раз.")
            return
        def job():
            r=self.router_conn()
            for a in actions:
                k=a["kind"]
                if k=="setup_vpn_routing":
                    f=dict(self.settings); table=f["route_table"]; wg=f["wg_interface"]
                    if r.exec(f'/interface wireguard print count-only where name={ros_q(wg)}').strip()!="1" or r.exec(f'/interface print count-only where name={ros_q(f["lan_interface"])}').strip()!="1":
                        raise RuntimeError("Интерфейс WireGuard или LAN изменился после сканирования. Повтори скан.")
                    if "allow-remote-requests: yes" not in r.exec("/ip dns print") or f'dns-server={f["lan_dns"]}' not in r.exec("/ip dhcp-server network print detail").replace(" ",""):
                        raise RuntimeError("DNS/DHCP prerequisites не выполнены. Ничего не применено.")
                    filters=r.exec("/ip firewall filter print detail"); all_mangle=r.exec("/ip firewall mangle print detail")
                    if "action=fasttrack-connection" in filters.lower(): raise RuntimeError("Обнаружен FastTrack. Автонастройка остановлена.")
                    if "action=mark-routing" in all_mangle and MANGLE_COMMENT not in all_mangle: raise RuntimeError("Обнаружено стороннее mark-routing правило.")
                    tc=r.exec(f'/routing table print count-only where name={ros_q(table)}').strip()
                    if tc=="0": self.cmd(r,f'/routing table add name={ros_q(table)} fib')
                    elif tc!="1": raise RuntimeError(f"Найдено таблиц {tc}; ожидается одна.")
                    routes=r.exec(f'/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(table)}')
                    if not routes.strip(): self.cmd(r,f'/ip route add dst-address=0.0.0.0/0 gateway={ros_q(wg)} routing-table={ros_q(table)} comment="VPN-MANAGER-DEFAULT"')
                    elif f'gateway={wg}' not in routes or "inactive" in routes.lower(): raise RuntimeError("В таблице уже есть конфликтующий или неактивный default route. Он не изменён.")
                    self.prepare_router(r)
                    verified=r.exec(f'/ip route print detail where dst-address=0.0.0.0/0 and routing-table={ros_q(table)}')
                    if f'gateway={wg}' not in verified or "inactive" in verified.lower(): raise RuntimeError("Default route не подтвердился как активный.")
                elif k=="apply_targets":
                    self.prepare_router(r)
                    for t,kind in a["targets"]: self.apply_target(r,t,kind)
                    self.cmd(r,"/ip dns cache flush")
                elif k=="remove_selected":
                    for t,kind in a["targets"]:
                        comment=f"VPN-MANAGER:{t}" if kind=="Домен" else f"VPN-MANAGER-CIDR:{t}"
                        path="/ip dns static" if kind=="Домен" else "/ip firewall address-list"
                        self.cmd(r,f'{path} remove [find where comment={ros_q(comment)}]')
                    self.cmd(r,"/ip dns cache flush")
                elif k in ("mangle_enable","mangle_disable"):
                    count=r.exec(f'/ip firewall mangle print count-only where comment={ros_q(MANGLE_COMMENT)}').strip()
                    if count!="1": raise RuntimeError(f"Ожидалось ровно одно управляемое Mangle-правило, найдено: {count or '0'}.")
                    verb="enable" if k=="mangle_enable" else "disable"
                    self.cmd(r,f'/ip firewall mangle {verb} [find where comment={ros_q(MANGLE_COMMENT)}]')
                    self.fetch_mangle_status(r)
                elif k=="doh_config":
                    if a["enabled"]:
                        from urllib.parse import urlparse
                        parsed=urlparse(a["url"])
                        if parsed.scheme!="https" or not parsed.netloc or parsed.username or parsed.password or not a["verify"]: raise ValueError("DoH требует корректный HTTPS URL и включённую проверку сертификата.")
                        bootstrap=a.get("bootstrap","").strip()
                        if bootstrap:
                            ips=[ipaddress.ip_address(x.strip()) for x in bootstrap.split(",") if x.strip()]
                            if not ips or any(ip.version!=4 for ip in ips): raise ValueError("Bootstrap DNS должен содержать корректные IPv4-адреса.")
                            self.cmd(r,f"/ip dns set servers={','.join(str(ip) for ip in ips)}")
                        self.cmd(r,f"/ip dns set use-doh-server={ros_q(a['url'])} verify-doh-cert=yes")
                    else:self.cmd(r,'/ip dns set use-doh-server="" verify-doh-cert=no')
                    self.cmd(r,"/ip dns cache flush")
                elif k=="fix_all":
                    self.prepare_router(r)
                    if a.get("enabled"):
                        from urllib.parse import urlparse
                        parsed=urlparse(a.get("url",""))
                        if parsed.scheme!="https" or not parsed.netloc or parsed.username or parsed.password or not a.get("verify",True): raise ValueError("DoH требует корректный HTTPS URL и включённую проверку сертификата.")
                        bootstrap=a.get("bootstrap","").strip()
                        if bootstrap:
                            ips=[ipaddress.ip_address(x.strip()) for x in bootstrap.split(",") if x.strip()]
                            if not ips or any(ip.version!=4 for ip in ips): raise ValueError("Bootstrap DNS должен содержать корректные IPv4-адреса.")
                            self.cmd(r,f"/ip dns set servers={','.join(str(ip) for ip in ips)}")
                        self.cmd(r,f"/ip dns set use-doh-server={ros_q(a['url'])} verify-doh-cert=yes")
                    else:self.cmd(r,'/ip dns set use-doh-server="" verify-doh-cert=no')
                    count=r.exec(f'/ip firewall mangle print count-only where comment={ros_q(MANGLE_COMMENT)}').strip()
                    if count!="1": raise RuntimeError(f"Ожидалось ровно одно управляемое Mangle-правило, найдено: {count or '0'}.")
                    self.cmd(r,f'/ip firewall mangle enable [find where comment={ros_q(MANGLE_COMMENT)}]')
                    self.cmd(r,"/ip dns cache flush")
                elif k=="clear_all":
                    self.cmd(r,'/ip dns static remove [find where comment~"VPN-MANAGER:"]')
                    self.cmd(r,f'/ip firewall address-list remove [find where list={ros_q(self.settings["address_list"])} and comment~"VPN-MANAGER-CIDR:"]')
                    self.cmd(r,"/ip dns cache flush")
            self.pending_actions=[]; self.q.put(("PENDING_CLEARED",None))
            self.fetch_targets(r); self.fetch_mangle_status(r); self.q.put(("LOG","Подготовленные изменения применены."))
        self.run_job("Применение очереди изменений…",job)

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
        commands={"filter":"/ip firewall filter print terse","nat":"/ip firewall nat print terse","mangle":"/ip firewall mangle print terse"}
        def job():
            r=self.router_conn()
            for key,command in commands.items():
                self.q.put(("FW_DATA",(key,r.exec(command,timeout=25))))
        self.run_job("Загрузка Filter / NAT / Mangle…",job)

    def on_firewall_data(self,key,output):
        records=[]
        for line in output.splitlines():
            line=line.strip()
            match=re.match(r"^(\d+)\s+(.*)$",line)
            if not match: continue
            number=int(match.group(1))
            parsed=parse_terse(str(number)+" "+match.group(2))
            if not parsed: continue
            records.append({"number":number,"flags":parsed[0]["flags"],"fields":parsed[0]["f"]})
        self.fw_data[key]=records
        self.render_firewall_table(key)

    def render_firewall_table(self,key):
        table=self.fw_tables[key]; table.setRowCount(0)
        for record in self.fw_data.get(key,[]):
            fields=record["fields"]; row=table.rowCount(); table.insertRow(row)
            enabled="Нет" if "X" in record["flags"] or fields.get("disabled")=="yes" else "Да"
            interface=fields.get("in-interface") or fields.get("out-interface") or fields.get("in-interface-list") or fields.get("out-interface-list","—")
            values=[str(record["number"]),enabled,fields.get("chain","—"),fields.get("action","—"),fields.get("protocol","—"),fields.get("src-address","—"),fields.get("dst-address","—"),interface,fields.get("comment","")]
            for column,value in enumerate(values):
                item=QTableWidgetItem(value); item.setData(Qt.ItemDataRole.UserRole,record)
                if column==1 and enabled=="Нет": item.setForeground(QColor("#fbbf24"))
                table.setItem(row,column,item)
        self.filter_firewall_table()

    def filter_firewall_table(self,*_):
        if not hasattr(self,"fw_tabs"): return
        key=("filter","nat","mangle")[self.fw_tabs.currentIndex()]
        table=self.fw_tables[key]; needle=self.fw_search.text().casefold()
        for row in range(table.rowCount()):
            hidden=bool(needle) and not any(needle in (table.item(row,col).text().casefold() if table.item(row,col) else "") for col in range(table.columnCount()))
            table.setRowHidden(row,hidden)

    def firewall_selected(self):
        key=("filter","nat","mangle")[self.fw_tabs.currentIndex()]
        table=self.fw_tables[key]; row=table.currentRow()
        if row<0: return key,None
        item=table.item(row,0)
        return key,item.data(Qt.ItemDataRole.UserRole) if item else None

    def firewall_rule_warnings(self,key,values):
        warnings=[]
        chain=values.get("chain","").lower(); action=values.get("action","").lower()
        constrained=any(values.get(name) for name in ("src-address","src-address-list","in-interface","in-interface-list"))
        if key=="filter" and chain=="input" and action=="accept" and not constrained:
            warnings.append("Filter/input accept без ограничения источника или входного интерфейса может открыть доступ к самому роутеру.")
        if key=="filter" and chain=="input" and action in ("drop","reject") and not constrained:
            warnings.append("Широкое правило drop/reject в input может заблокировать управление роутером.")
        if key=="filter" and chain=="forward" and action=="accept" and not (values.get("src-address") or values.get("dst-address") or values.get("in-interface") or values.get("out-interface")):
            warnings.append("Forward accept без адресных или интерфейсных ограничений может разрешить слишком широкий транзитный трафик.")
        if key=="nat" and action in ("masquerade","src-nat") and chain!="srcnat":
            warnings.append("Masquerade/src-nat обычно применяется в chain=srcnat; проверь выбранную цепочку.")
        if key=="nat" and action in ("masquerade","src-nat") and not (values.get("out-interface") or values.get("out-interface-list")):
            warnings.append("NAT без out-interface/out-interface-list может затронуть больше трафика, чем планировалось.")
        if key=="mangle" and action=="mark-routing" and not values.get("new-routing-mark"):
            warnings.append("Для mark-routing не задан new-routing-mark — правило не задаст целевую таблицу.")
        if key=="mangle" and action.startswith("mark-") and values.get("passthrough","").lower() not in ("no","false") and chain=="prerouting":
            warnings.append("Проверь passthrough и порядок Mangle: последующие правила могут повторно изменить метки.")
        if values.get("disabled")=="no" and action in ("accept","masquerade","mark-routing") and not values.get("comment"):
            warnings.append("У активного правила нет комментария; его будет сложнее идентифицировать и сопровождать.")
        return warnings

    def firewall_rule_dialog(self,key,record=None):
        title={"filter":"Filter","nat":"NAT","mangle":"Mangle"}[key]
        fields=["chain","action","protocol","src-address","src-address-list","dst-address","dst-address-list","src-port","dst-port","in-interface","in-interface-list","out-interface","out-interface-list","connection-state","connection-nat-state","connection-mark","new-connection-mark","new-packet-mark","new-routing-mark","passthrough","to-addresses","to-ports","jump-target","limit","log","log-prefix","tls-host","comment"]
        dialog=QDialog(self); dialog.setWindowTitle(("Редактировать " if record else "Новое правило ")+title); dialog.setMinimumWidth(520)
        form=QFormLayout(dialog); widgets={}; current=record["fields"] if record else {}
        for name in fields:
            edit=QLineEdit(current.get(name,"")); edit.setPlaceholderText("не задано"); widgets[name]=edit; form.addRow(name,edit)
        enabled=QCheckBox("Правило включено")
        enabled.setChecked(not record or ("X" not in record["flags"] and current.get("disabled")!="yes"))
        form.addRow("",enabled)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject); form.addRow(buttons)
        if dialog.exec()!=QDialog.DialogCode.Accepted: return
        values={name:edit.text().strip() for name,edit in widgets.items() if edit.text().strip()}
        if not values.get("chain") or not values.get("action"):
            QtMessageBox.warning(self,"Недостаточно данных","Поля chain и action обязательны."); return
        values["disabled"]="no" if enabled.isChecked() else "yes"
        warnings=self.firewall_rule_warnings(key,values)
        path=f"/ip firewall {key}"
        args=" ".join(f"{name}={ros_q(value)}" for name,value in values.items())
        if record:
            command=f"{path} set {record['number']} {args}"
            description=f"Изменить правило {title} №{record['number']} ({values['chain']} / {values['action']})."
        else:
            command=f"{path} add {args}"
            description=f"Добавить правило {title} ({values['chain']} / {values['action']})."
        risk="Изменение Firewall; проверь порядок, chain и влияние на доступ."
        if warnings:
            risk+="\n⚠ "+"\n⚠ ".join(warnings)
        self.fw_queue.append({"command":command,"description":description,"risk":risk})
        self.update_firewall_queue()
        if warnings:
            QtMessageBox.warning(self,"Потенциально опасные настройки","Правило добавлено в локальную очередь, но перед применением проверь:\n\n"+"\n".join("• "+item for item in warnings))

    def firewall_add_rule(self):
        self.firewall_rule_dialog(("filter","nat","mangle")[self.fw_tabs.currentIndex()])

    def firewall_edit_rule(self):
        key,record=self.firewall_selected()
        if not record: QtMessageBox.information(self,"Правило не выбрано","Выбери строку правила."); return
        self.firewall_rule_dialog(key,record)

    def firewall_delete_rule(self):
        key,record=self.firewall_selected()
        if not record: QtMessageBox.information(self,"Правило не выбрано","Выбери строку правила."); return
        title={"filter":"Filter","nat":"NAT","mangle":"Mangle"}[key]
        self.fw_queue.append({"command":f"/ip firewall {key} remove {record['number']}","description":f"Удалить правило {title} №{record['number']}.","risk":"Удаление правила может открыть или заблокировать сетевой доступ."})
        self.update_firewall_queue()

    def update_firewall_queue(self):
        if not hasattr(self,"fw_queue_view"): return
        lines=[]
        for i,item in enumerate(self.fw_queue,1):
            lines.extend([f"{i}. {item['description']}",f"   Риск: {item['risk']}",f"   $ {item['command']}",""])
        self.fw_queue_view.setPlainText("\n".join(lines) if lines else "")

    def firewall_clear_queue(self):
        self.fw_queue=[]; self.update_firewall_queue()

    def firewall_preview_queue(self):
        if not self.fw_queue:
            QtMessageBox.information(self,"Очередь пуста","Нет изменений для предпросмотра."); return
        dialog=QDialog(self); dialog.setWindowTitle("Предпросмотр изменений Firewall"); dialog.resize(850,520)
        layout=QVBoxLayout(dialog); label=QLabel("Проверь каждую команду и её влияние перед подтверждением."); label.setWordWrap(True); layout.addWidget(label)
        preview=QPlainTextEdit(); preview.setReadOnly(True)
        preview.setPlainText("\n\n".join(f"{i}. {item['description']}\nРиск: {item['risk']}\n$ {item['command']}" for i,item in enumerate(self.fw_queue,1)))
        preview.setStyleSheet("QPlainTextEdit {background:#07111f;color:#dce7f8;border:1px solid #304764;border-radius:10px;padding:12px;font-family:Consolas,monospace;}")
        layout.addWidget(preview,1)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(dialog.reject); layout.addWidget(buttons); dialog.exec()

    def firewall_apply_queue(self):
        if not self.fw_queue:
            QtMessageBox.information(self,"Очередь пуста","Нет изменений для применения."); return
        self.firewall_preview_queue()
        answer=QtMessageBox.question(self,"Применить изменения Firewall",f"Отправить на MikroTik {len(self.fw_queue)} команд(ы)? Это изменит активные правила.",QtMessageBox.StandardButton.Yes|QtMessageBox.StandardButton.No,QtMessageBox.StandardButton.No)
        if answer!=QtMessageBox.StandardButton.Yes: return
        # Индексы RouterOS меняются после удаления: сначала add/set, затем remove по убыванию номера.
        def queue_order(item):
            match=re.search(r"\bremove\s+(\d+)",item["command"])
            return (1,-int(match.group(1))) if match else (0,0)
        pending=sorted(list(self.fw_queue),key=queue_order)
        def job():
            router=self.router_conn()
            for item in pending:
                output=router.exec(item["command"],timeout=30)
                if re.search(r"failure:|expected end of command|syntax error",output,re.I):
                    raise RuntimeError(item["command"]+"\n"+output)
            self.q.put(("FW_APPLIED",None))
        self.run_job("Применение очереди Firewall…",job)

    def firewall_applied(self):
        self.fw_queue=[]; self.update_firewall_queue(); QTimer.singleShot(350,self.refresh_firewall)

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
QListWidget#Nav{background:transparent;border:0;outline:0;color:#8aa0c0;padding-top:2px;padding-right:0px;}
QListWidget#Nav::item{padding:12px 8px;border-radius:11px;margin:3px 0;font-size:9.5pt;font-weight:600;border:1px solid transparent;}
QListWidget#Nav::item:hover:!selected{background:rgba(255,255,255,14);color:#e4edfb;border:1px solid rgba(255,255,255,18)}
QListWidget#Nav::item:selected{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(70,120,235,150),stop:1 rgba(50,90,190,70));color:#ffffff;border:1px solid rgba(130,175,255,140)}

/* ---------- typography ---------- */
QLabel#PageTitle{font-size:21pt;font-weight:700;color:#ffffff}
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
QTreeWidget{background:#080f1d;border:1px solid #263750;border-radius:15px;color:#dce7f7;alternate-background-color:rgba(255,255,255,3);selection-background-color:rgba(55,112,210,115);selection-color:#ffffff;outline:0;padding:8px}
QTreeWidget::item{padding:9px 7px;border-bottom:1px solid rgba(105,135,180,22);min-height:25px}
QTreeWidget::item:hover{background:rgba(93,145,225,22)}
QTreeWidget::item:selected{background:rgba(49,105,205,105);color:#ffffff;border-radius:5px}
/* Check indicators for selectable rows in the routing tree (QTreeWidgetItem check-state, not QCheckBox). */
QTreeWidget::indicator{width:17px;height:17px;border:1px solid #536985;border-radius:4px;background:#101b2d;margin-right:5px}
QTreeWidget::indicator:unchecked{background:#101b2d;border:1px solid #536985}
QTreeWidget::indicator:unchecked:hover{background:#172943;border:1px solid #83b2ff}
QTreeWidget::indicator:checked{background:#3978e8;border:1px solid #78aaff}
QTreeWidget::indicator:indeterminate{background:#2457a8;border:1px solid #78aaff}
QTreeWidget::indicator:disabled{background:#182335;border:1px solid #35445b}
QTreeWidget::branch{background:transparent}
QLabel#TerminalTag{color:#8ce9c5;background:rgba(16,185,129,22);border:1px solid rgba(52,211,153,75);border-radius:9px;padding:8px 11px;font-size:8pt;font-weight:800;letter-spacing:1px}
QLabel#TerminalCaption{color:#91a9cc;font-size:8pt;font-weight:800;letter-spacing:1.2px}
QLabel#TerminalHint{color:#7188aa;font-size:8pt}
QLabel#TerminalRiskBadge{border-radius:8px;padding:5px 9px;font-size:8pt;font-weight:800}
QFrame#RouterHealthCell{background:rgba(5,11,22,150);border:1px solid rgba(150,185,235,35);border-radius:12px}
QLabel#RouterHealthValue{color:#edf4ff;font-size:10pt;font-weight:700}
QLabel#TerminalPrompt{color:#58e0a2;font-family:'Cascadia Mono','Consolas',monospace;font-size:19pt;font-weight:800;padding:0 5px}
QLineEdit#TerminalCommandInput{background:#071222;border:1px solid #36547a;border-radius:13px;padding:0 15px;min-height:48px;color:#f0f6ff;font-family:'Cascadia Mono','Consolas',monospace;font-size:10pt;selection-background-color:#244b82}
QLineEdit#TerminalCommandInput:hover{border-color:#648fc8}
QLineEdit#TerminalCommandInput:focus{background:#09182b;border:1px solid #72a8ff}
QTreeWidget::branch:has-siblings:!adjoins-item{border-image:none;border-left:1px solid #30425e}
QTreeWidget::branch:has-siblings:adjoins-item{border-image:none;border-left:1px solid #30425e}
QTreeWidget::branch:!has-children:!has-siblings:adjoins-item{border-image:none;border-left:1px solid #30425e}
QTreeWidget::branch:closed:has-children{image:url(TREE_COLLAPSED_URL);width:20px;height:20px}
QTreeWidget::branch:open:has-children{image:url(TREE_EXPANDED_URL);width:20px;height:20px}
QTreeWidget#RoutingTree QHeaderView::section{background:#111d30;color:#a9bddb;border:0;border-bottom:1px solid #30435f;padding:13px 10px;font-size:8pt;font-weight:800}
QLabel#TreeCaption{color:#91a9cc;font-size:8pt;font-weight:800;letter-spacing:1px}
QLineEdit#TargetSearch{min-width:240px;background:#0a1424;border:1px solid #30435f;border-radius:12px;padding:0 14px;color:#edf4ff}
QLineEdit#TargetSearch:focus{border:1px solid #6a9fff;background:#0c192d}
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
/* ---------- enhanced liquid-glass finish ---------- */
QFrame#Panel{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(58,82,125,105),stop:.42 rgba(19,31,54,174),stop:1 rgba(8,14,26,205));border:1px solid rgba(180,210,255,48);border-top:1px solid rgba(220,235,255,72);border-radius:20px}
QFrame#Card{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(56,76,112,132),stop:1 rgba(10,17,31,196));border:1px solid rgba(190,215,255,45);border-top:2px solid rgba(115,165,255,190);border-radius:17px}
QFrame#Hero{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(69,112,210,145),stop:.5 rgba(23,42,83,180),stop:1 rgba(35,59,112,140));border:1px solid rgba(190,215,255,95);border-top:1px solid rgba(235,245,255,125);border-radius:22px}
QLineEdit,QComboBox,QSpinBox{background:rgba(7,13,25,150);border:1px solid rgba(190,215,255,42);border-radius:12px}
QPlainTextEdit,QTextEdit,QTableWidget{background:rgba(5,10,20,178);border:1px solid rgba(190,215,255,35);border-radius:15px}
QPushButton{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 rgba(255,255,255,22),stop:1 rgba(255,255,255,7));border:1px solid rgba(190,215,255,48);padding-left:14px;padding-right:14px}
QPushButton:hover{background:rgba(110,155,235,35);border-color:rgba(175,210,255,145)}
QLabel#StatusBar{background:rgba(100,135,190,18);border:1px solid rgba(190,215,255,48)}
QLabel#EmptyState{color:#91a6c6;background:rgba(255,255,255,5);border:1px dashed rgba(160,190,235,55);border-radius:12px;padding:18px;font-size:10pt}
QProgressBar#BusyProgress{background:rgba(255,255,255,10);border:1px solid rgba(190,215,255,35);border-radius:4px;min-height:7px;max-height:7px}
QProgressBar#BusyProgress::chunk{background:#5b9aff;border-radius:4px}
QLineEdit:disabled,QComboBox:disabled{color:#667b9a}
QPushButton:focus,QLineEdit:focus,QComboBox:focus{outline:0;border:1px solid #83b2ff}
QTableWidget::item:selected{background:rgba(61,115,205,90)}
QListWidget#Nav::item{padding:12px 12px}

"""



if __name__=="__main__":
    app=QApplication(sys.argv); app.setApplicationName(APP_NAME)
    _ui_icons = make_ui_icons()
    _arrow = make_arrow_icon()
    STYLE = STYLE.replace("image:url(ARROW_URL);", f'image:url("{_arrow}");' if _arrow else "image:none;")
    STYLE = STYLE.replace("TREE_COLLAPSED_URL", _ui_icons.get("tree_collapsed", ""))
    STYLE = STYLE.replace("TREE_EXPANDED_URL", _ui_icons.get("tree_expanded", ""))
    app.setStyleSheet(STYLE + """
        QDialog { background:#080f1d; color:#e8effb; } QDialog#ApplyChangesDialog QWidget { color:#e8effb; } QDialog#ApplyChangesDialog QScrollArea { background:#080f1d; } QDialog#ApplyChangesDialog QScrollArea QWidget#ApplyChangesBody { background:#080f1d; }
        QMessageBox { background:#0a1423; color:#e8effb; }
        QMessageBox QLabel { color:#e8effb; min-width:280px; }
        QMessageBox QPushButton { min-width:92px; min-height:34px; }
        QCheckBox { color:#dce7f8; spacing:9px; }
        QCheckBox::indicator { width:17px; height:17px; border:1px solid #536985; border-radius:4px; background:#101b2d; }
        QCheckBox::indicator:hover { border:1px solid #83b2ff; background:#172943; }
        QCheckBox::indicator:checked { background:#3978e8; border:1px solid #78aaff; }
        QCheckBox::indicator:disabled { background:#182335; border:1px solid #35445b; }
    """)
    win=App(); win._ui_icons = _ui_icons; win.show()
    if paramiko is None: QMessageBox.critical(win,"Нет Paramiko","Запусти start.bat — он создаст venv и установит зависимости.")
    sys.exit(app.exec())
