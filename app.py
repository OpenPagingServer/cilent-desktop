import base64
import ctypes
import io
import json
import mimetypes
import os
import platform
import queue
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import wave
from collections import deque
from ctypes import wintypes
from datetime import datetime, timedelta
from pathlib import Path

import embedded_assets

_missing = []
try:
    import webview
except ImportError:
    _missing.append("pywebview")
try:
    import pystray
    from PIL import Image
except ImportError:
    _missing.append("pystray Pillow")
if _missing:
    print("Missing required packages. Install them with:")
    print("    pip install " + " ".join(_missing))
    sys.exit(1)
try:
    import audioop
except ImportError:
    audioop = None
try:
    import miniaudio
except ImportError:
    miniaudio = None
try:
    import winsound
except ImportError:
    winsound = None
try:
    import winreg
except ImportError:
    winreg = None
try:
    from windows_toasts import Toast, ToastButton, ToastDisplayImage, ToastDuration, ToastImagePosition, ToastScenario, WindowsToaster
except ImportError:
    WindowsToaster = None

import tkinter as tk
from tkinter import font as tkfont

APP_FALLBACK_NAME = "Open Paging Server"
DESKTOP_CLIENT_HEADER = "x-ops-desktop-client"
CLIENT_OS_HEADER = "X-OPS-Client-OS"
CONFIG_DIR = Path(os.getenv("APPDATA") or Path.home()) / "OpenPagingServerClient"
CONFIG_FILE = CONFIG_DIR / "config.json"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "OpenPagingServerClient"

COLOR_CONNECTED = "#2E7D32"
COLOR_DISCONNECTED = "#C62828"
COLOR_RECEIVING = "#FFB300"
COLOR_IDLE = "#9E9E9E"

MB_YESNO = 0x4
MB_ICONWARNING = 0x30
MB_ICONQUESTION = 0x20
MB_SYSTEMMODAL = 0x1000
MB_SETFOREGROUND = 0x10000
IDYES = 6

WM_MOVING = 0x0216
WM_SYSCOMMAND = 0x0112
_SC_MOVE = 0xF010
_GWLP_WNDPROC = -4
_popup_proc_refs: list = []  # keep WndProc callbacks alive (prevent GC)

INSECURE_HOSTS = set()


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi_protect_bytes(data):
    raw = bytes(data or b"")
    if not raw:
        return b""
    if os.name != "nt":
        return raw
    in_buffer = ctypes.create_string_buffer(raw)
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "OpenPagingServerClient",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        return b""
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect_bytes(data):
    raw = bytes(data or b"")
    if not raw:
        return b""
    if os.name != "nt":
        return raw
    in_buffer = ctypes.create_string_buffer(raw)
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        return b""
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def read_secure_config_value(config, key):
    encrypted = str(config.get(f"{key}_enc") or "").strip()
    if encrypted.startswith("dpapi:"):
        try:
            payload = base64.b64decode(encrypted[6:].encode("ascii"))
            decoded = _dpapi_unprotect_bytes(payload).decode("utf-8")
            if decoded:
                return decoded
        except Exception:
            pass
    return str(config.get(key) or "")


def write_secure_config_value(config, key, value):
    token = str(value or "")
    plain_key = str(key)
    secure_key = f"{plain_key}_enc"
    if not token:
        config.pop(plain_key, None)
        config.pop(secure_key, None)
        return
    try:
        protected = _dpapi_protect_bytes(token.encode("utf-8"))
        if protected:
            config[secure_key] = "dpapi:" + base64.b64encode(protected).decode("ascii")
            config.pop(plain_key, None)
            return
    except Exception:
        pass
    config[plain_key] = token
    config.pop(secure_key, None)


def client_os_string():
    release = platform.release() or ""
    return ("Windows " + release).strip()


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(data):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def system_uses_dark_mode():
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        value, _kind = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return int(value) == 0
    except Exception:
        return False


def apply_dark_titlebar(hwnd, dark):
    try:
        value = ctypes.c_int(1 if dark else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


_ICO_PATH = None
_TOAST_PNG_PATH = None


def app_ico_path():
    global _ICO_PATH
    if _ICO_PATH is None:
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".ico")
        handle.write(base64.b64decode(embedded_assets.APP_ICO))
        handle.close()
        _ICO_PATH = handle.name
    return _ICO_PATH


def app_toast_png_path():
    global _TOAST_PNG_PATH
    if _TOAST_PNG_PATH is None:
        try:
            image = Image.open(io.BytesIO(base64.b64decode(embedded_assets.APP_ICO)))
            image = image.convert("RGBA")
            handle = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            handle.close()
            image.save(handle.name, "PNG")
            _TOAST_PNG_PATH = handle.name
        except Exception:
            _TOAST_PNG_PATH = ""
    return _TOAST_PNG_PATH or None


def toast_safe_icon(path):
    if not path:
        return None
    suffix = os.path.splitext(path)[1].lower()
    if suffix in (".png", ".jpg", ".jpeg", ".gif"):
        return path
    try:
        image = Image.open(path).convert("RGBA")
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        handle.close()
        image.save(handle.name, "PNG")
        return handle.name
    except Exception:
        return None


def logo_png_bytes(dark):
    data = embedded_assets.LOGO_DARK_PNG if dark else embedded_assets.LOGO_LIGHT_PNG
    return base64.b64decode(data)


def favicon_mask_image():
    return Image.open(io.BytesIO(base64.b64decode(embedded_assets.FAVICON_MASK_PNG))).convert("RGBA")


def tinted_favicon(color):
    mask = favicon_mask_image()
    token = str(color or COLOR_IDLE).lstrip("#")
    rgb = tuple(int(token[i:i + 2], 16) for i in (0, 2, 4))
    tinted = Image.new("RGBA", mask.size, rgb + (0,))
    tinted.putalpha(mask.getchannel("A"))
    return tinted


def native_message_box(title, text, flags, owner=0):
    modal = 0 if owner else MB_SYSTEMMODAL
    return ctypes.windll.user32.MessageBoxW(owner, str(text), str(title), flags | modal | MB_SETFOREGROUND)


def _hook_no_move(hwnd):
    """Subclass the WndProc of hwnd so the window cannot be moved at all."""
    if not hwnd or os.name != "nt":
        return
    try:
        user32 = ctypes.windll.user32
        user32.GetWindowLongPtrW.restype = ctypes.c_void_p
        user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.SetWindowLongPtrW.restype = ctypes.c_void_p
        user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]

        _WndProc = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t,
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        )
        old_ptr = user32.GetWindowLongPtrW(hwnd, _GWLP_WNDPROC)
        if not old_ptr:
            return
        old_wndproc = _WndProc(old_ptr)

        @_WndProc
        def _no_move_proc(h, msg, wp, lp):
            if msg == WM_SYSCOMMAND and (wp & 0xFFF0) == _SC_MOVE:
                return 0
            if msg == WM_MOVING:
                # Pin window: write current rect back into the RECT pointed to by lp
                try:
                    cur = wintypes.RECT()
                    user32.GetWindowRect(h, ctypes.byref(cur))
                    ctypes.memmove(lp, ctypes.addressof(cur), ctypes.sizeof(cur))
                except Exception:
                    pass
                return 1
            return old_wndproc(h, msg, wp, lp)

        user32.SetWindowLongPtrW(hwnd, _GWLP_WNDPROC, ctypes.cast(_no_move_proc, ctypes.c_void_p))
        _popup_proc_refs.append((_no_move_proc, old_wndproc))
    except Exception:
        pass


def uac_approved():
    try:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", os.path.join(system_root, "System32", "cmd.exe"), "/c exit", None, 0
        )
        return int(result) > 32
    except Exception:
        return False


def foreground_is_fullscreen():
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return False
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        screen_w = user32.GetSystemMetrics(0)
        screen_h = user32.GetSystemMetrics(1)
        if rect.left <= 0 and rect.top <= 0 and rect.right >= screen_w and rect.bottom >= screen_h:
            buffer = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buffer, 256)
            return buffer.value not in ("Progman", "WorkerW")
        return False
    except Exception:
        return False


def all_monitor_bounds():
    monitors = []
    try:
        enum_proc = ctypes.WINFUNCTYPE(
            ctypes.c_int,
            wintypes.HMONITOR,
            wintypes.HDC,
            ctypes.POINTER(wintypes.RECT),
            wintypes.LPARAM,
        )

        class MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        def callback(hmonitor, _hdc, _rect, _data):
            info = MONITORINFO()
            info.cbSize = ctypes.sizeof(MONITORINFO)
            if ctypes.windll.user32.GetMonitorInfoW(hmonitor, ctypes.byref(info)):
                rect = info.rcMonitor
                monitors.append(
                    {
                        "x": int(rect.left),
                        "y": int(rect.top),
                        "width": int(rect.right - rect.left),
                        "height": int(rect.bottom - rect.top),
                    }
                )
            return 1

        ctypes.windll.user32.EnumDisplayMonitors(0, 0, enum_proc(callback), 0)
    except Exception:
        monitors = []
    if monitors:
        return monitors
    try:
        user32 = ctypes.windll.user32
        return [{"x": 0, "y": 0, "width": int(user32.GetSystemMetrics(0)), "height": int(user32.GetSystemMetrics(1))}]
    except Exception:
        return [{"x": 0, "y": 0, "width": 1920, "height": 1080}]


def virtual_screen_bounds():
    try:
        user32 = ctypes.windll.user32
        x = int(user32.GetSystemMetrics(76))   # SM_XVIRTUALSCREEN
        y = int(user32.GetSystemMetrics(77))   # SM_YVIRTUALSCREEN
        w = int(user32.GetSystemMetrics(78))   # SM_CXVIRTUALSCREEN
        h = int(user32.GetSystemMetrics(79))   # SM_CYVIRTUALSCREEN
        if w > 0 and h > 0:
            return {"x": x, "y": y, "width": w, "height": h}
    except Exception:
        pass
    monitors = all_monitor_bounds()
    if not monitors:
        return {"x": 0, "y": 0, "width": 1920, "height": 1080}
    min_x = min(int(item.get("x", 0)) for item in monitors)
    min_y = min(int(item.get("y", 0)) for item in monitors)
    max_x = max(int(item.get("x", 0)) + int(item.get("width", 0)) for item in monitors)
    max_y = max(int(item.get("y", 0)) + int(item.get("height", 0)) for item in monitors)
    return {"x": min_x, "y": min_y, "width": max(1, max_x - min_x), "height": max(1, max_y - min_y)}


def startup_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = str(pythonw if pythonw.is_file() else sys.executable)
    return f'"{interpreter}" "{Path(__file__).resolve()}"'


def startup_enabled():
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
        winreg.QueryValueEx(key, RUN_VALUE)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def set_startup_enabled(enabled):
    if winreg is None:
        return
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        if enabled:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass


def request_ssl_context(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return None
    context = ssl.create_default_context()
    if parsed.hostname in INSECURE_HOSTS:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def http_json(origin, path, method="GET", token="", body=None, timeout=10, extra_headers=None):
    url = origin.rstrip("/") + path
    request = urllib.request.Request(url, method=method)
    request.add_header(DESKTOP_CLIENT_HEADER, "1")
    request.add_header(CLIENT_OS_HEADER, client_os_string())
    for name, value in (extra_headers or {}).items():
        request.add_header(name, value)
    if token:
        request.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, data=data, timeout=timeout, context=request_ssl_context(url)) as response:
        return json.loads(response.read().decode("utf-8")), response.geturl()


def http_download(origin, path, token, timeout=30, default_suffix=".wav"):
    url = origin.rstrip("/") + path
    request = urllib.request.Request(url)
    request.add_header(DESKTOP_CLIENT_HEADER, "1")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=timeout, context=request_ssl_context(url)) as response:
        suffix = os.path.splitext(urllib.parse.urlparse(response.geturl()).path)[1] or default_suffix
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        handle.write(response.read())
        handle.close()
        return handle.name


def _is_cert_error(exc):
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLCertVerificationError)


def validate_server_info_payload(info):
    payload = info if isinstance(info, dict) else {}
    product_name = str(payload.get("product_name") or "").strip()
    websocket_path = str(payload.get("websocket_path") or "").strip()
    keepalive_path = str(payload.get("keepalive_path") or "").strip()
    if not product_name:
        raise ValueError("The server did not identify itself as Open Paging Server.")
    if websocket_path != "/desktop/ws" or keepalive_path != "/desktop/session/ping":
        raise ValueError("The server did not return a valid Open Paging Server desktop client configuration.")
    return payload


def probe_server(text, confirm_http=None, confirm_cert=None):
    raw = str(text or "").strip().rstrip("/")
    if not raw:
        raise ValueError("Please enter a server address.")
    if "://" in raw:
        candidates = [raw]
    else:
        parsed_raw = urllib.parse.urlparse("//" + raw)
        candidates = ["https://" + raw]
        if parsed_raw.port != 443:
            candidates.append("http://" + raw)
    last_error = None
    for base in candidates:
        host = urllib.parse.urlparse(base).hostname or ""
        attempt = 0
        while attempt < 2:
            attempt += 1
            try:
                info, final_url = http_json(base, "/desktop/server-info")
            except Exception as exc:
                if _is_cert_error(exc) and host and host not in INSECURE_HOSTS:
                    if confirm_cert is not None and confirm_cert(host):
                        INSECURE_HOSTS.add(host)
                        continue
                last_error = exc
                break
            parsed = urllib.parse.urlparse(final_url)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else base
            if origin.startswith("http://") and confirm_http is not None and not confirm_http(origin):
                raise ValueError("Connection cancelled.")
            return validate_server_info_payload(info), origin
    raise ConnectionError(f"Could not reach the server: {last_error}")


def build_ulaw_to_linear_table():
    table = []
    for index in range(256):
        ulaw = (~index) & 0xFF
        sign = ulaw & 0x80
        exponent = (ulaw >> 4) & 0x07
        mantissa = ulaw & 0x0F
        sample = ((mantissa << 3) + 0x84) << exponent
        table.append(0x84 - sample if sign else sample - 0x84)
    return table


ULAW_TO_LINEAR_TABLE = build_ulaw_to_linear_table()


def ulaw_frame_to_pcm16(frame):
    data = bytes(frame or b"")
    if not data:
        return b""
    if audioop is not None:
        try:
            return audioop.ulaw2lin(data, 2)
        except Exception:
            pass
    out = bytearray()
    for byte in data:
        out.extend(struct.pack("<h", int(ULAW_TO_LINEAR_TABLE[byte])))
    return bytes(out)


def parse_ts(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, pattern)
        except ValueError:
            continue
    return None


class AudioPlayer:
    def __init__(self, on_state_change=None):
        self.lock = threading.Lock()
        self.device = None
        self.playing = False
        self.current_path = ""
        self.mode = "idle"
        self.active_broadcast_id = ""
        self.live_paused = False
        self.live_queue = deque()
        self.live_queue_max = 180
        self.live_last_chunk = b""
        self.live_gap_repeats = 0
        self.live_stream_closed = False
        self.live_stop_event = threading.Event()
        self._live_frame_event = threading.Event()  # signals generator when frame arrives
        self.recordings = {}
        self.on_state_change = on_state_change

    def _notify(self):
        if self.on_state_change is not None:
            try:
                self.on_state_change(self.playing)
            except Exception:
                pass

    def _silence_chunk(self, frames=160):
        return b"\x00" * max(1, int(frames)) * 2

    def _live_generator(self):
        # Accumulate raw PCM bytes
        buffer = bytearray()
        live_buffering = True
        
        # First yield to support priming
        num_frames = (yield b"") or 160
        while not self.live_stop_event.is_set():
            bytes_needed = (num_frames or 160) * 2
            chunk = None
            active = False
            notify = False
            
            with self.lock:
                active = bool(self.mode == "live" and not self.live_paused)
                if active:
                    # Pull all available frames from self.live_queue
                    while self.live_queue:
                        buffer.extend(self.live_queue.popleft())
                    
                    if not buffer and self.live_stream_closed:
                        self.live_paused = True
                        self.playing = False
                        self.live_last_chunk = b""
                        self.live_gap_repeats = 0
                        notify = True
            
            # If we are buffering, wait until we have a safe amount of audio before playing
            if active and live_buffering and not self.live_stream_closed:
                target_buffer_size = 5 * bytes_needed
                if len(buffer) < target_buffer_size:
                    start_wait = time.time()
                    while len(buffer) < target_buffer_size and not self.live_stream_closed:
                        # Max wait 200ms while buffering
                        if time.time() - start_wait > 0.20:
                            break
                        self._live_frame_event.wait(timeout=0.01)
                        self._live_frame_event.clear()
                        with self.lock:
                            while self.live_queue:
                                buffer.extend(self.live_queue.popleft())
                
                if len(buffer) >= target_buffer_size or self.live_stream_closed:
                    live_buffering = False

            # If playing but we ran out of audio, do a very quick wait
            if active and not live_buffering and len(buffer) < bytes_needed and not self.live_stream_closed:
                start_wait = time.time()
                while len(buffer) < bytes_needed and not self.live_stream_closed:
                    if time.time() - start_wait > 0.015:
                        break
                    self._live_frame_event.wait(timeout=0.005)
                    self._live_frame_event.clear()
                    with self.lock:
                        while self.live_queue:
                            buffer.extend(self.live_queue.popleft())
                
                # If we still don't have enough, enter buffering mode to rebuild the cushion
                if len(buffer) < bytes_needed and not self.live_stream_closed:
                    live_buffering = True

            if active and live_buffering:
                chunk = self._silence_chunk(num_frames or 160)
            elif len(buffer) >= bytes_needed:
                # Extract exactly bytes_needed
                chunk = bytes(buffer[:bytes_needed])
                del buffer[:bytes_needed]
                self.live_last_chunk = chunk
                self.live_gap_repeats = 0
            elif len(buffer) > 0:
                # Partially filled buffer, pad with silence
                chunk = bytes(buffer)
                chunk += b"\x00" * (bytes_needed - len(buffer))
                buffer.clear()
                self.live_last_chunk = chunk
                self.live_gap_repeats = 0
            else:
                # Completely empty buffer, handle repeats or silence
                with self.lock:
                    still_active = bool(self.mode == "live" and not self.live_paused)
                    if (
                        still_active
                        and not self.live_stream_closed
                        and self.live_last_chunk
                        and self.live_gap_repeats < 2
                    ):
                        chunk = self.live_last_chunk
                        self.live_gap_repeats += 1
                    else:
                        chunk = self._silence_chunk(num_frames or 160)
            
            if notify:
                self._notify()
            num_frames = (yield chunk) or 160

    def _start_live_device_locked(self):
        if miniaudio is None:
            return False
        if self.device is not None and self.mode == "live":
            return True
        try:
            self.live_stop_event.clear()
            self.device = miniaudio.PlaybackDevice(
                output_format=miniaudio.SampleFormat.SIGNED16,
                nchannels=1,
                sample_rate=8000,
            )
            gen = self._live_generator()
            next(gen)  # Prime the generator!
            self.device.start(gen)
            return True
        except Exception:
            self.device = None
            return False

    def _close_device_locked(self):
        if self.device is not None:
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None

    def _recording_entry(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return None
        entry = self.recordings.get(bid)
        if entry is not None:
            return entry
        runtime_dir = Path(tempfile.gettempdir()) / "openpagingserver-runtime" / "broadcast-recordings"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        path = runtime_dir / f"desktop-broadcast-{bid}.wav"
        try:
            handle = wave.open(str(path), "wb")
            handle.setnchannels(1)
            handle.setsampwidth(2)
            handle.setframerate(8000)
        except Exception:
            return None
        entry = {
            "path": str(path),
            "writer": handle,
            "expires": None,
            "active": True,
            "updated_at": time.time(),
        }
        self.recordings[bid] = entry
        return entry

    def register_broadcast(self, broadcast_id, expires="", issued=""):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return
        with self.lock:
            entry = self._recording_entry(bid)
            if entry is None:
                return
            expires_at = parse_ts(expires)
            if expires_at is None:
                issued_at = parse_ts(issued) or datetime.now()
                expires_at = issued_at + timedelta(hours=24)
            entry["expires"] = expires_at
            entry["updated_at"] = time.time()
            self._cleanup_expired_locked()

    def _cleanup_expired_locked(self):
        now = datetime.now()
        stale_ids = []
        for bid, entry in list(self.recordings.items()):
            expires_at = entry.get("expires")
            if expires_at is None or expires_at > now:
                continue
            writer = entry.get("writer")
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                entry["writer"] = None
            path = str(entry.get("path") or "")
            if path:
                try:
                    os.remove(path)
                except OSError:
                    pass
            stale_ids.append(bid)
        for bid in stale_ids:
            self.recordings.pop(bid, None)

    def push_live_frame(self, broadcast_id, frame):
        bid = str(broadcast_id or "").strip()
        data = bytes(frame or b"")
        if not bid or not data:
            return
        pcm = ulaw_frame_to_pcm16(data)
        if not pcm:
            return
        wav_writer = None
        with self.lock:
            entry = self._recording_entry(bid)
            if entry is not None and entry.get("writer") is not None:
                wav_writer = entry["writer"]
                entry["updated_at"] = time.time()
            if self.mode == "live" and self.active_broadcast_id == bid and not self.live_paused:
                self.live_stream_closed = False
                self.live_queue.append(pcm)
                while len(self.live_queue) > self.live_queue_max:
                    self.live_queue.popleft()
                self._live_frame_event.set()
        # Write WAV outside the lock so disk I/O doesn't block the audio generator
        if wav_writer is not None:
            try:
                wav_writer.writeframesraw(pcm)
            except Exception:
                with self.lock:
                    entry = self.recordings.get(bid)
                    if entry and entry.get("writer") is wav_writer:
                        try:
                            entry["writer"].close()
                        except Exception:
                            pass
                        entry["writer"] = None

    def end_live_stream(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return
        with self.lock:
            entry = self.recordings.get(bid)
            if entry is not None and entry.get("writer") is not None:
                try:
                    entry["writer"].close()
                except Exception:
                    pass
                entry["writer"] = None
                entry["active"] = False
            if self.active_broadcast_id == bid:
                self.live_stream_closed = True
                if not self.live_queue:
                    self.live_paused = True
                    self.live_last_chunk = b""
                    self.live_gap_repeats = 0
                    self.playing = False
            self._cleanup_expired_locked()
        self._live_frame_event.set()
        self._notify()

    def start_live(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return False
        with self.lock:
            self.current_path = ""
            self.mode = "live"
            self.active_broadcast_id = bid
            self.live_paused = False
            self.live_stream_closed = False
            self.live_queue.clear()
            self.live_last_chunk = b""
            self.live_gap_repeats = 0
            self.playing = self._start_live_device_locked()
        self._notify()
        self._live_frame_event.set()
        return self.playing

    def stop_live(self):
        with self.lock:
            if self.mode != "live":
                return
            self.live_paused = True
            self.live_stream_closed = True
            self.live_queue.clear()
            self.live_last_chunk = b""
            self.live_gap_repeats = 0
            self.playing = False
        self._notify()

    def play_recording(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return False
        with self.lock:
            entry = self.recordings.get(bid)
            path = str((entry or {}).get("path") or "")
            if (
                self.mode == "file"
                and self.playing
                and path
                and str(self.current_path or "") == path
            ):
                self.stop()
                return False
        if not path or not os.path.isfile(path):
            return False
        return self.play_file(path)

    def play_file(self, path):
        self.stop()
        with self.lock:
            self.current_path = path
            self.mode = "file"
            if miniaudio is not None:
                try:
                    stream = miniaudio.stream_file(path)
                    self.device = miniaudio.PlaybackDevice()
                    self.device.start(stream)
                    self.playing = True
                    self._notify()
                    return True
                except Exception:
                    self.device = None
            if winsound is not None and path.lower().endswith(".wav"):
                try:
                    winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                    self.playing = True
                    self._notify()
                    return True
                except Exception:
                    pass
        return False

    def replay(self):
        if self.current_path and os.path.isfile(self.current_path):
            self.play_file(self.current_path)

    def toggle_dashboard_audio(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        if not bid:
            return False
        with self.lock:
            entry = self.recordings.get(bid) or {}
            has_live = bool(entry.get("active"))
            playing_file = bool(
                self.mode == "file"
                and self.playing
                and str(entry.get("path") or "")
                and str(entry.get("path") or "") == str(self.current_path or "")
            )
        if playing_file:
            self.stop()
            return False
        if has_live:
            notify = False
            with self.lock:
                if self.mode == "live" and self.active_broadcast_id == bid and not self.live_paused:
                    self.live_paused = True
                    self.live_queue.clear()
                    self.playing = False
                    notify = True
            if notify:
                self._notify()
                return False
            return self.start_live(bid)
        return self.play_recording(bid)

    def dashboard_audio_state(self, broadcast_id):
        bid = str(broadcast_id or "").strip()
        with self.lock:
            entry = self.recordings.get(bid) or {}
            live_active = bool(entry.get("active"))
            playing_file = bool(
                self.mode == "file"
                and self.playing
                and str(entry.get("path") or "")
                and str(entry.get("path") or "") == str(self.current_path or "")
            )
            playing_live = bool(self.mode == "live" and self.active_broadcast_id == bid and not self.live_paused and self.playing)
            playing = bool(playing_live or playing_file)
            has_recording = bool(entry)
        mode = "live" if live_active else ("recording" if has_recording else "none")
        return {"playing": playing, "mode": mode}

    def live_state(self):
        with self.lock:
            return {
                "mode": str(self.mode or "idle"),
                "broadcast_id": str(self.active_broadcast_id or ""),
                "paused": bool(self.live_paused),
                "playing": bool(self.playing),
            }

    def stop(self):
        with self.lock:
            self.live_stop_event.set()
            self.live_queue.clear()
            self.live_stream_closed = True
            self.live_last_chunk = b""
            self.live_gap_repeats = 0
            self._live_frame_event.set()
            self.mode = "idle"
            self.active_broadcast_id = ""
            self.live_paused = False
            if self.device is not None:
                try:
                    self.device.close()
                except Exception:
                    pass
                self.device = None
            if winsound is not None:
                try:
                    winsound.PlaySound(None, winsound.SND_PURGE)
                except Exception:
                    pass
            self.playing = False
        self._notify()


class WebSocketClient:
    def __init__(self, origin, token, on_broadcast, on_audio_frame=None, on_audio_end=None):
        self.origin = origin
        self.token = token
        self.on_broadcast = on_broadcast
        self.on_audio_frame = on_audio_frame
        self.on_audio_end = on_audio_end
        self.sock = None
        self.stop_event = threading.Event()

    def connect(self):
        parsed = urllib.parse.urlparse(self.origin)
        secure = parsed.scheme == "https"
        host = parsed.hostname
        port = parsed.port or (443 if secure else 80)
        raw = socket.create_connection((host, port), timeout=15)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        if secure:
            context = ssl.create_default_context()
            if host in INSECURE_HOSTS:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            raw = context.wrap_socket(raw, server_hostname=host)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        handshake = (
            f"GET /desktop/ws?token={urllib.parse.quote(self.token)} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"{DESKTOP_CLIENT_HEADER}: 1\r\n"
            "\r\n"
        )
        raw.sendall(handshake.encode("ascii"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                break
            response += chunk
        status_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
        if "101" not in status_line:
            raw.close()
            if "401" in status_line:
                raise PermissionError("Unauthorized")
            raise ConnectionError(status_line)
        raw.settimeout(45)
        self.sock = raw

    def send_frame(self, opcode, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        mask = secrets.token_bytes(4)
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def read_exact(self, count):
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def read_frame(self):
        first = self.read_exact(2)
        opcode = first[0] & 0x0F
        masked = bool(first[1] & 0x80)
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.read_exact(8))[0]
        mask = self.read_exact(4) if masked else b""
        payload = self.read_exact(length) if length else b""
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def run(self):
        pinger = threading.Thread(target=self.ping_loop, daemon=True)
        pinger.start()
        while not self.stop_event.is_set():
            try:
                opcode, payload = self.read_frame()
            except socket.timeout:
                continue
            except Exception:
                break
            if opcode == 0x8:
                break
            if opcode == 0x9:
                try:
                    self.send_frame(0xA, payload)
                except Exception:
                    break
                continue
            if opcode == 0x1:
                try:
                    message = json.loads(payload.decode("utf-8"))
                except Exception:
                    continue
                if message.get("type") == "broadcast":
                    self.on_broadcast(message)
                continue
            if opcode == 0x2 and len(payload) >= 33:
                packet_type = chr(payload[0])
                broadcast_id = payload[1:33].decode("ascii", errors="ignore").strip()
                frame = payload[33:]
                if packet_type == "A" and self.on_audio_frame is not None:
                    try:
                        self.on_audio_frame(broadcast_id, frame)
                    except Exception:
                        pass
                elif packet_type == "E" and self.on_audio_end is not None:
                    try:
                        self.on_audio_end(broadcast_id)
                    except Exception:
                        pass

    def ping_loop(self):
        while not self.stop_event.is_set():
            time.sleep(20)
            try:
                self.send_frame(0x1, json.dumps({"type": "ping"}))
            except Exception:
                break

    def close(self):
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.send_frame(0x8)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def text_color_for(color):
    token = str(color or "").lstrip("#")
    try:
        r, g, b = int(token[0:2], 16), int(token[2:4], 16), int(token[4:6], 16)
    except (ValueError, IndexError):
        return "#FFFFFF"
    return "#1A1A1A" if (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.6 else "#FFFFFF"


def html_escape(value):
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


EMERGENCY_POPUP_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
*{-webkit-app-region:no-drag!important;user-select:none;box-sizing:border-box;}
html,body{height:100%;}
body{margin:0;background:__COLOR__;color:__TEXT__;font-family:Roboto,Arial,sans-serif;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;overflow:hidden;padding:clamp(22px,4vh,54px) clamp(18px,4vw,70px) clamp(88px,12vh,144px);}
#close{position:fixed;top:18px;right:18px;width:52px;height:52px;border:none;border-radius:50%;background:rgba(0,0,0,0.28);color:__TEXT__;font-size:26px;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;line-height:1;visibility:hidden;z-index:20;}
#close.ready{visibility:visible;}
#close:hover{background:rgba(0,0,0,0.42);}
#close:disabled{opacity:0.45;cursor:not-allowed;}
#content{width:100%;max-width:90vw;min-height:0;max-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;}
#icon{width:min(92px,14vh);height:min(92px,14vh);object-fit:contain;margin:0 0 clamp(10px,2vh,18px);flex:0 0 auto;}
.short{font-size:clamp(1.85rem,5.2vh,3rem);font-weight:500;max-width:85vw;line-height:1.25;white-space:pre-wrap;overflow-wrap:anywhere;flex:0 0 auto;}
.name{position:fixed;bottom:24px;left:24px;max-width:45vw;text-align:left;font-size:1.1em;opacity:0.9;white-space:pre-wrap;overflow-wrap:anywhere;z-index:10;}
.long{font-size:clamp(1rem,2.6vh,1.5rem);margin-top:clamp(8px,1.8vh,14px);max-width:85vw;line-height:1.35;white-space:pre-wrap;overflow-wrap:anywhere;min-height:0;overflow-y:auto;scrollbar-width:thin;padding:0 14px;flex:0 1 auto;}
.long::-webkit-scrollbar{width:12px;}
.long::-webkit-scrollbar-thumb{background:rgba(0,0,0,0.32);border-radius:999px;border:3px solid transparent;background-clip:content-box;}
.meta{position:fixed;bottom:24px;right:24px;max-width:50vw;text-align:right;font-size:0.95em;opacity:0.85;z-index:10;}
</style></head><body>
<button id="close" disabled>&#10005;</button>
<div id="content">
__ICON__
<div class="short">__SHORT__</div>
<div class="long">__LONG__</div>
</div>
__NAME__
<div class="meta">__META__</div>
<script>
var button = document.getElementById('close');
setTimeout(function(){
  button.disabled = false;
  button.classList.add('ready');
}, 30000);
document.querySelectorAll('[data-ts]').forEach(function(el){
  var d = new Date(el.getAttribute('data-ts').replace(' ', 'T'));
  if (!isNaN(d.getTime())) el.textContent = d.toLocaleString();
});
function numberValue(value){
  var parsed = parseFloat(value);
  return isNaN(parsed) ? 0 : parsed;
}
function elementOuterHeight(el){
  if (!el) return 0;
  var rect = el.getBoundingClientRect();
  var style = window.getComputedStyle(el);
  return rect.height + numberValue(style.marginTop) + numberValue(style.marginBottom);
}
function fitLongMessage(){
  var longMessage = document.querySelector('.long');
  var content = document.getElementById('content');
  if (!longMessage || !content) return;
  var viewportHeight = window.innerHeight || document.documentElement.clientHeight || 600;
  var bodyStyle = window.getComputedStyle(document.body);
  var reserved = numberValue(bodyStyle.paddingTop) + numberValue(bodyStyle.paddingBottom) + 32;
  Array.prototype.forEach.call(content.children, function(el){
    if (el !== longMessage) reserved += elementOuterHeight(el);
  });
  var meta = document.querySelector('.meta');
  var name = document.querySelector('.name');
  reserved += Math.min(140, Math.max(elementOuterHeight(meta), elementOuterHeight(name)) + 18);
  var maxHeight = Math.max(96, Math.floor(Math.min(viewportHeight * 0.58, viewportHeight - reserved)));
  longMessage.style.maxHeight = maxHeight + 'px';
  longMessage.style.overflowY = longMessage.scrollHeight > longMessage.clientHeight + 2 ? 'auto' : 'visible';
}
window.addEventListener('resize', fitLongMessage);
setTimeout(fitLongMessage, 0);
setTimeout(fitLongMessage, 150);
setTimeout(fitLongMessage, 600);
function tryClose(){
  if (button.disabled) return;
  var api = window.pywebview && window.pywebview.api;
  if (!api) return;
  api.request_close_popup('__POPUP_ID__');
}
button.addEventListener('click', tryClose);
</script>
</body></html>"""


INJECT_JS = r"""
(function(){
  if (window.__opsClientInjected) return;
  window.__opsClientInjected = true;
  window.__OPS_DESKTOP_CLIENT__ = true;

  // ── Live-stream audio suppression ─────────────────────────────────────────
  // Python's AudioPlayer owns all live-stream audio (messages, pages, bells).
  // Make sure the WebView never opens its own WebSocket or AudioContext for it,
  // even if pywebview was not ready when the dashboard script first ran.
  function __opsSuppressWebViewLiveAudio(){
    // Close any browser WebSocket already opened for live audio frames
    try {
      if (typeof dashWs !== 'undefined' && dashWs) {
        dashWs.close();
        dashWs = null;
      }
    } catch (_e) {}
    // Prevent the dashboard from (re)opening its browser WebSocket
    try {
      if (typeof connectDashboardWebSocket !== 'undefined') {
        connectDashboardWebSocket = function() {};
      }
    } catch (_e) {}
    // Shut down any live ScriptProcessor AudioContext the browser may have spun up
    try {
      if (typeof dashAudioNode !== 'undefined' && dashAudioNode) {
        dashAudioNode.disconnect();
        dashAudioNode = null;
      }
    } catch (_e) {}
    try {
      if (typeof dashAudioCtx !== 'undefined' && dashAudioCtx) {
        dashAudioCtx.close().catch(function() {});
        dashAudioCtx = null;
      }
    } catch (_e) {}
    // Block any stale audio frames from being queued into the (now-dead) context
    try {
      if (typeof queueLiveFrame !== 'undefined') queueLiveFrame = function() {};
    } catch (_e) {}
  }
  __opsSuppressWebViewLiveAudio();
  // Re-apply periodically in case dashboard scripts reinitialize after route/view changes.
  if (!window.__opsLiveAudioSuppressTimer) {
    window.__opsLiveAudioSuppressTimer = setInterval(__opsSuppressWebViewLiveAudio, 1500);
  }

  function requestLogout(){
    window.pywebview.api.confirm_logout().then(function(ok){
      if (ok) window.location.href = '/logout';
    });
  }
  function hookLogout(){
    if (!window.__opsLogoutWrapped){
      window.__opsLogoutWrapped = true;
      window.logout = requestLogout;
    }
    document.querySelectorAll('.logout-btn, .logout-btn-mobile, a.logout, a[href="/logout"]').forEach(function(el){
      if (el.__opsHooked) return;
      el.__opsHooked = true;
      el.removeAttribute('onclick');
      el.addEventListener('click', function(ev){
        ev.preventDefault();
        ev.stopImmediatePropagation();
        requestLogout();
      }, true);
    });
  }
  function addSettingsButton(){
    var account = document.querySelector('.sidebar-account');
    if (!account || document.getElementById('ops-client-settings-btn')) return;
    var link = document.createElement('a');
    link.id = 'ops-client-settings-btn';
    link.href = 'javascript:void(0)';
    link.innerHTML = '<span class="nav-icon"><i class="fa-solid fa-sliders"></i></span><span class="nav-label">App Settings</span>';
    link.addEventListener('click', function(ev){
      ev.preventDefault();
      window.pywebview.api.open_app_settings();
    });
    account.insertBefore(link, account.firstChild);
  }
  hookLogout();
  addSettingsButton();
  var observer = new MutationObserver(function(){ hookLogout(); addSettingsButton(); });
  observer.observe(document.documentElement, {childList: true, subtree: true});
})();
"""


class ToastCenter:
    def __init__(self, app):
        self.app = app
        self.toaster = None
        if WindowsToaster is not None:
            try:
                self.toaster = WindowsToaster(app.product_name)
            except Exception:
                self.toaster = None

    def refresh_name(self):
        if WindowsToaster is not None:
            try:
                self.toaster = WindowsToaster(self.app.product_name)
            except Exception:
                pass

    def show(self, title, body, icon_path=None, persistent=False, silent=False, on_click=None):
        def _show_in_thread():
            if self.toaster is not None:
                try:
                    toast = Toast()
                    toast.text_fields = [title, body] if body else [title]
                    if icon_path:
                        try:
                            toast.AddImage(ToastDisplayImage.fromPath(icon_path, position=ToastImagePosition.AppLogo))
                        except Exception:
                            pass
                    toast.duration = ToastDuration.Long if persistent else ToastDuration.Short
                    if persistent:
                        toast.scenario = ToastScenario.Reminder
                        toast.AddAction(ToastButton("Close", "close"))
                    if silent:
                        try:
                            from windows_toasts import ToastAudio
                            toast.audio = ToastAudio(silent=True)
                        except Exception:
                            pass
                    if on_click is not None:
                        toast.on_activated = lambda _args: on_click()
                    self.toaster.show_toast(toast)
                    return
                except Exception:
                    pass
            tray = self.app.tray
            if tray is not None:
                try:
                    tray.notify(body or title, title)
                    return
                except Exception:
                    pass
            print(f"{title}: {body}")
        threading.Thread(target=_show_in_thread, daemon=True).start()


class ServerAddressDialog:
    def __init__(self, app):
        self.app = app
        self.result = None

    def run(self):
        dark = system_uses_dark_mode()
        bg = "#1F1F1F" if dark else "#FFFFFF"
        fg = "#EEEEEE" if dark else "#1A1A1A"
        subtle = "#9E9E9E" if dark else "#666666"
        field_bg = "#2A2A2A" if dark else "#F5F5F5"
        accent = "#1976D2"
        closed = False
        ui_queue = queue.Queue()

        root = tk.Tk()
        root.title(self.app.product_name)
        root.configure(bg=bg)
        root.geometry("420x520")
        root.resizable(False, False)
        try:
            root.iconbitmap(app_ico_path())
        except Exception:
            pass
        root.update_idletasks()
        try:
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            apply_dark_titlebar(hwnd, dark)
        except Exception:
            pass
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        root.geometry(f"420x520+{(screen_w - 420) // 2}+{(screen_h - 520) // 2}")

        def close(result=None):
            nonlocal closed
            if closed:
                return
            closed = True
            if result is not None:
                self.result = result
            try:
                root.quit()
            except Exception:
                pass
            try:
                root.destroy()
            except Exception:
                pass

        def drain_queue():
            if closed:
                return
            while True:
                try:
                    callback = ui_queue.get_nowait()
                except queue.Empty:
                    break
                if not closed:
                    try:
                        callback()
                    except Exception:
                        pass
            if not closed:
                try:
                    root.after(50, drain_queue)
                except Exception:
                    pass

        def schedule(callback):
            if not closed:
                ui_queue.put(callback)

        root.after(50, drain_queue)

        logo_data = logo_png_bytes(dark)
        logo_image = tk.PhotoImage(data=base64.b64encode(logo_data).decode("ascii"))
        factor = max(1, logo_image.width() // 240)
        if factor > 1:
            logo_image = logo_image.subsample(factor, factor)
        logo_label = tk.Label(root, image=logo_image, bg=bg, borderwidth=0)
        logo_label.image = logo_image
        logo_label.pack(pady=(44, 18))

        label_font = tkfont.Font(family="Segoe UI", size=11)
        entry_font = tkfont.Font(family="Segoe UI", size=12)
        button_font = tkfont.Font(family="Segoe UI", size=11, weight="bold")

        tk.Label(root, text="Server Address", bg=bg, fg=fg, font=label_font).pack(pady=(6, 8))

        entry_frame = tk.Frame(root, bg=accent, padx=0, pady=0)
        entry_frame.pack()
        entry_inner = tk.Frame(entry_frame, bg=field_bg)
        entry_inner.pack(padx=0, pady=(0, 2))
        entry = tk.Entry(
            entry_inner, width=30, font=entry_font, bg=field_bg, fg=fg,
            insertbackground=fg, relief="flat", justify="center",
        )
        entry.pack(ipady=8, padx=2, pady=2)
        entry.insert(0, str(self.app.config.get("server_input") or ""))
        entry.focus_set()

        error_label = tk.Label(root, text="", bg=bg, fg="#E53935", font=label_font, wraplength=360, justify="center")
        error_label.pack(pady=(10, 0))

        status_label = tk.Label(root, text="", bg=bg, fg=subtle, font=label_font)
        status_label.pack(pady=(2, 0))

        def do_login():
            value = entry.get().strip()
            if not value:
                error_label.configure(text="Please enter a server address.")
                return
            error_label.configure(text="")
            status_label.configure(text="Connecting...")
            login_button.configure(state="disabled")

            def worker():
                def confirm_http(origin):
                    return native_message_box(
                        self.app.product_name,
                        f"{origin} does not use a secure connection (HTTP). Your pages will not be encrypted. Do you want to continue?",
                        MB_YESNO | MB_ICONWARNING,
                    ) == IDYES

                def confirm_cert(host):
                    accepted = native_message_box(
                        self.app.product_name,
                        f"The security certificate presented by {host} is not trusted. Do you want to continue anyway?",
                        MB_YESNO | MB_ICONWARNING,
                    ) == IDYES
                    if accepted:
                        trusted = set(self.app.config.get("insecure_hosts") or [])
                        trusted.add(host)
                        self.app.config["insecure_hosts"] = sorted(trusted)
                        save_config(self.app.config)
                    return accepted

                try:
                    info, origin = probe_server(value, confirm_http=confirm_http, confirm_cert=confirm_cert)
                except Exception as exc:
                    message = str(exc)
                    schedule(lambda msg=message: (error_label.configure(text=msg), status_label.configure(text=""), login_button.configure(state="normal")))
                    return
                schedule(lambda: close((value, info, origin)))

            threading.Thread(target=worker, daemon=True).start()

        login_button = tk.Button(
            root, text="LOGIN", command=do_login, font=button_font,
            bg=accent, fg="#FFFFFF", activebackground="#1565C0", activeforeground="#FFFFFF",
            relief="flat", cursor="hand2", padx=60, pady=8, borderwidth=0,
        )
        login_button.pack(pady=(22, 0))

        if self.app.config.get("server"):
            def do_disconnect():
                self.app.disconnect_from_server()
                error_label.configure(text="")
                status_label.configure(text="Disconnected from previous server.")
                entry.delete(0, "end")
                disconnect_button.pack_forget()

            disconnect_button = tk.Button(
                root, text="Disconnect from server", command=do_disconnect, font=label_font,
                bg=bg, fg="#E53935", activebackground=bg, activeforeground="#B71C1C",
                relief="flat", cursor="hand2", borderwidth=0,
            )
            disconnect_button.pack(pady=(14, 0))

        entry.bind("<Return>", lambda _ev: do_login())
        root.protocol("WM_DELETE_WINDOW", lambda: close(None))
        try:
            root.mainloop()
        finally:
            try:
                logo_label.configure(image="")
                logo_label.image = None
            except Exception:
                pass
        return self.result


class AppSettingsWindow:
    def __init__(self, app):
        self.app = app

    def run(self):
        if not self.app.origin:
            return
        if self.app.config.get("require_uac") and not uac_approved():
            return
        dark = system_uses_dark_mode()
        bg = "#1F1F1F" if dark else "#FFFFFF"
        fg = "#EEEEEE" if dark else "#1A1A1A"
        accent = "#1976D2"
        red = "#C62828"
        closed = False

        root = tk.Tk()
        root.title("App Settings")
        root.configure(bg=bg)
        root.geometry("380x390")
        root.resizable(False, False)
        try:
            root.iconbitmap(app_ico_path())
        except Exception:
            pass
        root.update_idletasks()
        try:
            apply_dark_titlebar(ctypes.windll.user32.GetParent(root.winfo_id()), dark)
        except Exception:
            pass
        root.geometry(f"380x390+{(root.winfo_screenwidth() - 380) // 2}+{(root.winfo_screenheight() - 390) // 2}")

        def close():
            nonlocal closed
            if closed:
                return
            closed = True
            try:
                root.quit()
            except Exception:
                pass
            try:
                root.destroy()
            except Exception:
                pass

        tk.Label(root, text="App Settings", bg=bg, fg=fg, font=tkfont.Font(family="Segoe UI", size=13, weight="bold")).pack(pady=(22, 16))

        button_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        normal_font = tkfont.Font(family="Segoe UI", size=11)
        startup_state = [startup_enabled()]
        uac_state = [bool(self.app.config.get("require_uac"))]

        def startup_text():
            return "Launch at startup: " + ("On" if startup_state[0] else "Off")

        def uac_text():
            return "Require UAC for App Settings: " + ("On" if uac_state[0] else "Off")

        def toggle_startup():
            startup_state[0] = not startup_state[0]
            set_startup_enabled(startup_state[0])
            startup_button.configure(text=startup_text())

        def toggle_uac():
            uac_state[0] = not uac_state[0]
            self.app.config["require_uac"] = bool(uac_state[0])
            save_config(self.app.config)
            uac_button.configure(text=uac_text())

        startup_button = tk.Button(
            root, text=startup_text(), command=toggle_startup,
            bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
            relief="groove", cursor="hand2", padx=16, pady=7, borderwidth=1, font=normal_font,
        )
        startup_button.pack(pady=(0, 10))

        uac_button = tk.Button(
            root, text=uac_text(), command=toggle_uac,
            bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
            relief="groove", cursor="hand2", padx=16, pady=7, borderwidth=1, font=normal_font,
        )
        uac_button.pack(pady=(0, 18))

        def do_disconnect():
            answer = native_message_box(
                self.app.product_name,
                "Disconnect from the server? You will stop receiving messages until you connect again.",
                MB_YESNO | MB_ICONQUESTION,
            )
            if answer == IDYES:
                close()
                self.app.disconnect_from_server()
                threading.Thread(target=self.app.show_server_dialog, daemon=True).start()

        def do_close_client():
            answer = native_message_box(
                self.app.product_name,
                "Close the client? You will not receive pages or emergency notifications while it is closed.",
                MB_YESNO | MB_ICONWARNING,
            )
            if answer == IDYES:
                close()
                self.app.quit()

        tk.Button(
            root, text="DISCONNECT FROM SERVER", command=do_disconnect,
            bg=accent, fg="#FFFFFF", activebackground="#1565C0", activeforeground="#FFFFFF",
            relief="flat", cursor="hand2", padx=20, pady=8, borderwidth=0, font=button_font,
        ).pack(pady=(0, 12))
        tk.Button(
            root, text="CLOSE CLIENT", command=do_close_client,
            bg=red, fg="#FFFFFF", activebackground="#B71C1C", activeforeground="#FFFFFF",
            relief="flat", cursor="hand2", padx=20, pady=8, borderwidth=0, font=button_font,
        ).pack()
        root.protocol("WM_DELETE_WINDOW", close)
        root.mainloop()

class ClientApp:
    def __init__(self):
        self.config = load_config()
        self.origin = str(self.config.get("server") or "")
        self.token = read_secure_config_value(self.config, "token")
        self.refresh_token = read_secure_config_value(self.config, "refresh_token")
        self.role = str(self.config.get("role") or "")
        self.user_id = self.config.get("user_id")
        self.product_name = str(self.config.get("product_name") or APP_FALLBACK_NAME)
        self.guest_available = bool(self.config.get("guest_available"))
        self.ws = None
        self.ws_thread = None
        self.tray = None
        self.main_window = None
        self.popups = {}
        self.connected = False
        self.startup_check_done = False
        self.reconnect_stop = threading.Event()
        self.seen_broadcasts = set()
        self.tk_lock = threading.Lock()
        self.toasts = None
        self.receive_flash_until = 0.0
        self.auth_notified = False
        self.cert_prompt_shown = False
        self.current_url = ""
        self.popup_close_confirming = threading.Event()
        INSECURE_HOSTS.update(str(host) for host in (self.config.get("insecure_hosts") or []))
        self.audio = AudioPlayer(on_state_change=self._on_audio_state_change)
        self.persist_session_state()

    def main_window_hwnd(self):
        window = self.main_window
        if window is None:
            return 0
        try:
            return int(window.native.Handle.ToInt64())
        except Exception:
            pass
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, self.product_name)
            return int(hwnd or 0)
        except Exception:
            return 0

    def apply_native_icon(self, window):
        def worker():
            for _attempt in range(40):
                native = getattr(window, "native", None)
                if native is not None:
                    try:
                        from System.Drawing import Icon
                        from System import Action
                        path = app_ico_path()
                        native.Invoke(Action(lambda: setattr(native, "Icon", Icon(path))))
                        return
                    except Exception:
                        try:
                            native.Icon = __import__("System.Drawing", fromlist=["Icon"]).Icon(app_ico_path())
                            return
                        except Exception:
                            return
                time.sleep(0.25)

        threading.Thread(target=worker, daemon=True).start()

    def _on_audio_state_change(self, playing):
        """Push audio state to webview dashboard without using async API callbacks."""
        window = self.main_window
        if window is None:
            return
        if not self.current_url or "dashboard" not in self.current_url:
            return
        bid = str(self.audio.active_broadcast_id or "")
        js_playing = "true" if playing else "false"
        try:
            window.evaluate_js(
                f"if(typeof window.__opsUpdateAudioState==='function'){{window.__opsUpdateAudioState({json.dumps(bid)},{js_playing});}}"
            )
        except Exception:
            pass

    def _force_popup_focus(self, windows, monitor_bounds):
        """Force popup windows topmost, focused, and completely unmovable via WndProc hook + snap loop."""
        def worker():
            time.sleep(0.5)
            HWND_TOPMOST = -1
            SW_SHOW = 5
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            SWP_NOACTIVATE = 0x0010
            SWP_SHOWWINDOW = 0x0040
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            def activate_window(hwnd):
                try:
                    user32.AllowSetForegroundWindow(0xFFFFFFFF)
                except Exception:
                    pass
                attached_threads = []
                current_thread = 0
                try:
                    current_thread = int(kernel32.GetCurrentThreadId())
                    foreground = user32.GetForegroundWindow()
                    thread_ids = []
                    if foreground:
                        thread_ids.append(int(user32.GetWindowThreadProcessId(foreground, None)))
                    thread_ids.append(int(user32.GetWindowThreadProcessId(hwnd, None)))
                    for thread_id in sorted(set(thread_ids)):
                        if thread_id and current_thread and thread_id != current_thread:
                            try:
                                if user32.AttachThreadInput(current_thread, thread_id, True):
                                    attached_threads.append(thread_id)
                            except Exception:
                                pass
                except Exception:
                    pass
                try:
                    user32.ShowWindow(hwnd, SW_SHOW)
                    user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
                    user32.BringWindowToTop(hwnd)
                    try:
                        user32.SetActiveWindow(hwnd)
                    except Exception:
                        pass
                    try:
                        user32.SetFocus(hwnd)
                    except Exception:
                        pass
                    user32.SetForegroundWindow(hwnd)
                except Exception:
                    pass
                finally:
                    for thread_id in attached_threads:
                        try:
                            user32.AttachThreadInput(current_thread, thread_id, False)
                        except Exception:
                            pass

            hwnd_bounds = []
            for win, bounds in zip(windows, monitor_bounds):
                hwnd = None
                for _ in range(20):
                    native = getattr(win, "native", None)
                    if native is not None:
                        try:
                            hwnd = int(native.Handle.ToInt64())
                        except Exception:
                            pass
                        break
                    time.sleep(0.25)
                if not hwnd:
                    continue
                try:
                    user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
                    user32.ShowWindow(hwnd, SW_SHOW)
                    user32.BringWindowToTop(hwnd)
                    activate_window(hwnd)
                except Exception:
                    pass
                hwnd_bounds.append((hwnd, bounds))
                _hook_no_move(hwnd)

            # Snap loop: reposition aggressively as secondary defense against movement.
            # Also acts as a watchdog — auto-closes on repeated errors.
            error_count = 0
            max_errors = 12
            last_focus_attempt = 0.0
            while hwnd_bounds:
                alive = False
                alive_hwnds = []
                confirming_close = bool(getattr(self, "popup_close_confirming", None) and self.popup_close_confirming.is_set())
                for hwnd, b in hwnd_bounds:
                    if not user32.IsWindow(hwnd):
                        continue
                    alive = True
                    alive_hwnds.append(hwnd)
                    if confirming_close:
                        continue
                    try:
                        user32.SetWindowPos(
                            hwnd, HWND_TOPMOST,
                            int(b["x"]), int(b["y"]),
                            max(1, int(b["width"])), max(1, int(b["height"])),
                            SWP_NOACTIVATE,
                        )
                    except Exception:
                        error_count += 1
                if not alive:
                    break
                try:
                    foreground = user32.GetForegroundWindow()
                except Exception:
                    foreground = 0
                now = time.time()
                if not confirming_close and alive_hwnds and foreground not in alive_hwnds and (now - last_focus_attempt) >= 0.15:
                    activate_window(alive_hwnds[0])
                    last_focus_attempt = now
                if error_count >= max_errors:
                    # Too many errors — force-close all popups and notify user
                    try:
                        for pop_id, wins in list(self.popups.items()):
                            self.popups.pop(pop_id, None)
                            for w in wins:
                                try:
                                    w.destroy()
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    native_message_box(
                        self.product_name,
                        "Error",
                        MB_YESNO | MB_ICONWARNING,
                        owner=0,
                    )
                    break
                time.sleep(0.01)

        threading.Thread(target=worker, daemon=True).start()

    def build_api(self):
        app = self

        class Api:
            def open_app_settings(self):
                threading.Thread(target=app.open_app_settings, daemon=True).start()
                return True

            def confirm_logout(self):
                answer = native_message_box(
                    app.product_name,
                    "Are you sure you want to log out? You may not be able to receive messages until you log in again.",
                    MB_YESNO | MB_ICONWARNING,
                    owner=app.main_window_hwnd(),
                )
                return answer == IDYES

            def request_close_popup(self, popup_id):
                threading.Thread(target=app.confirm_close_emergency, args=(str(popup_id),), daemon=True).start()
                return True

            def dashboard_toggle_audio(self, broadcast_id):
                playing = app.audio.toggle_dashboard_audio(str(broadcast_id or "").strip())
                return {"ok": True, "playing": bool(playing)}

            def dashboard_audio_state(self, broadcast_id):
                return app.audio.dashboard_audio_state(str(broadcast_id or "").strip())

        return Api()

    def set_product_name(self, name):
        cleaned = str(name or "").strip() or APP_FALLBACK_NAME
        if cleaned == self.product_name:
            return
        self.product_name = cleaned
        self.config["product_name"] = cleaned
        save_config(self.config)
        if self.tray is not None:
            self.tray.title = self.tray_tooltip()
        if self.main_window is not None:
            try:
                self.main_window.set_title(cleaned)
            except Exception:
                pass
        if self.toasts is not None:
            self.toasts.refresh_name()

    def tray_tooltip(self):
        return f"{self.product_name} - " + ("Connected" if self.connected else "Disconnected")

    def tray_icon_image(self):
        if time.time() < self.receive_flash_until:
            return tinted_favicon(COLOR_RECEIVING)
        if not self.origin or not self.token:
            return tinted_favicon(COLOR_IDLE)
        return tinted_favicon(COLOR_CONNECTED if self.connected else COLOR_DISCONNECTED)

    def refresh_tray(self):
        if self.tray is None:
            return
        try:
            self.tray.icon = self.tray_icon_image()
        except Exception:
            pass
        try:
            self.tray.title = self.tray_tooltip()
        except Exception:
            pass

    def flash_receiving(self):
        self.receive_flash_until = time.time() + 4
        self.refresh_tray()

        def restore():
            time.sleep(4.2)
            self.refresh_tray()

        threading.Thread(target=restore, daemon=True).start()

    def start_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem("Open", lambda: threading.Thread(target=self.show_main_window, daemon=True).start(), default=True),
            pystray.MenuItem("Stop audio", lambda: threading.Thread(target=self.audio.stop, daemon=True).start()),
            pystray.MenuItem("App Settings", lambda: threading.Thread(target=self.open_app_settings, daemon=True).start()),
        )
        self.tray = pystray.Icon("OpenPagingServerClient", self.tray_icon_image(), self.tray_tooltip(), menu)
        threading.Thread(target=self.tray.run, daemon=True).start()
        self.toasts = ToastCenter(self)

    def set_status(self, connected):
        was_connected = self.connected
        self.connected = connected
        if connected:
            self.auth_notified = False
        self.refresh_tray()
        if connected and not was_connected:
            self.maybe_show_welcome_toast()

    def maybe_show_welcome_toast(self):
        key = "welcomed:" + self.origin
        if self.config.get(key):
            return
        self.config[key] = True
        save_config(self.config)
        self.notify(
            f'Connected to "{self.product_name}"',
            "You are now ready to receive pages and emergency notifications from your organization.",
        )

    def notify(self, title, body, **kwargs):
        if self.toasts is not None:
            self.toasts.show(title, body, icon_path=app_toast_png_path(), **kwargs)
        else:
            print(f"{title}: {body}")

    def _desktop_page_path(self, path=""):
        raw = str(path or "").strip()
        if not raw:
            raw = "/" if not self.token or self.role == "guest" else "/dashboard"
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        if not raw.startswith("/"):
            raw = "/" + raw
        if "desktop_client=" in raw:
            return raw
        return raw + ("&" if "?" in raw else "?") + "desktop_client=1"

    def show_main_window(self, path=""):
        window = self.main_window
        if window is None:
            return
        try:
            window.show()
            window.restore()
        except Exception:
            pass
        if not self.origin:
            return
        target = self.origin + self._desktop_page_path(path)
        if path or not self.current_url.startswith(self.origin):
            try:
                window.load_url(target)
                self.current_url = target
            except Exception:
                pass

    def hide_main_window(self):
        if self.main_window is not None:
            try:
                self.main_window.hide()
            except Exception:
                pass
            try:
                self.main_window.load_url("about:blank")
                self.current_url = "about:blank"
            except Exception:
                pass

    def quit(self):
        self.reconnect_stop.set()
        if self.ws is not None:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None
        self.audio.stop()
        if self.main_window is not None:
            try:
                self.main_window.destroy()
            except Exception:
                pass
            self.main_window = None
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
            self.tray = None
        os._exit(0)

    def disconnect_from_server(self):
        self.reconnect_stop.set()
        if self.ws is not None:
            self.ws.close()
            self.ws = None
        self.audio.stop()
        self.token = ""
        self.refresh_token = ""
        self.role = ""
        self.user_id = None
        self.origin = ""
        self.guest_available = False
        for key in ("server", "server_input", "token", "token_enc", "refresh_token", "refresh_token_enc", "role", "user_id", "product_name", "guest_available"):
            self.config.pop(key, None)
        save_config(self.config)
        self.product_name = APP_FALLBACK_NAME
        self.connected = False
        self.auth_notified = False
        self.current_url = ""
        self.refresh_tray()
        self.hide_main_window()
        self.reconnect_stop = threading.Event()
        self.ws_thread = None

    def show_server_dialog(self):
        with self.tk_lock:
            result = ServerAddressDialog(self).run()
        if not result:
            if not self.origin:
                self.quit()
            return
        raw_input_value, info, origin = result
        self.apply_server(raw_input_value, info, origin)

    def apply_server(self, raw_input_value, info, origin):
        self.origin = origin
        self.guest_available = bool(info.get("guest_receiver_enabled"))
        self.set_product_name(info.get("product_name"))
        self.config.update({
            "server": origin,
            "server_input": raw_input_value,
            "guest_available": self.guest_available,
        })
        save_config(self.config)
        if self.guest_available and not self.token:
            try:
                session, _url = http_json(origin, "/desktop/session/guest", method="POST")
                self.apply_session(session)
            except Exception:
                pass
        self.start_reconnect_loop()
        self.show_main_window("/" if self.guest_available else "/login")

    def apply_session(self, session):
        self.token = str(session.get("token") or "")
        self.refresh_token = str(session.get("refresh_token") or self.refresh_token or "")
        user = session.get("user") or {}
        self.role = str(user.get("role") or "")
        self.user_id = user.get("id")
        self.persist_session_state()
        if self.ws is not None:
            self.ws.close()
            self.ws = None
        self.refresh_tray()
        if str(self.role or "").strip().lower() != "guest":
            self.sync_web_session_in_webview()

    def sync_web_session_in_webview(self):
        token = str(self.token or "").strip()
        window = self.main_window
        if str(self.role or "").strip().lower() == "guest" or str(self.user_id or "").strip().lower() == "guest":
            return
        if not token or window is None or not self.origin:
            return
        current = str(self.current_url or "")
        if current and (not current.startswith(self.origin) or current == "about:blank"):
            return
        script = (
            "(function(){"
            "var t=" + json.dumps(token) + ";"
            "if(!t)return false;"
            "return fetch('/desktop/session/web-login?desktop_client=1',{method:'POST',headers:{'"
            + DESKTOP_CLIENT_HEADER + "':'1','Authorization':'Bearer '+t}})"
            ".then(function(r){return !!r.ok;})"
            ".catch(function(){return false;});"
            "})()"
        )
        try:
            window.evaluate_js(script)
        except Exception:
            pass

    def persist_session_state(self):
        self.config.update({"role": self.role, "user_id": self.user_id})
        write_secure_config_value(self.config, "token", self.token)
        write_secure_config_value(self.config, "refresh_token", self.refresh_token)
        save_config(self.config)

    def refresh_desktop_session(self):
        if not self.origin or not self.refresh_token:
            return False
        try:
            session, _url = http_json(
                self.origin,
                "/desktop/session/refresh",
                method="POST",
                body={"refresh_token": self.refresh_token},
            )
        except Exception:
            return False
        token = str((session or {}).get("token") or "")
        if not token:
            return False
        self.apply_session(session)
        return True

    def open_app_settings(self):
        if self.config.get("require_uac") and not uac_approved():
            return
        with self.tk_lock:
            AppSettingsWindow(self).run()

    def start_reconnect_loop(self):
        if self.ws_thread is not None and self.ws_thread.is_alive():
            return
        self.ws_thread = threading.Thread(target=self.reconnect_loop, daemon=True)
        self.ws_thread.start()

    def reconnect_loop(self):
        delay = 2
        stop = self.reconnect_stop
        while not stop.is_set():
            if not self.origin or not self.token:
                time.sleep(2)
                continue
            client = WebSocketClient(
                self.origin,
                self.token,
                self.handle_broadcast,
                on_audio_frame=self.handle_audio_frame,
                on_audio_end=self.handle_audio_end,
            )
            try:
                client.connect()
            except ssl.SSLCertVerificationError:
                self.set_status(False)
                host = urllib.parse.urlparse(self.origin).hostname or ""
                if host and host not in INSECURE_HOSTS and not self.cert_prompt_shown:
                    self.cert_prompt_shown = True
                    accepted = native_message_box(
                        self.product_name,
                        f"The security certificate presented by {host} is not trusted. Do you want to continue anyway?",
                        MB_YESNO | MB_ICONWARNING,
                    ) == IDYES
                    if accepted:
                        INSECURE_HOSTS.add(host)
                        trusted = set(self.config.get("insecure_hosts") or [])
                        trusted.add(host)
                        self.config["insecure_hosts"] = sorted(trusted)
                        save_config(self.config)
                        continue
                time.sleep(min(delay, 30))
                delay = min(delay * 2, 30)
                continue
            except PermissionError:
                self.set_status(False)
                self.handle_auth_failure()
                time.sleep(5)
                continue
            except Exception as exc:
                self.set_status(False)
                if not self.startup_check_done:
                    self.startup_check_done = True
                    self.notify(self.product_name, f"Could not connect to the paging server: {exc}")
                time.sleep(min(delay, 30))
                delay = min(delay * 2, 30)
                continue
            delay = 2
            self.startup_check_done = True
            self.ws = client
            self.set_status(True)
            client.run()
            self.ws = None
            if not stop.is_set():
                self.set_status(False)
            time.sleep(2)

    def handle_auth_failure(self):
        if self.refresh_desktop_session():
            return
        self.token = ""
        self.persist_session_state()
        if self.guest_available and self.role == "guest":
            try:
                session, _url = http_json(self.origin, "/desktop/session/guest", method="POST")
                self.apply_session(session)
                return
            except Exception:
                pass
        if not self.auth_notified:
            self.auth_notified = True
            self.notify(self.product_name, "Your session has expired. Please log in again to keep receiving messages.")

    def poll_web_session(self):
        script = (
            "(function(){"
            "if(window._opsTokenBusy)return window._opsTokenValue||null;"
            "window._opsTokenBusy=true;"
            "fetch('/desktop/session/token?desktop_client=1',{method:'POST',headers:{'" + DESKTOP_CLIENT_HEADER + "':'1','"
            + CLIENT_OS_HEADER + "':'" + client_os_string() + "'}})"
            ".then(function(r){return r.ok?r.json():null})"
            ".then(function(d){window._opsTokenValue=d?JSON.stringify(d):null;window._opsTokenBusy=false;})"
            ".catch(function(){window._opsTokenBusy=false;});"
            "return window._opsTokenValue||null;})()"
        )
        while True:
            time.sleep(4)
            window = self.main_window
            if window is None or not self.origin:
                continue
            cur = self.current_url
            if not cur or cur == "about:blank" or not cur.startswith(self.origin):
                continue
            try:
                raw = window.evaluate_js(script)
            except Exception:
                continue
            if not raw:
                continue
            try:
                session = json.loads(raw)
            except Exception:
                continue
            token = str(session.get("token") or "")
            user = session.get("user") or {}
            refresh_token = str(session.get("refresh_token") or "")
            incoming_user_id = user.get("id")
            incoming_role = str(user.get("role") or "")
            current_user_id = str(self.user_id if self.user_id is not None else "")
            next_user_id = str(incoming_user_id if incoming_user_id is not None else "")
            current_role = str(self.role or "")
            same_signed_in_user = bool(
                self.token
                and current_user_id
                and next_user_id
                and current_user_id == next_user_id
                and current_role.strip().lower() == incoming_role.strip().lower()
                and current_role.strip().lower() != "guest"
            )
            should_apply = bool(
                token
                and not same_signed_in_user
                and (
                    not self.token
                    or current_role.strip().lower() == "guest"
                    or current_user_id != next_user_id
                    or current_role.strip().lower() != incoming_role.strip().lower()
                )
            )
            if should_apply:
                self.apply_session(session)
                self.start_reconnect_loop()
                try:
                    window.evaluate_js("window._opsTokenValue=null;")
                except Exception:
                    pass
            elif same_signed_in_user and (token != self.token or (refresh_token and refresh_token != self.refresh_token)):
                try:
                    window.evaluate_js("window._opsTokenValue=null;")
                except Exception:
                    pass

    def download_icon(self, broadcast_id, icon_name=""):
        if not broadcast_id:
            return None
        suffix = os.path.splitext(str(icon_name or ""))[1] or ".png"
        try:
            return http_download(self.origin, f"/desktop/broadcasts/{broadcast_id}/icon", self.token, default_suffix=suffix)
        except Exception:
            return None

    def handle_broadcast(self, message):
        broadcast_id = str(message.get("broadcast_id") or "")
        if broadcast_id:
            self.audio.register_broadcast(
                broadcast_id,
                expires=str(message.get("expires") or ""),
                issued=str(message.get("issued") or ""),
            )
            if bool(message.get("has_audio")) and not bool(message.get("late")):
                audio_mode = str(message.get("audio_mode") or "").strip().lower()
                if audio_mode in {"live", "websocket", "mulaw", "ulaw"}:
                    live_state = self.audio.live_state()
                    same_live = bool(
                        live_state.get("mode") == "live"
                        and str(live_state.get("broadcast_id") or "") == broadcast_id
                    )
                    if not same_live:
                        self.audio.start_live(broadcast_id)
        duplicate = bool(broadcast_id and broadcast_id in self.seen_broadcasts)
        if broadcast_id and not duplicate:
            self.seen_broadcasts.add(broadcast_id)
        self.set_product_name(message.get("product_name") or self.product_name)
        if duplicate:
            return
        if message.get("late"):
            return
        self.flash_receiving()
        shortmessage = str(message.get("shortmessage") or "").strip()
        longmessage = str(message.get("longmessage") or "").strip()
        priority = str(message.get("priority") or "Normal").strip().lower()
        has_audio = bool(message.get("has_audio"))
        has_text = bool(shortmessage or longmessage)
        if not has_text:
            return
        if priority == "emergency":
            self.show_emergency_popup(message)
        elif priority == "high":
            self.handle_high_priority(message)
        else:
            def show_toast_async():
                icon_path = toast_safe_icon(self.download_icon(broadcast_id, message.get("icon"))) or app_toast_png_path()
                if self.toasts is not None:
                    try:
                        self.toasts.show(
                            shortmessage or self.product_name,
                            longmessage,
                            icon_path=icon_path,
                            persistent=(priority != "low"),
                            silent=has_audio,
                            on_click=lambda: self.show_main_window("/dashboard"),
                        )
                    except Exception:
                        pass
            threading.Thread(target=show_toast_async, daemon=True).start()

    def handle_audio_frame(self, broadcast_id, frame):
        self.audio.push_live_frame(str(broadcast_id or "").strip(), frame)

    def handle_audio_end(self, broadcast_id):
        self.audio.end_live_stream(str(broadcast_id or "").strip())

    def handle_high_priority(self, message):
        prev = 0
        fullscreen = foreground_is_fullscreen()
        try:
            prev = ctypes.windll.user32.GetForegroundWindow()
        except Exception:
            prev = 0
        self.show_main_window("/dashboard")
        if fullscreen and prev:
            def restore_focus():
                time.sleep(0.6)
                try:
                    ctypes.windll.user32.SetForegroundWindow(prev)
                except Exception:
                    pass
            threading.Thread(target=restore_focus, daemon=True).start()

    def show_emergency_popup(self, message):
        popup_id = secrets.token_hex(8)
        color = str(message.get("color") or "#B71C1C")
        text_color = text_color_for(color)
        issued = str(message.get("issued") or "").strip()
        expires = str(message.get("expires") or "").strip()
        sender = str(message.get("sender") or "").strip()
        name = str(message.get("name") or "").strip()
        meta_parts = []
        if issued:
            meta_parts.append(f'Issued <span data-ts="{html_escape(issued)}">{html_escape(issued)}</span>')
        if expires:
            meta_parts.append(f'Expires <span data-ts="{html_escape(expires)}">{html_escape(expires)}</span>')
        meta_parts.append(html_escape(self.product_name))
        if sender:
            meta_parts.append(f"Sent by {html_escape(sender)}")
        icon_html = ""
        icon_path = self.download_icon(str(message.get("broadcast_id") or ""), message.get("icon"))
        if icon_path:
            try:
                raw = open(icon_path, "rb").read()
                mime = mimetypes.guess_type(str(message.get("icon") or icon_path))[0] or "image/png"
                icon_html = f'<img id="icon" src="data:{mime};base64,{base64.b64encode(raw).decode("ascii")}" alt="">'
            except Exception:
                icon_html = ""
        name_html = f'<div class="name">{html_escape(name)}</div>' if name else ""
        html = (
            EMERGENCY_POPUP_HTML
            .replace("__COLOR__", color)
            .replace("__TEXT__", text_color)
            .replace("__ICON__", icon_html)
            .replace("__SHORT__", html_escape(message.get("shortmessage")))
            .replace("__NAME__", name_html)
            .replace("__LONG__", html_escape(message.get("longmessage")))
            .replace("__META__", " &middot; ".join(meta_parts))
            .replace("__POPUP_ID__", popup_id)
        )
        popup_windows = []
        monitor_bounds = list(all_monitor_bounds())
        for bounds in monitor_bounds:
            win = webview.create_window(
                self.product_name,
                html=html,
                js_api=self.build_api(),
                x=int(bounds["x"]),
                y=int(bounds["y"]),
                width=max(1, int(bounds["width"])),
                height=max(1, int(bounds["height"])),
                on_top=True,
                fullscreen=True,
                resizable=False,
                frameless=True,
                easy_drag=False,
            )
            self.apply_native_icon(win)
            popup_windows.append(win)
        self.popups[popup_id] = popup_windows
        self._force_popup_focus(popup_windows, monitor_bounds)

    def confirm_close_emergency(self, popup_id):
        windows = list(self.popups.get(popup_id) or [])
        if not windows:
            return
        owner = 0
        for window in windows:
            native = getattr(window, "native", None)
            if native is None:
                continue
            try:
                owner = int(native.Handle.ToInt64())
            except Exception:
                owner = 0
            if owner:
                break
        self.popup_close_confirming.set()
        try:
            answer = native_message_box(
                self.product_name,
                "Are you sure you would like to close?",
                MB_YESNO | MB_ICONWARNING,
                owner=owner,
            )
        finally:
            self.popup_close_confirming.clear()
        if answer != IDYES:
            return
        self.popups.pop(popup_id, None)
        for window in windows:
            try:
                window.destroy()
            except Exception:
                pass

    def play_broadcast_audio(self, broadcast_id):
        if not broadcast_id or not self.origin or not self.token:
            return
        try:
            path = http_download(self.origin, f"/desktop/broadcasts/{broadcast_id}/audio", self.token)
        except Exception:
            return
        self.audio.play_file(path)

    def restore_session_after_restart(self):
        if not self.origin or self.token:
            return
        if self.refresh_desktop_session():
            return
        if self.guest_available:
            try:
                session, _url = http_json(self.origin, "/desktop/session/guest", method="POST")
                self.apply_session(session)
                return
            except Exception:
                pass
        window = self.main_window
        if window is None:
            return
        try:
            target = self.origin.rstrip("/") + self._desktop_page_path("/")
            window.load_url(target)
            self.current_url = target
        except Exception:
            pass

    def on_main_window_closing(self):
        self.hide_main_window()
        return False

    def on_main_window_loaded(self):
        window = self.main_window
        if window is None:
            return
        try:
            current = window.get_current_url() or ""
        except Exception:
            current = ""
        self.current_url = current
        if self.origin and current.startswith(self.origin):
            try:
                window.evaluate_js(INJECT_JS)
            except Exception:
                pass
            self.sync_web_session_in_webview()

    def bootstrap(self):
        self.start_tray()
        self.apply_native_icon(self.main_window)
        threading.Thread(target=self.poll_web_session, daemon=True).start()
        self.restore_session_after_restart()
        pending = getattr(self, "_pending_server", None)
        if pending:
            del self._pending_server
            self.apply_server(*pending)
            return
        if self.origin and self.token:
            self.start_reconnect_loop()
            self.refresh_tray()
        elif self.origin:
            self.start_reconnect_loop()
            if self.guest_available:
                self.show_main_window("/")
            else:
                self.show_main_window("/login")


def main():
    app = ClientApp()
    # Show server address dialog on the main thread BEFORE webview takes it over.
    # (tkinter must run on the main thread; webview.start() permanently captures it.)
    if not app.origin:
        result = ServerAddressDialog(app).run()
        if result:
            raw_input_value, info, origin = result
            app._pending_server = (raw_input_value, info, origin)
        else:
            return
    window = webview.create_window(
        app.product_name,
        url="about:blank",
        js_api=app.build_api(),
        width=1100,
        height=760,
        min_size=(900, 600),
        hidden=True,
    )
    app.main_window = window
    window.events.closing += app.on_main_window_closing
    window.events.loaded += app.on_main_window_loaded
    storage = CONFIG_DIR / "webview"
    try:
        storage.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        webview.start(app.bootstrap, private_mode=False, storage_path=str(storage), gui="edgechromium")
    except Exception:
        webview.start(app.bootstrap, private_mode=False, storage_path=str(storage))
    app.quit()


if __name__ == "__main__":
    main()
