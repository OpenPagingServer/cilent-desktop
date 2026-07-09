import base64
import ctypes
import io
import json
import mimetypes
import os
import platform
import queue
import secrets
import shutil
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
import webbrowser
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
EXTERNAL_BROWSER_SCHEMES = {"http", "https", "mailto", "tel"}
CONFIG_DIR = Path(os.getenv("APPDATA") or Path.home()) / "OpenPagingServerClient"
CONFIG_FILE = CONFIG_DIR / "config.json"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "OpenPagingServerClient"

AUTOSTART_FLAG = "--autostart"
AUTOSTART_ARG_VALUES = {"--autostart", "/autostart", "--minimized", "/minimized"}
SINGLE_INSTANCE_MUTEX = "OpenPagingServerClient_SingleInstance_Mutex"
SINGLE_INSTANCE_EVENT = "OpenPagingServerClient_ShowWindow_Event"

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
WM_DPICHANGED = 0x02E0
_SC_MOVE = 0xF010
_GWLP_WNDPROC = -4
_GWLP_HWNDPARENT = -8
_SWP_NOZORDER = 0x0004
_SWP_NOACTIVATE = 0x0010

FLASHW_STOP = 0x00000000
FLASHW_CAPTION = 0x00000001
FLASHW_TRAY = 0x00000002
FLASHW_ALL = FLASHW_CAPTION | FLASHW_TRAY
FLASHW_TIMERNOFG = 0x0000000C

# Per-window DPI awareness context handle; -1 == DPI_AWARENESS_CONTEXT_UNAWARE.
DPI_AWARENESS_CONTEXT_UNAWARE = -1
_popup_proc_refs: list = []
_dpi_proc_refs: list = []
_dpi_hooked_hwnds: set = set()
_SINGLE_INSTANCE_HANDLES: list = []

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


def _hook_dpi_changed(hwnd):
    """Honor WM_DPICHANGED on the main window so a Per-Monitor-DPI-aware app
    resizes to the OS-suggested rectangle when it moves between monitors with
    different scaling. pywebview's bundled .NET Framework WinForms host ignores
    this message, which otherwise makes the window progressively shrink and
    transition poorly (blurry) between mixed-DPI displays."""
    if not hwnd or os.name != "nt":
        return
    if hwnd in _dpi_hooked_hwnds:
        return
    try:
        user32 = ctypes.windll.user32
        user32.GetWindowLongPtrW.restype = ctypes.c_void_p
        user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.SetWindowLongPtrW.restype = ctypes.c_void_p
        user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        user32.CallWindowProcW.restype = ctypes.c_ssize_t
        user32.CallWindowProcW.argtypes = [
            ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        ]
        user32.SetWindowPos.argtypes = [
            wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, wintypes.UINT,
        ]

        _WndProc = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t,
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        )
        old_ptr = user32.GetWindowLongPtrW(hwnd, _GWLP_WNDPROC)
        if not old_ptr:
            return

        @_WndProc
        def _dpi_proc(h, msg, wp, lp):
            if msg == WM_DPICHANGED and lp:
                try:
                    suggested = ctypes.cast(lp, ctypes.POINTER(wintypes.RECT)).contents
                    user32.SetWindowPos(
                        h, None,
                        suggested.left, suggested.top,
                        suggested.right - suggested.left,
                        suggested.bottom - suggested.top,
                        _SWP_NOZORDER | _SWP_NOACTIVATE,
                    )
                    return 0
                except Exception:
                    pass
            return user32.CallWindowProcW(old_ptr, h, msg, wp, lp)

        user32.SetWindowLongPtrW(hwnd, _GWLP_WNDPROC, ctypes.cast(_dpi_proc, ctypes.c_void_p))
        _dpi_proc_refs.append((_dpi_proc, old_ptr))
        _dpi_hooked_hwnds.add(hwnd)
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
        x = int(user32.GetSystemMetrics(76))
        y = int(user32.GetSystemMetrics(77))
        w = int(user32.GetSystemMetrics(78))
        h = int(user32.GetSystemMetrics(79))
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
        return f'"{sys.executable}" {AUTOSTART_FLAG}'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = str(pythonw if pythonw.is_file() else sys.executable)
    return f'"{interpreter}" "{Path(__file__).resolve()}" {AUTOSTART_FLAG}'


def launched_at_startup():
    return any(str(arg).strip().lower() in AUTOSTART_ARG_VALUES for arg in sys.argv[1:])


def _acquire_single_instance():
    """Return (is_primary, mutex_handle). Non-Windows always acts as primary."""
    if not sys.platform.startswith("win"):
        return True, None
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        handle = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX)
        already_running = ctypes.get_last_error() == 183 or kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS
        return (not already_running), handle
    except Exception:
        return True, None


def create_show_event():
    """Create the named auto-reset event the primary instance waits on."""
    if not sys.platform.startswith("win"):
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        # CreateEventW(security, manual_reset=False, initial_state=False, name)
        return kernel32.CreateEventW(None, False, False, SINGLE_INSTANCE_EVENT)
    except Exception:
        return None


def signal_existing_instance():
    """Ask the already-running instance to bring its window to the front."""
    if not sys.platform.startswith("win"):
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenEventW.restype = wintypes.HANDLE
        kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        EVENT_MODIFY_STATE = 0x0002
        handle = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, SINGLE_INSTANCE_EVENT)
        if handle:
            kernel32.SetEvent(handle)
            kernel32.CloseHandle(handle)
            return True
    except Exception:
        pass
    return False


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
        self._live_frame_event = threading.Event()
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
        buffer = bytearray()
        live_buffering = True
        num_frames = (yield b"") or 160
        while not self.live_stop_event.is_set():
            bytes_needed = (num_frames or 160) * 2
            chunk = None
            active = False
            notify = False
            
            with self.lock:
                active = bool(self.mode == "live" and not self.live_paused)
                if active:
                    while self.live_queue:
                        buffer.extend(self.live_queue.popleft())
                    
                    if not buffer and self.live_stream_closed:
                        self.live_paused = True
                        self.playing = False
                        self.live_last_chunk = b""
                        self.live_gap_repeats = 0
                        notify = True
            
            if active and live_buffering and not self.live_stream_closed:
                target_buffer_size = 5 * bytes_needed
                if len(buffer) < target_buffer_size:
                    start_wait = time.time()
                    while len(buffer) < target_buffer_size and not self.live_stream_closed:
                        if time.time() - start_wait > 0.20:
                            break
                        self._live_frame_event.wait(timeout=0.01)
                        self._live_frame_event.clear()
                        with self.lock:
                            while self.live_queue:
                                buffer.extend(self.live_queue.popleft())
                
                if len(buffer) >= target_buffer_size or self.live_stream_closed:
                    live_buffering = False

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
                
                if len(buffer) < bytes_needed and not self.live_stream_closed:
                    live_buffering = True

            if active and live_buffering:
                chunk = self._silence_chunk(num_frames or 160)
            elif len(buffer) >= bytes_needed:
                chunk = bytes(buffer[:bytes_needed])
                del buffer[:bytes_needed]
                self.live_last_chunk = chunk
                self.live_gap_repeats = 0
            elif len(buffer) > 0:
                chunk = bytes(buffer)
                chunk += b"\x00" * (bytes_needed - len(buffer))
                buffer.clear()
                self.live_last_chunk = chunk
                self.live_gap_repeats = 0
            else:
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
            next(gen)
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
            if self.device is not None and self.mode != "live":
                self._close_device_locked()
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
            self._live_frame_event.set()
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
                    self._live_frame_event.set()
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


def desktop_token_identity(token):
    raw = str(token or "").strip()
    if "." not in raw:
        return ("", "", "")
    payload_b64 = raw.rsplit(".", 1)[0]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode((payload_b64 + padding).encode("ascii")).decode("utf-8"))
    except Exception:
        return ("", "", "")
    return (
        str(payload.get("user_id") if payload.get("user_id") is not None else "").strip(),
        str(payload.get("role") or "").strip().lower(),
        str(payload.get("sid") or payload.get("session_id") or "").strip(),
    )


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

  function __opsSuppressWebViewLiveAudio(){
    try {
      if (typeof dashWs !== 'undefined' && dashWs) {
        dashWs.close();
        dashWs = null;
      }
    } catch (_e) {}
    try {
      if (typeof connectDashboardWebSocket !== 'undefined') connectDashboardWebSocket = function() {};
    } catch (_e) {}
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
    try {
      if (typeof queueLiveFrame !== 'undefined') queueLiveFrame = function() {};
    } catch (_e) {}
  }

  function __opsAbsoluteUrl(value){
    try { return new URL(value, window.location.href).href; } catch (_e) { return ''; }
  }

  function __opsPathIsSso(path){
    path = String(path || '').toLowerCase();
    return path.indexOf('/login/sso') === 0 || path.indexOf('/login/oidc') === 0 || path.indexOf('/login/saml') === 0 || path.indexOf('/desktop/sso') === 0 || path.indexOf('/auth/sso') === 0 || path.indexOf('/sso/') !== -1 || path.slice(-4) === '/sso';
  }

  function __opsShouldUseExternalBrowser(value){
    var href = __opsAbsoluteUrl(value);
    if (!href) return false;
    var u;
    try { u = new URL(href); } catch (_e) { return false; }
    var protocol = u.protocol.toLowerCase();
    if (protocol === 'javascript:' || protocol === 'data:' || protocol === 'file:') return true;
    if (protocol !== 'http:' && protocol !== 'https:') return true;
    if (u.origin !== window.location.origin) return true;
    return __opsPathIsSso(u.pathname || '');
  }

  function __opsApi(){
    return window.pywebview && window.pywebview.api ? window.pywebview.api : null;
  }

  function __opsCallApi(name, args){
    var api = __opsApi();
    if (!api || typeof api[name] !== 'function') return false;
    try {
      var result = api[name].apply(api, args || []);
      if (result && typeof result.catch === 'function') result.catch(function(){});
      return true;
    } catch (_e) {
      return false;
    }
  }

  function __opsStartDesktopSso(){
    if (!__opsCallApi('start_desktop_sso', [])) setTimeout(function(){ __opsCallApi('start_desktop_sso', []); }, 350);
  }

  function __opsOpenExternal(value){
    var href = __opsAbsoluteUrl(value);
    if (!href) return;
    if (!__opsCallApi('open_external_url', [href])) setTimeout(function(){ __opsCallApi('open_external_url', [href]); }, 350);
  }

  function requestLogout(){
    var api = __opsApi();
    if (!api || typeof api.confirm_logout !== 'function') return;
    try {
      var result = api.confirm_logout();
      if (result && typeof result.then === 'function') {
        result.then(function(ok){
          if (ok === true) window.location.href = '/logout';
        }).catch(function(){});
      }
    } catch (_e) {}
  }

  function __opsClosest(node, selector){
    try {
      if (node && node.closest) return node.closest(selector);
    } catch (_e) {}
    return null;
  }

  window.startSsoLogin = function(){
    __opsStartDesktopSso();
  };

  if (!window.__opsClientDelegatedEvents) {
    window.__opsClientDelegatedEvents = true;
    document.addEventListener('click', function(ev){
      var logoutButton = __opsClosest(ev.target, '.logout-btn, .logout-btn-mobile, a.logout, a[href="/logout"]');
      if (logoutButton) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        requestLogout();
        return;
      }
      var settingsButton = __opsClosest(ev.target, '.desktop-app-settings-btn');
      if (settingsButton) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        if (!__opsCallApi('open_app_settings', [])) window.location.href = '/desktop/app-settings';
        return;
      }
      var ssoButton = __opsClosest(ev.target, '#sso-login-button');
      if (ssoButton) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        __opsStartDesktopSso();
        return;
      }
      var link = __opsClosest(ev.target, 'a[href]');
      if (!link) return;
      var href = link.getAttribute('href') || '';
      if (!href || href.charAt(0) === '#') return;
      var absolute = __opsAbsoluteUrl(href);
      var url;
      try { url = new URL(absolute); } catch (_e) { url = null; }
      if (url && url.origin === window.location.origin && __opsPathIsSso(url.pathname || '')) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        __opsStartDesktopSso();
        return;
      }
      if (__opsShouldUseExternalBrowser(href)) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        __opsOpenExternal(href);
      }
    }, true);

    document.addEventListener('submit', function(ev){
      var form = ev.target;
      if (!form || !form.getAttribute) return;
      var action = form.getAttribute('action') || window.location.href;
      var absolute = __opsAbsoluteUrl(action);
      var url;
      try { url = new URL(absolute); } catch (_e) { url = null; }
      if (url && url.origin === window.location.origin && __opsPathIsSso(url.pathname || '')) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        __opsStartDesktopSso();
        return;
      }
      if (__opsShouldUseExternalBrowser(action)) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        __opsOpenExternal(action);
      }
    }, true);
  }

  var __opsNativeWindowOpen = window.open;
  window.open = function(url){
    if (url && __opsShouldUseExternalBrowser(url)) {
      var absolute = __opsAbsoluteUrl(url);
      try {
        var parsed = new URL(absolute);
        if (parsed.origin === window.location.origin && __opsPathIsSso(parsed.pathname || '')) {
          __opsStartDesktopSso();
          return null;
        }
      } catch (_e) {}
      __opsOpenExternal(url);
      return null;
    }
    return __opsNativeWindowOpen.apply(window, arguments);
  };

  __opsSuppressWebViewLiveAudio();
  if (!window.__opsLiveAudioSuppressTimer) window.__opsLiveAudioSuppressTimer = setInterval(__opsSuppressWebViewLiveAudio, 1500);
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


# All Tk dialogs run on this single, long-lived thread. Creating tk.Tk() roots on
# several different threads (the startup dialog on the main thread, later dialogs
# on assorted worker threads) is what triggered the fatal
# "Tcl_AsyncDelete: async handler deleted by the wrong thread" abort, which then
# surfaced downstream as bogus "not enough free memory for image buffer" errors.
# Funnelling every dialog through one thread makes all Tcl interpreters be created
# and destroyed on the same thread, which is safe.
_tk_dispatch_queue = queue.Queue()
_tk_dispatch_thread = None
_tk_dispatch_lock = threading.Lock()
_tk_dead_roots = []

def _set_thread_dpi_unaware():
    """Force the calling thread's DPI awareness to UNAWARE so every window created
    on it is DPI-virtualized (bitmap-scaled) by Windows instead of receiving
    WM_DPICHANGED. This is applied once to the shared Tk dialog thread so the small
    dialogs (server address, app settings, SSO) stop shrinking/resizing when they
    are dragged across the screen. It is intentionally never restored: this thread
    only ever hosts those dialogs. The main WebView2 window lives on a different
    thread and keeps full Per-Monitor-V2 awareness."""
    if os.name != "nt":
        return
    try:
        user32 = ctypes.windll.user32
        user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
        user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(DPI_AWARENESS_CONTEXT_UNAWARE))
    except Exception:
        pass


def _tk_dispatch_loop():
    _set_thread_dpi_unaware()
    while True:
        fn, result_holder, done = _tk_dispatch_queue.get()
        try:
            result_holder["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller
            result_holder["error"] = exc
        finally:
            if done is not None:
                done.set()


def run_on_tk_thread(fn, block=True):
    """Run a Tk dialog callable on the shared, persistent Tk dialog thread.

    Modal dialogs pass block=True and receive the dialog's return value (the
    calling worker thread simply waits). Non-modal dialogs (the SSO window) pass
    block=False to fire-and-forget. Because every dialog runs here, all Tk/Tcl
    interpreters are created and torn down on one thread - no cross-thread teardown,
    no Tcl_AsyncDelete."""
    global _tk_dispatch_thread
    with _tk_dispatch_lock:
        if _tk_dispatch_thread is None or not _tk_dispatch_thread.is_alive():
            _tk_dispatch_thread = threading.Thread(
                target=_tk_dispatch_loop, daemon=True, name="TkDialogThread"
            )
            _tk_dispatch_thread.start()
    result_holder = {}
    done = threading.Event() if block else None
    _tk_dispatch_queue.put((fn, result_holder, done))
    if not block:
        return None
    done.wait()
    if "error" in result_holder:
        raise result_holder["error"]
    return result_holder.get("value")


def _create_dialog_tk_root():
    """Create a Tk root for a dialog.

    This always runs on the shared Tk dialog thread (see run_on_tk_thread), which
    is permanently marked DPI-unaware (see _set_thread_dpi_unaware) so these small
    windows are bitmap-scaled by Windows and don't shrink when moved. Running every
    dialog on that one thread also keeps Tk stable - every Tcl interpreter is
    created and torn down on the same thread, so the cross-thread "async handler
    deleted by the wrong thread" abort can't happen."""
    return tk.Tk()


def _apply_tk_dpi_geometry(root, base_w, base_h):
    """Center a fixed-size Tk window and scale its geometry to the current
    monitor DPI.

    Tk scales fonts (and other point-based metrics) to the display DPI but leaves
    pixel-based geometry unscaled, so a hard-coded width/height clips the (now
    larger) content at 125%/150% scaling. winfo_fpixels('1i') is the exact
    pixels-per-inch Tk uses for that font scaling, so deriving the geometry scale
    from it makes the window grow in lockstep with its content instead of
    clipping. Returns the scale factor (1.0 at 96 DPI)."""
    scale = 1.0
    try:
        root.update_idletasks()
        ppi = root.winfo_fpixels("1i")
        if ppi and ppi > 0:
            scale = ppi / 96.0
    except Exception:
        scale = 1.0
    if not scale or scale <= 0:
        scale = 1.0
    w = int(round(base_w * scale))
    h = int(round(base_h * scale))
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")
    return scale


def _flash_window(hwnd, count=5):
    """Flash a window's taskbar button and title bar to grab the user's attention.
    With FLASHW_TIMERNOFG the flashing continues until the window is brought to the
    foreground, so the user always notices the SSO prompt even if it opened behind
    another window."""
    if os.name != "nt" or not hwnd:
        return
    try:
        class FLASHWINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint),
                ("hwnd", wintypes.HWND),
                ("dwFlags", ctypes.c_uint),
                ("uCount", ctypes.c_uint),
                ("dwTimeout", ctypes.c_uint),
            ]

        info = FLASHWINFO(
            ctypes.sizeof(FLASHWINFO),
            wintypes.HWND(hwnd),
            FLASHW_ALL | FLASHW_TIMERNOFG,
            int(count),
            0,
        )
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        pass


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
        worker_threads = []

        root = _create_dialog_tk_root()
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
        _apply_tk_dpi_geometry(root, 420, 520)

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
                        f"{origin} does not support a secure connection. Content sent is not encrypted while in transit. Avoid sending private or confidential information if possible until this is resolved. Do you want to continue?",
                        MB_YESNO | MB_ICONWARNING,
                    ) == IDYES

                def confirm_cert(host):
                    accepted = native_message_box(
                        self.app.product_name,
                        f"The security certificate presented by {host} is not trusted. Content sent is not encrypted while in transit. It's not recommended to continue and you should contact your system administrator to resolve this issue as soon as possible. Do you want to continue anyway?",
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

            worker_thread = threading.Thread(target=worker, daemon=True)
            worker_threads.append(worker_thread)
            worker_thread.start()

        login_button = tk.Button(
            root, text="CONNECT", command=do_login, font=button_font,
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
            # Join any in-flight connect worker before tearing down the Tk objects.
            for worker_thread in worker_threads:
                try:
                    worker_thread.join()
                except Exception:
                    pass
            try:
                logo_label.configure(image="")
                logo_label.image = None
            except Exception:
                pass
            try:
                root.destroy()
            except Exception:
                pass
            _tk_dead_roots.append(root)
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
        subtle = "#9E9E9E" if dark else "#666666"
        accent = "#1976D2"
        red = "#C62828"
        closed = False
        self.action = None

        root = _create_dialog_tk_root()
        root.title("App Settings")
        root.configure(bg=bg)
        root.geometry("380x580")
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
        _apply_tk_dpi_geometry(root, 380, 580)

        def close():
            nonlocal closed
            if closed:
                return
            closed = True
            try:
                root.quit()
            except Exception:
                pass

        tk.Label(root, text="App Settings", bg=bg, fg=fg, font=tkfont.Font(family="Segoe UI", size=13, weight="bold")).pack(pady=(22, 12))

        info_font = tkfont.Font(family="Segoe UI", size=9)
        tk.Label(
            root,
            text="Open Paging Server Desktop Client 0.1.0",
            bg=bg, fg=fg, font=tkfont.Font(family="Segoe UI", size=9, weight="bold"),
            wraplength=340, justify="center",
        ).pack(padx=20, pady=(0, 8))
        tk.Label(
            root,
            text="Open Paging Server is licensed under the GNU General Public License v2.0. Third-party components, modules, and software used by Open Paging Server are subject to their own licenses.",
            bg=bg, fg=subtle, font=info_font, wraplength=340, justify="center",
        ).pack(padx=20, pady=(0, 8))
        tk.Label(
            root,
            text="Open Paging Server is provided \"as is\" without any warranties, express or implied, including but not limited to fitness for a particular purpose or non-infringement.",
            bg=bg, fg=subtle, font=info_font, wraplength=340, justify="center",
        ).pack(padx=20, pady=(0, 16))

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
                # Defer the actual disconnect/server-dialog until run() has
                # returned and open_app_settings() has released tk_lock. Doing it
                # here would spawn show_server_dialog() while this window still
                # holds tk_lock, so its non-blocking acquire fails and the server
                # address page never appears (app appears hung until restart).
                self.action = "disconnect"
                close()

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
        try:
            root.mainloop()
        finally:
            try:
                root.destroy()
            except Exception:
                pass
            _tk_dead_roots.append(root)
        return self.action


class DesktopSsoWindow:
    def __init__(self, app, browser_url):
        self.app = app
        self.browser_url = str(browser_url or "")
        self.thread = None
        self._started = False
        self.root = None
        self.status_label = None
        self.ui_queue = queue.Queue()
        self.closed = threading.Event()
        self.cancelled = threading.Event()

    def start(self):
        if self._started:
            return
        self._started = True
        # Run on the shared Tk dialog thread (non-blocking) so this window shares
        # the single Tcl interpreter thread with every other dialog.
        run_on_tk_thread(self.run, block=False)

    def enqueue(self, callback):
        try:
            self.ui_queue.put(callback)
        except Exception:
            pass

    def bring_to_front(self):
        def worker():
            root = self.root
            if root is None:
                return
            try:
                root.deiconify()
                root.lift()
                # Keep the prompt persistently on top (do not drop -topmost) so it
                # can't be lost behind the browser window opened for SSO.
                root.attributes("-topmost", True)
                root.focus_force()
            except Exception:
                pass
            try:
                hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            except Exception:
                hwnd = 0
            if hwnd:
                _flash_window(hwnd)
        self.enqueue(worker)

    def set_status(self, text, error=False):
        def worker():
            if self.status_label is None:
                return
            dark = system_uses_dark_mode()
            color = "#EF9A9A" if error and dark else "#C62828" if error else "#BBBBBB" if dark else "#555555"
            try:
                self.status_label.configure(text=str(text or ""), fg=color)
            except Exception:
                pass
        self.enqueue(worker)

    def close(self):
        def worker():
            if self.closed.is_set():
                return
            self.closed.set()
            root = self.root
            if root is None:
                return
            try:
                root.quit()
            except Exception:
                pass
        self.enqueue(worker)

    def cancel(self):
        self.cancelled.set()
        self.close()

    def run(self):
        if not self.app.tk_lock.acquire(blocking=False):
            return
        self.app.set_main_window_enabled(False)
        try:
            dark = system_uses_dark_mode()
            bg = "#1F1F1F" if dark else "#FFFFFF"
            fg = "#EEEEEE" if dark else "#1A1A1A"
            subtle = "#BBBBBB" if dark else "#555555"
            accent = "#1976D2"
            root = _create_dialog_tk_root()
            self.root = root
            root.title(self.app.product_name)
            root.configure(bg=bg)
            root.geometry("440x330")
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
            _apply_tk_dpi_geometry(root, 440, 330)
            try:
                sso_hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            except Exception:
                sso_hwnd = 0
            try:
                root.attributes("-topmost", True)
                root.lift()
                root.focus_force()
            except Exception:
                pass
            if sso_hwnd:
                _flash_window(sso_hwnd)
            title_font = tkfont.Font(family="Segoe UI", size=15, weight="bold")
            body_font = tkfont.Font(family="Segoe UI", size=10)
            icon_font = tkfont.Font(family="Segoe UI Symbol", size=36, weight="bold")
            button_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")
            tk.Label(root, text="↗", bg=bg, fg=accent, font=icon_font).pack(pady=(28, 8))
            tk.Label(root, text="Continue login in your browser", bg=bg, fg=fg, font=title_font).pack(pady=(0, 32))
            
            button_row = tk.Frame(root, bg=bg)
            button_row.pack(pady=(0, 22))
            tk.Button(
                button_row,
                text="CANCEL",
                command=self.cancel,
                bg=bg,
                fg=fg,
                activebackground=bg,
                activeforeground=fg,
                relief="groove",
                cursor="hand2",
                padx=16,
                pady=7,
                borderwidth=1,
                font=button_font,
            ).pack(side="left")

            def drain_queue():
                while True:
                    try:
                        callback = self.ui_queue.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        callback()
                    except Exception:
                        pass
                if not self.closed.is_set():
                    try:
                        root.after(50, drain_queue)
                    except Exception:
                        pass

            root.after(50, drain_queue)
            root.protocol("WM_DELETE_WINDOW", self.cancel)
            try:
                root.mainloop()
            finally:
                self.closed.set()
                try:
                    root.destroy()
                except Exception:
                    pass
                _tk_dead_roots.append(root)
                self.root = None
                self.status_label = None
        finally:
            self.app.set_main_window_enabled(True)
            self.app.tk_lock.release()

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
        self.sso_provider = str(self.config.get("sso_provider") or "")
        self.desktop_sso_start_path = str(self.config.get("desktop_sso_start_path") or "/desktop/sso/start")
        self.desktop_sso_poll_path = str(self.config.get("desktop_sso_poll_path") or "/desktop/sso/poll")
        self.ws = None
        self.ws_thread = None
        self.tray = None
        self.main_window = None
        self.gui_thread_id = None
        self.popups = {}
        self.connected = False
        self.startup_check_done = False
        self.disconnect_since = None
        self.offline_notified = False
        self.pending_welcome = False
        self.launched_at_startup = False
        self.start_minimized = False
        self._show_event_handle = None
        self.error_page_active = False
        self.error_retry_target = ""
        self.error_retry_stop = threading.Event()
        self.error_lock = threading.Lock()
        self.reconnect_stop = threading.Event()
        self.seen_broadcasts = set()
        self.tk_lock = threading.Lock()
        self.toasts = None
        self.receive_flash_until = 0.0
        self.auth_notified = False
        self.cert_prompt_shown = False
        self.current_url = ""
        self.popup_close_confirming = threading.Event()
        self.tray_refresh_stop = threading.Event()
        self.tray_lock = threading.Lock()
        self.sso_lock = threading.Lock()
        self.web_session_sync_lock = threading.Lock()
        self.sso_active = False
        self.sso_prompt = None
        INSECURE_HOSTS.update(str(host) for host in (self.config.get("insecure_hosts") or []))
        self.audio = AudioPlayer(on_state_change=self._on_audio_state_change)
        if self.config.get("clear_webview_storage"):
            self.delete_webview_storage()
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

    def set_main_window_enabled(self, enabled):
        if os.name != "nt":
            return False
        hwnd = self.main_window_hwnd()
        if not hwnd:
            return False
        try:
            ctypes.windll.user32.EnableWindow(hwnd, bool(enabled))
            if enabled:
                try:
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
                except Exception:
                    pass
            return True
        except Exception:
            return False

    def _window_invoke(self, callback, window=None):
        target = window or self.main_window
        if callback is None or target is None:
            return None
        if getattr(target, "native", None) is None:
            return None
        if self.gui_thread_id is not None and threading.get_ident() == self.gui_thread_id:
            return callback(target)
        try:
            return callback(target)
        except Exception:
            return None

    def _window_eval_js(self, script, window=None, timeout=15):
        # evaluate_js can block indefinitely (e.g. if the page navigates away
        # mid-call), so run it on a worker thread and give up after a timeout
        # instead of hanging the caller.
        target = window or self.main_window
        if target is None or getattr(target, "native", None) is None:
            return None
        result = {}
        done = threading.Event()

        def run():
            try:
                result["value"] = target.evaluate_js(script)
            except Exception:
                result["value"] = None
            finally:
                done.set()

        threading.Thread(target=run, daemon=True).start()
        if not done.wait(timeout):
            return None
        return result.get("value")

    def _window_load_url(self, url, window=None):
        self._window_invoke(lambda win: win.load_url(url), window=window)

    def _window_get_current_url(self, window=None):
        # window.get_current_url() waits (up to 20s) for pywebview's "loaded"
        # event, which freezes callers - notably the UI thread during
        # before_load. Read the renderer's cached URL directly instead.
        target = window or self.main_window
        if target is None:
            return ""
        try:
            browser = getattr(getattr(target, "native", None), "browser", None)
            url = getattr(browser, "url", None)
            if url is not None:
                return str(url)
        except Exception:
            pass
        return str(self.current_url or "")

    def _window_show_restore(self, window=None):
        def action(win):
            win.show()
            win.restore()
        self._window_invoke(action, window=window)

    def _window_hide(self, window=None):
        self._window_invoke(lambda win: win.hide(), window=window)

    def _window_destroy(self, window=None):
        self._window_invoke(lambda win: win.destroy(), window=window)

    def _window_set_title(self, title, window=None):
        self._window_invoke(lambda win: win.set_title(title), window=window)

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
        window = self.main_window
        if window is None:
            return
        if not self.current_url or "dashboard" not in self.current_url:
            return
        bid = str(self.audio.active_broadcast_id or "")
        js_playing = "true" if playing else "false"
        try:
            self._window_eval_js(
                f"if(typeof window.__opsUpdateAudioState==='function'){{window.__opsUpdateAudioState({json.dumps(bid)},{js_playing});}}"
            )
        except Exception:
            pass

    def _force_popup_focus(self, windows, monitor_bounds):
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
                    try:
                        for pop_id, wins in list(self.popups.items()):
                            self.popups.pop(pop_id, None)
                            for w in wins:
                                try:
                                    self._window_destroy(window=w)
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
                if answer == IDYES:
                    # Run the logout (which navigates the webview) after this
                    # JS-API call returns. Navigating synchronously here would
                    # destroy pywebview's pending return-value callback for this
                    # call and raise a JavascriptException on the resolver thread.
                    threading.Thread(target=lambda: app.logout(rebuild_guest=True), daemon=True).start()
                return False

            def request_close_popup(self, popup_id):
                threading.Thread(target=app.confirm_close_emergency, args=(str(popup_id),), daemon=True).start()
                return True

            def dashboard_toggle_audio(self, broadcast_id):
                bid = str(broadcast_id or "").strip()
                before = app.audio.dashboard_audio_state(bid)
                playing = app.audio.toggle_dashboard_audio(bid)
                if not playing and not bool(before.get("playing")) and bid and app.origin:
                    try:
                        path = http_download(app.origin, "/desktop/broadcasts/" + urllib.parse.quote(bid) + "/audio", app.token, default_suffix=".wav")
                        playing = app.audio.play_file(path)
                    except Exception:
                        playing = False
                return {"ok": True, "playing": bool(playing)}

            def dashboard_audio_state(self, broadcast_id):
                return app.audio.dashboard_audio_state(str(broadcast_id or "").strip())

            def open_external_url(self, url):
                return app.handle_external_url_request(str(url or ""))

            def start_desktop_sso(self):
                return app.start_desktop_sso_flow()

            def retry_webview(self):
                threading.Thread(target=app.retry_webview, daemon=True).start()
                return True

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
                self._window_set_title(cleaned)
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
        tray = self.tray
        if tray is None:
            return
        with self.tray_lock:
            try:
                tray.icon = self.tray_icon_image().copy()
            except Exception:
                pass
            try:
                tray.title = self.tray_tooltip()
            except Exception:
                pass
            try:
                tray.update_menu()
            except Exception:
                pass

    def tray_refresh_loop(self):
        while not self.tray_refresh_stop.is_set():
            delay = 0.75 if time.time() < self.receive_flash_until else 2.0
            if self.tray_refresh_stop.wait(delay):
                break
            self.refresh_tray()

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
        self.tray_refresh_stop.clear()
        self.tray = pystray.Icon("OpenPagingServerClient", self.tray_icon_image().copy(), self.tray_tooltip(), menu)
        threading.Thread(target=self.tray.run, daemon=True).start()
        threading.Thread(target=self.tray_refresh_loop, daemon=True).start()
        self.toasts = ToastCenter(self)

    def set_status(self, connected):
        connected = bool(connected)
        was_connected = self.connected
        self.connected = connected
        if connected:
            self.auth_notified = False
            self.disconnect_since = None
            if self.offline_notified:
                self.offline_notified = False
                self.notify(
                    f"Reconnected to {self.product_name}",
                    "You will now be able to receive pages and emergency notifications.",
                )
        else:
            if self.disconnect_since is None:
                self.disconnect_since = time.time()
            if not self.offline_notified and (time.time() - self.disconnect_since) >= 30:
                self.offline_notified = True
                self.notify(
                    f"Unable to connect to {self.product_name}",
                    "You won't be able to receive pages and emergency notifications. "
                    "We'll retry the connection in the background.",
                )
        self.refresh_tray()

        def delayed_refresh():
            time.sleep(0.35)
            self.refresh_tray()
            time.sleep(1.25)
            self.refresh_tray()

        threading.Thread(target=delayed_refresh, daemon=True).start()
        if connected and not was_connected:
            self.maybe_show_welcome_toast()

    def maybe_show_welcome_toast(self):
        if not self.pending_welcome:
            return
        self.pending_welcome = False
        self.notify(
            f"Connected to {self.product_name}",
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
            raw = "/"
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        if not raw.startswith("/"):
            raw = "/" + raw
        if "desktop_client=" in raw:
            return raw
        return raw + ("&" if "?" in raw else "?") + "desktop_client=1"

    def _url_origin_parts(self, value):
        parsed = urllib.parse.urlparse(str(value or ""))
        scheme = str(parsed.scheme or "").lower()
        host = str(parsed.hostname or "").lower()
        if not scheme or not host:
            return None
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        return scheme, host, port

    def is_server_url(self, url):
        if not self.origin:
            return False
        return self._url_origin_parts(url) == self._url_origin_parts(self.origin)

    def is_allowed_webview_url(self, url):
        raw = str(url or "").strip()
        if not raw or raw == "about:blank":
            return True
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            return False
        return self.is_server_url(raw)

    def is_sso_url(self, url):
        raw = str(url or "").strip().lower()
        if not raw:
            return False
        try:
            parsed = urllib.parse.urlparse(raw)
        except Exception:
            return False
        path = (parsed.path or "").lower()
        prefixes = ("/login/sso", "/login/oidc", "/login/saml", "/desktop/sso", "/auth/sso")
        return path.startswith(prefixes) or "/sso/" in path or path.endswith("/sso")

    def open_in_default_browser(self, url):
        raw = str(url or "").strip()
        if not raw:
            return False
        try:
            parsed = urllib.parse.urlparse(raw)
        except Exception:
            return False
        if parsed.scheme.lower() not in EXTERNAL_BROWSER_SCHEMES:
            return False
        try:
            webbrowser.open(raw)
            return True
        except Exception:
            return False

    def safe_main_url(self):
        if not self.origin:
            return "about:blank"
        return self.origin.rstrip("/") + self._desktop_page_path("/")

    def return_to_safe_main_url(self):
        window = self.main_window
        if window is None:
            return
        target = self.safe_main_url()
        try:
            self._window_load_url(target, window=window)
            self.current_url = target
        except Exception:
            pass

    def _deferred_return_to_safe_main_url(self, delay=0.05):
        # Navigating the webview synchronously from inside a pywebview JS-API
        # method (e.g. open_external_url) destroys the pending return-value
        # callback for that call and raises a JavascriptException
        # ("_returnValuesCallbacks.<method> is not a function"). Deferring the
        # navigation to a worker thread lets the JS-API call resolve first.
        def run():
            if delay:
                time.sleep(delay)
            self.return_to_safe_main_url()
        threading.Thread(target=run, daemon=True).start()

    def handle_external_url_request(self, url):
        raw = str(url or "").strip()
        if not raw:
            return False
        if self.is_server_url(raw) and self.is_sso_url(raw):
            self.start_desktop_sso_flow()
            self._deferred_return_to_safe_main_url()
            return True
        if self.is_allowed_webview_url(raw) and not self.is_sso_url(raw):
            return False
        opened = self.open_in_default_browser(raw)
        self._deferred_return_to_safe_main_url()
        return bool(opened)

    def start_desktop_sso_flow(self):
        if not self.origin:
            return False
        with self.sso_lock:
            if self.sso_active:
                prompt = self.sso_prompt
                if prompt is not None:
                    prompt.bring_to_front()
                return True
            old_prompt = self.sso_prompt
            self.sso_prompt = None
            self.sso_active = True
        if old_prompt is not None:
            old_prompt.close()

        def worker():
            prompt = None
            try:
                start_path = self.desktop_sso_start_path or "/desktop/sso/start"
                started, _url = http_json(self.origin, start_path, method="POST", timeout=10)
                browser_url = str(started.get("browser_url") or "").strip()
                request_id = str(started.get("request_id") or "").strip()
                request_secret = str(started.get("request_secret") or "").strip()
                if not browser_url or not request_id or not request_secret:
                    raise RuntimeError("The server did not return a valid desktop SSO request.")
                prompt = DesktopSsoWindow(self, browser_url)
                with self.sso_lock:
                    self.sso_prompt = prompt
                prompt.start()
                self.open_in_default_browser(browser_url)
                self.poll_desktop_sso(started, prompt)
            except Exception as exc:
                message = "Could not start desktop SSO: " + str(exc)
                if prompt is not None:
                    prompt.set_status(message, True)
                else:
                    native_message_box(self.product_name, message, MB_ICONWARNING, owner=self.main_window_hwnd())
            finally:
                with self.sso_lock:
                    self.sso_active = False
                    if self.sso_prompt is prompt and prompt is not None and prompt.closed.is_set():
                        self.sso_prompt = None

        threading.Thread(target=worker, daemon=True).start()
        return True

    def poll_desktop_sso(self, started, prompt=None):
        request_id = str((started or {}).get("request_id") or "").strip()
        request_secret = str((started or {}).get("request_secret") or "").strip()
        poll_path = str((started or {}).get("poll_path") or self.desktop_sso_poll_path or "/desktop/sso/poll").strip()
        try:
            expires_in = int((started or {}).get("expires_in") or 600)
        except Exception:
            expires_in = 600
        deadline = time.time() + max(30, min(expires_in, 1800))
        while time.time() < deadline and not self.reconnect_stop.is_set():
            if prompt is not None and prompt.cancelled.is_set():
                return False
            try:
                session, _url = http_json(
                    self.origin,
                    poll_path,
                    method="POST",
                    body={"request_id": request_id, "request_secret": request_secret},
                    timeout=10,
                )
            except urllib.error.HTTPError as exc:
                if exc.code in (202, 408, 429, 500, 502, 503, 504):
                    time.sleep(2)
                    continue
                message = "Desktop SSO did not complete."
                if prompt is not None:
                    prompt.set_status(message, True)
                return False
            except Exception:
                time.sleep(2)
                continue
            status = str((session or {}).get("status") or "").strip().lower()
            if status == "pending":
                time.sleep(2)
                continue
            token = str((session or {}).get("token") or "")
            if token:
                self.pending_welcome = True
                self.apply_session(session)
                self.start_reconnect_loop()
                if prompt is not None:
                    prompt.close()
                self.show_main_window("/")
                return True
            if status in {"failed", "expired", "consumed"}:
                message = str((session or {}).get("error") or "Desktop SSO did not complete.")
                if prompt is not None:
                    prompt.set_status(message, True)
                return False
            time.sleep(2)
        if prompt is not None:
            prompt.set_status("Desktop SSO timed out. Try logging in again.", True)
        return False

    def show_main_window(self, path=""):
        window = self.main_window
        if window is None:
            return
        try:
            self._window_show_restore(window=window)
        except Exception:
            pass
        if not self.origin:
            return
        page = self._desktop_page_path(path)
        target = page if page.startswith("http://") or page.startswith("https://") else self.origin.rstrip("/") + page
        if not self.is_allowed_webview_url(target):
            self.open_in_default_browser(target)
            target = self.safe_main_url()
        if path or not self.is_server_url(self.current_url) or self.error_page_active:
            self.load_server_url(target, window=window)

    def _has_internet(self):
        for host in (("1.1.1.1", 53), ("8.8.8.8", 53), ("208.67.222.222", 53)):
            try:
                sock = socket.create_connection(host, timeout=3)
                sock.close()
                return True
            except Exception:
                continue
        return False

    def _probe_origin(self, timeout=6):
        """Return "" when the server is reachable, else a webview error type."""
        origin = str(self.origin or "").strip()
        if not origin:
            return "unable"
        url = origin.rstrip("/") + "/"
        try:
            request = urllib.request.Request(url, method="GET")
            request.add_header(DESKTOP_CLIENT_HEADER, "1")
            with urllib.request.urlopen(request, timeout=timeout, context=request_ssl_context(url)):
                return ""
        except urllib.error.HTTPError:
            # The server responded (even with an error status): it is reachable.
            return ""
        except (socket.timeout, TimeoutError):
            return "timeout"
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ConnectionRefusedError):
                return "refused"
            if isinstance(reason, (socket.timeout, TimeoutError)):
                return "timeout"
            if isinstance(reason, ssl.SSLError):
                return "unable"
            if not self._has_internet():
                return "no_internet"
            if isinstance(reason, ConnectionResetError):
                return "refused"
            return "unable"
        except ConnectionRefusedError:
            return "refused"
        except Exception:
            if not self._has_internet():
                return "no_internet"
            return "unable"

    def _webview_error_html(self, error_type):
        catalog = {
            "refused": ("Connection refused", "Please ensure the server address is up-to-date and try again.", "network"),
            "timeout": ("Connection timeout", "Please check your network connection and try again.", "network"),
            "no_internet": ("No internet connection", "Please check your network connection and try again.", "network"),
            "unable": ("Unable to load page", "Please contact your system administrator if this issue persists.", "warning"),
            "failed": ("Failed to load page", "Please contact your system administrator if this issue persists.", "warning"),
            "fatal": ("Fatal page error", "Please contact your system administrator if this issue persists.", "warning"),
        }
        title, submessage, icon_kind = catalog.get(error_type, catalog["failed"])
        dark = system_uses_dark_mode()
        bg = "#1B1B1B" if dark else "#F5F6F8"
        card_bg = "#262626" if dark else "#FFFFFF"
        fg = "#F1F1F1" if dark else "#1A1A1A"
        subtle = "#B0B0B0" if dark else "#5F6368"
        accent = "#1976D2"
        border = "#3A3A3A" if dark else "#E0E0E0"
        icon_color = "#E53935"
        if icon_kind == "network":
            icon_svg = (
                f'<svg viewBox="0 0 24 24" width="72" height="72" fill="none" stroke="{icon_color}" '
                'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
                '<path d="M1 1l22 22"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/>'
                '<path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/>'
                '<path d="M10.71 5.05A16 16 0 0 1 22.58 9"/>'
                '<path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"/>'
                '<path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>'
            )
        else:
            icon_svg = (
                f'<svg viewBox="0 0 24 24" width="72" height="72" fill="none" stroke="{icon_color}" '
                'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
                '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="13"/>'
                '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
            )
        product = html_escape(self.product_name)
        title_h = html_escape(title)
        sub_h = html_escape(submessage)
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * {{ box-sizing: border-box; }}
  html, body {{ height: 100%; margin: 0; }}
  body {{ background: {bg}; color: {fg}; font-family: "Segoe UI", system-ui, sans-serif;
          display: flex; align-items: center; justify-content: center; }}
  .card {{ background: {card_bg}; border: 1px solid {border}; border-radius: 14px; padding: 40px 44px;
           max-width: 460px; width: calc(100% - 48px); text-align: center;
           box-shadow: 0 10px 40px rgba(0,0,0,0.18); }}
  .icon {{ margin-bottom: 18px; }}
  h1 {{ font-size: 22px; margin: 0 0 10px; font-weight: 600; }}
  p.sub {{ color: {subtle}; font-size: 14px; margin: 0 0 8px; line-height: 1.5; }}
  p.retry {{ color: {subtle}; font-size: 12.5px; margin: 18px 0 22px; }}
  .actions {{ display: flex; gap: 12px; justify-content: center; }}
  button {{ font-family: inherit; font-size: 14px; font-weight: 600; border: none; border-radius: 8px;
            padding: 11px 22px; cursor: pointer; }}
  .primary {{ background: {accent}; color: #fff; }}
  .primary:hover {{ background: #1565C0; }}
  .secondary {{ background: transparent; color: {fg}; border: 1px solid {border}; }}
  .secondary:hover {{ border-color: {accent}; color: {accent}; }}
</style></head>
<body>
  <div class="card">
    <div class="icon">{icon_svg}</div>
    <h1>{title_h}</h1>
    <p class="sub">We couldn't reach {product}.</p>
    <p class="sub">{sub_h}</p>
    <p class="retry" id="retry-status">Retrying automatically in <span id="count">10</span>s&hellip;</p>
    <div class="actions">
      <button class="primary" onclick="doRetry()">Retry</button>
      <button class="secondary" onclick="openSettings()">App Settings</button>
    </div>
  </div>
  <script>
    var remaining = 10;
    var timer = setInterval(function() {{
      remaining -= 1;
      if (remaining < 0) remaining = 10;
      var el = document.getElementById('count');
      if (el) el.textContent = remaining;
    }}, 1000);
    function api() {{ return (window.pywebview && window.pywebview.api) ? window.pywebview.api : null; }}
    function doRetry() {{
      var status = document.getElementById('retry-status');
      if (status) status.textContent = 'Retrying\u2026';
      var a = api();
      if (a && a.retry_webview) a.retry_webview();
    }}
    function openSettings() {{
      var a = api();
      if (a && a.open_app_settings) a.open_app_settings();
    }}
  </script>
</body></html>"""

    def _clear_error_page(self):
        with self.error_lock:
            self.error_page_active = False
            self.error_retry_stop.set()

    def load_server_url(self, target, window=None):
        window = window or self.main_window
        if window is None:
            return
        # Fast path: a healthy realtime connection means the server is reachable.
        if self.connected:
            self._clear_error_page()
            try:
                self._window_load_url(target, window=window)
                self.current_url = target
            except Exception:
                pass
            return
        error_type = self._probe_origin()
        if error_type:
            self.show_webview_error(error_type, target)
            return
        self._clear_error_page()
        try:
            self._window_load_url(target, window=window)
            self.current_url = target
        except Exception:
            pass

    def show_webview_error(self, error_type, target):
        window = self.main_window
        if window is None:
            return
        with self.error_lock:
            self.error_retry_target = target
            self.error_page_active = True
            self.error_retry_stop.set()
            self.error_retry_stop = threading.Event()
            stop = self.error_retry_stop
        try:
            html = self._webview_error_html(error_type)
            self._window_invoke(lambda win: win.load_html(html), window=window)
            self.current_url = ""
        except Exception:
            pass

        def retry_loop():
            while not stop.is_set() and not self.reconnect_stop.is_set():
                if stop.wait(10):
                    return
                if stop.is_set() or self.reconnect_stop.is_set():
                    return
                err = self._probe_origin()
                if not err:
                    self._recover_from_error(target)
                    return

        threading.Thread(target=retry_loop, daemon=True).start()

    def _recover_from_error(self, target):
        with self.error_lock:
            if not self.error_page_active:
                return
            self.error_page_active = False
            self.error_retry_stop.set()
        try:
            self._window_load_url(target, window=self.main_window)
            self.current_url = target
        except Exception:
            pass

    def retry_webview(self):
        target = self.error_retry_target or self.safe_main_url()
        err = self._probe_origin()
        if not err:
            self._recover_from_error(target)
        else:
            self.show_webview_error(err, target)

    def hide_main_window(self):
        self._clear_error_page()
        if self.main_window is not None:
            try:
                self._window_hide(window=self.main_window)
            except Exception:
                pass
            try:
                self._window_load_url("about:blank", window=self.main_window)
                self.current_url = "about:blank"
            except Exception:
                pass

    def quit(self):
        self.reconnect_stop.set()
        self.tray_refresh_stop.set()
        if self.ws is not None:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None
        self.audio.stop()
        if self.main_window is not None:
            try:
                self._window_destroy(window=self.main_window)
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
        self.notify_server_logout()
        self.reconnect_stop.set()
        if self.ws is not None:
            self.ws.close()
            self.ws = None
        self.audio.stop()
        self.clear_webview_storage()
        self.token = ""
        self.refresh_token = ""
        self.role = ""
        self.user_id = None
        self.origin = ""
        self.guest_available = False
        for key in ("server", "server_input", "token", "token_enc", "refresh_token", "refresh_token_enc", "role", "user_id", "product_name", "guest_available", "sso_provider", "desktop_sso_start_path", "desktop_sso_poll_path"):
            self.config.pop(key, None)
        save_config(self.config)
        self.product_name = APP_FALLBACK_NAME
        self.connected = False
        self.auth_notified = False
        self.current_url = ""
        self.tray_refresh_stop.clear()
        self.refresh_tray()
        self.hide_main_window()
        self.reconnect_stop = threading.Event()
        self.ws_thread = None

    def show_server_dialog(self):
        if not self.tk_lock.acquire(blocking=False):
            return
        try:
            result = run_on_tk_thread(lambda: ServerAddressDialog(self).run())
        finally:
            self.tk_lock.release()
        if not result:
            if not self.origin:
                self.quit()
            return
        raw_input_value, info, origin = result
        self.apply_server(raw_input_value, info, origin)

    def apply_server(self, raw_input_value, info, origin):
        self.origin = origin
        self.guest_available = bool(info.get("guest_receiver_enabled"))
        self.sso_provider = str(info.get("sso_provider") or "")
        self.desktop_sso_start_path = str(info.get("desktop_sso_start_path") or "/desktop/sso/start")
        self.desktop_sso_poll_path = str(info.get("desktop_sso_poll_path") or "/desktop/sso/poll")
        self.set_product_name(info.get("product_name"))
        self.config.update({
            "server": origin,
            "server_input": raw_input_value,
            "guest_available": self.guest_available,
            "sso_provider": self.sso_provider,
            "desktop_sso_start_path": self.desktop_sso_start_path,
            "desktop_sso_poll_path": self.desktop_sso_poll_path,
        })
        save_config(self.config)
        self.pending_welcome = True
        if self.guest_available and not self.token:
            try:
                session, _url = http_json(origin, "/desktop/session/guest", method="POST", timeout=3)
                self.apply_session(session)
            except Exception:
                pass
        self.start_reconnect_loop()
        self.show_main_window("/")

    def apply_session(self, session):
        old_identity = desktop_token_identity(self.token)
        new_token = str((session or {}).get("token") or "")
        new_identity = desktop_token_identity(new_token)
        same_live_identity = bool(old_identity[0] and new_identity[0] and old_identity == new_identity)
        self.token = new_token
        self.refresh_token = str((session or {}).get("refresh_token") or self.refresh_token or "")
        user = (session or {}).get("user") or {}
        self.role = str(user.get("role") or "")
        self.user_id = user.get("id")
        self.persist_session_state()
        if self.ws is not None and not same_live_identity:
            self.ws.close()
            self.ws = None
        self.refresh_tray()
        if str(self.role or "").strip().lower() != "guest":
            self.sync_web_session_in_webview()

    def sync_web_session_in_webview(self):
        if not self.web_session_sync_lock.acquire(blocking=False):
            return

        def worker():
            try:
                if str(self.role or "").strip().lower() == "guest" or str(self.user_id or "").strip().lower() == "guest":
                    return
                window = self.main_window
                if window is None or not self.origin:
                    return
                current = self._window_get_current_url(window=window)
                if current:
                    self.current_url = current
                if current == "about:blank":
                    return
                if current and not self.is_server_url(current):
                    return
                current_path = ""
                try:
                    current_path = str(urllib.parse.urlparse(current).path or "").rstrip("/")
                except Exception:
                    current_path = ""
                if current_path == "/login" or current_path.startswith("/login/"):
                    try:
                        self.refresh_desktop_session(timeout=4)
                    except Exception:
                        pass
                token = str(self.token or "").strip()
                if not token:
                    return
                script = (
                    "(function(){"
                    "var t=" + json.dumps(token) + ";"
                    "if(!t)return false;"
                    "try{"
                    "fetch('/desktop/session/web-login?desktop_client=1',{method:'POST',credentials:'include',headers:{'"
                    + DESKTOP_CLIENT_HEADER + "':'1','Authorization':'Bearer '+t}})"
                    ".then(function(r){return !!(r&&r.ok);})"
                    ".then(function(ok){"
                    "if(!ok)return;"
                    "try{"
                    "var path=(window.location&&window.location.pathname?window.location.pathname:'');"
                    "if(path.indexOf('/login')!==-1){"
                    "window.location.href='/?desktop_client=1';"
                    "}"
                    "}catch(_e){}"
                    "})"
                    ".catch(function(){});"
                    "}catch(_e){return false;}"
                    "return true;"
                    "})()"
                )
                try:
                    self._window_eval_js(script, window=window)
                except Exception:
                    pass
            finally:
                self.web_session_sync_lock.release()

        threading.Thread(target=worker, daemon=True).start()

    def persist_session_state(self):
        self.config.update({"role": self.role, "user_id": self.user_id})
        write_secure_config_value(self.config, "token", self.token)
        write_secure_config_value(self.config, "refresh_token", self.refresh_token)
        save_config(self.config)

    def refresh_desktop_session(self, timeout=10):
        if not self.origin or not self.refresh_token:
            return False
        try:
            session, _url = http_json(
                self.origin,
                "/desktop/session/refresh",
                method="POST",
                body={"refresh_token": self.refresh_token},
                timeout=timeout,
            )
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 404):
                self.token = ""
                self.refresh_token = ""
                self.role = ""
                self.user_id = None
                self.persist_session_state()
            return False
        except Exception:
            return False
        token = str((session or {}).get("token") or "")
        if not token:
            return False
        self.apply_session(session)
        return True

    def open_app_settings(self):
        def run():
            if not self.tk_lock.acquire(blocking=False):
                return
            try:
                action = run_on_tk_thread(lambda: AppSettingsWindow(self).run())
            finally:
                self.tk_lock.release()
            if action == "disconnect":
                self.disconnect_from_server()
                self.show_server_dialog()
        threading.Thread(target=run, daemon=True).start()

    def notify_server_logout(self):
        origin = str(self.origin or "").strip()
        token = str(self.token or "").strip()
        refresh_token = str(self.refresh_token or "").strip()
        if not origin or (not token and not refresh_token):
            return
        try:
            http_json(
                origin,
                "/desktop/session/logout",
                method="POST",
                token=token,
                body={"refresh_token": refresh_token},
                timeout=8,
            )
        except Exception:
            pass

    def browser_logout_script(self):
        token = json.dumps(str(self.token or ""))
        refresh_token = json.dumps(str(self.refresh_token or ""))
        header = json.dumps(DESKTOP_CLIENT_HEADER)
        return (
            "(async function(){"
            "try{await fetch('/desktop/session/logout?desktop_client=1',{method:'POST',credentials:'include',headers:{"
            + header + ":'1','Content-Type':'application/json','Authorization':'Bearer '+" + token + "},body:JSON.stringify({refresh_token:" + refresh_token + "})});}catch(_e){}"
            "try{localStorage.clear();}catch(_e){}"
            "try{sessionStorage.clear();}catch(_e){}"
            "try{document.cookie.split(';').forEach(function(c){var n=c.split('=')[0].trim();if(n){document.cookie=n+'=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';document.cookie=n+'=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Lax';}});}catch(_e){}"
            "try{if(window.caches&&caches.keys){var ks=await caches.keys();await Promise.all(ks.map(function(k){return caches.delete(k);}));}}catch(_e){}"
            "try{if(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations){var rs=await navigator.serviceWorker.getRegistrations();await Promise.all(rs.map(function(r){return r.unregister();}));}}catch(_e){}"
            "return true;})()"
        )

    def clear_native_webview_cookies(self):
        window = self.main_window
        if window is None:
            return
        native = getattr(window, "native", None)
        candidates = []
        if native is not None:
            candidates.extend([native])
            for name in ("CoreWebView2", "core_webview", "webview", "WebView", "Browser"):
                try:
                    value = getattr(native, name)
                    if value is not None:
                        candidates.append(value)
                except Exception:
                    pass
        for candidate in candidates:
            for name in ("CookieManager", "cookie_manager"):
                try:
                    manager = getattr(candidate, name)
                except Exception:
                    manager = None
                if manager is None:
                    continue
                for method in ("DeleteAllCookies", "delete_all_cookies", "ClearCookies", "clear_cookies"):
                    try:
                        getattr(manager, method)()
                    except Exception:
                        pass

    def delete_webview_storage(self):
        storage = CONFIG_DIR / "webview"
        deleted = False
        for _attempt in range(6):
            try:
                if storage.exists():
                    shutil.rmtree(storage)
                deleted = True
                break
            except Exception:
                time.sleep(0.2)
        if deleted:
            self.config.pop("clear_webview_storage", None)
            save_config(self.config)
        return deleted

    def clear_webview_storage(self):
        self.config["clear_webview_storage"] = True
        save_config(self.config)
        window = self.main_window
        if window is not None:
            try:
                self._window_eval_js("window._opsTokenValue=null;window._opsTokenValueAt=0;window._opsTokenBusy=false;", window=window)
            except Exception:
                pass
            try:
                self._window_eval_js(self.browser_logout_script(), window=window)
                time.sleep(0.25)
            except Exception:
                pass
            try:
                self._window_load_url("about:blank", window=window)
                self.current_url = "about:blank"
            except Exception:
                pass
        self.clear_native_webview_cookies()
        self.delete_webview_storage()

    def logout(self, rebuild_guest=True):
        self.notify_server_logout()
        self.reconnect_stop.set()
        if self.ws is not None:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None
        self.audio.stop()
        self.clear_webview_storage()
        self.token = ""
        self.refresh_token = ""
        self.role = ""
        self.user_id = None
        self.persist_session_state()
        self.connected = False
        self.auth_notified = False
        self.reconnect_stop = threading.Event()
        self.ws_thread = None
        self.refresh_tray()
        if rebuild_guest and self.guest_available and self.origin:
            try:
                session, _url = http_json(self.origin, "/desktop/session/guest", method="POST")
                self.apply_session(session)
                self.start_reconnect_loop()
                self.show_main_window("/")
                return
            except Exception:
                pass
        self.show_main_window("/")

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
            except Exception:
                self.set_status(False)
                self.startup_check_done = True
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
            "var now=Date.now();"
            "if(window._opsTokenBusy)return window._opsTokenValue||null;"
            "if(window._opsTokenValue&&window._opsTokenValueAt&&now-window._opsTokenValueAt<60000)return window._opsTokenValue;"
            "window._opsTokenBusy=true;"
            "fetch('/desktop/session/token?desktop_client=1',{method:'POST',headers:{'" + DESKTOP_CLIENT_HEADER + "':'1','"
            + CLIENT_OS_HEADER + "':'" + client_os_string() + "'}})"
            ".then(function(r){return r.ok?r.json():null;})"
            ".then(function(d){"
            "var hasToken=!!(d&&d.token);"
            "window._opsTokenValue=hasToken?JSON.stringify(d):null;"
            "window._opsTokenValueAt=hasToken?Date.now():0;"
            "window._opsTokenBusy=false;"
            "})"
            ".catch(function(){window._opsTokenBusy=false;});"
            "return window._opsTokenValue||null;})()"
        )
        while True:
            time.sleep(4)
            window = self.main_window
            if window is None or not self.origin:
                continue
            try:
                cur = self._window_get_current_url(window=window)
                if cur:
                    self.current_url = cur
            except Exception:
                cur = self.current_url
            if not cur or cur == "about:blank" or not self.is_server_url(cur):
                continue
            try:
                raw = self._window_eval_js(script, window=window)
            except Exception:
                continue
            if not raw:
                if self.token and self.current_url and ("/login" in self.current_url):
                    self.sync_web_session_in_webview()
                continue
            try:
                session = json.loads(raw)
            except Exception:
                continue
            current_path = ""
            try:
                current_path = str(urllib.parse.urlparse(self.current_url).path or "").rstrip("/")
            except Exception:
                current_path = ""

            token = str(session.get("token") or "")
            if token and token != self.token:
                old_identity = desktop_token_identity(self.token)
                new_identity = desktop_token_identity(token)
                changed_identity = not (old_identity[0] and new_identity[0] and old_identity == new_identity)
                self.apply_session(session)
                if current_path == "/login" or current_path.startswith("/login/"):
                    self.return_to_safe_main_url()
                if changed_identity:
                    self.pending_welcome = True
                    self.start_reconnect_loop()
                    try:
                        self._window_eval_js("window._opsTokenValue=null;window._opsTokenValueAt=0;", window=window)
                    except Exception:
                        pass
            elif token and (current_path == "/login" or current_path.startswith("/login/")):
                self.return_to_safe_main_url()
            elif not token and self.token and self.current_url and "/login" in self.current_url:
                self.token = ""
                self.refresh_token = ""
                self.role = ""
                self.user_id = None
                self.persist_session_state()
                self.refresh_tray()
                if self.ws:
                    try:
                        self.ws.close()
                    except Exception:
                        pass
                    self.ws = None

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
        priority = str(message.get("priority") or "Normal").strip().lower()
        if priority == "emergency":
            state = self.audio.live_state()
            if str(state.get("broadcast_id") or "") != broadcast_id:
                self.audio.stop()
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

        def create_popups(_win):
            created = []
            for bounds in monitor_bounds:
                popup = webview.create_window(
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
                self.apply_native_icon(popup)
                created.append(popup)
            return created

        try:
            popup_windows = list(self._window_invoke(create_popups) or [])
        except Exception:
            popup_windows = []
        if not popup_windows:
            return
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
                self._window_destroy(window=window)
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
        if self.refresh_desktop_session(timeout=3):
            return
        if self.guest_available:
            try:
                session, _url = http_json(self.origin, "/desktop/session/guest", method="POST", timeout=3)
                self.apply_session(session)
                return
            except Exception:
                pass
        window = self.main_window
        if window is None:
            return
        target = self.origin.rstrip("/") + self._desktop_page_path("/")
        self.load_server_url(target, window=window)

    def on_main_window_closing(self):
        self.hide_main_window()
        return False

    def on_main_window_before_load(self, *args):
        if self.error_page_active:
            return True
        window = self.main_window
        url = ""
        for arg in args:
            if isinstance(arg, str):
                url = arg
            elif hasattr(arg, "get_current_url"):
                window = arg
        if not url and window is not None:
            # Never call window.get_current_url() here: before_load handlers
            # run inline on the UI thread and get_current_url() blocks waiting
            # for the "loaded" event that cannot fire until this handler
            # returns, freezing the app ("Not Responding") for ~20 seconds.
            url = self._window_get_current_url(window=window)
        if url and self.is_server_url(url):
            try:
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.path.rstrip("/") == "/desktop/app-settings":
                    self.open_app_settings()
                    self.return_to_safe_main_url()
                    return False
            except Exception:
                pass
        if url and self.is_server_url(url) and self.is_sso_url(url):
            self.start_desktop_sso_flow()
            self.return_to_safe_main_url()
            return False
        if url and not self.is_allowed_webview_url(url):
            self.open_in_default_browser(url)
            self.return_to_safe_main_url()
            return False
        return True

    def on_main_window_loaded(self):
        if self.error_page_active:
            return
        window = self.main_window
        if window is None:
            return
        if not getattr(self, "_dpi_hook_installed", False):
            try:
                _hook_dpi_changed(self.main_window_hwnd())
            except Exception:
                pass
            self._dpi_hook_installed = True
        try:
            current = self._window_get_current_url(window=window)
        except Exception:
            current = ""
        self.current_url = current
        if current and not self.is_allowed_webview_url(current):
            self.open_in_default_browser(current)
            self.return_to_safe_main_url()
            return
        if self.origin and self.is_server_url(current):
            try:
                self._window_eval_js(INJECT_JS, window=window)
            except Exception:
                pass
            self.sync_web_session_in_webview()

    def start_show_event_listener(self):
        # Waits for a second launch of the app (manual double-click or shortcut)
        # to signal us, then restores/unminimizes the window from the tray.
        if not sys.platform.startswith("win"):
            return
        handle = self._show_event_handle
        if not handle:
            handle = create_show_event()
            self._show_event_handle = handle
        if not handle:
            return

        def worker():
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                kernel32.WaitForSingleObject.restype = wintypes.DWORD
                while not self.reconnect_stop.is_set():
                    result = kernel32.WaitForSingleObject(handle, 500)
                    if result == 0:  # WAIT_OBJECT_0 - another instance asked us to show
                        threading.Thread(target=self.show_main_window, daemon=True).start()
                    elif result not in (258,):  # anything other than WAIT_TIMEOUT means trouble
                        break
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def bootstrap(self):
        self.gui_thread_id = threading.get_ident()
        self.start_tray()
        self.apply_native_icon(self.main_window)
        self.start_show_event_listener()
        threading.Thread(target=self.poll_web_session, daemon=True).start()
        pending = getattr(self, "_pending_server", None)
        if pending:
            del self._pending_server
            threading.Thread(target=self.apply_server, args=pending, daemon=True).start()
            return
        if self.origin:
            self.start_reconnect_loop()
            self.refresh_tray()
            threading.Thread(target=self.restore_session_after_restart, daemon=True).start()
            if not self.start_minimized:
                self.show_main_window("/")


def _enable_high_dpi_awareness():
    """Make the app Per-Monitor-V2 DPI-aware so the WebView2 UI renders crisply at
    Windows display scaling above 100% (e.g. 125%/150%) instead of being
    bitmap-stretched/blurry.

    The bundled Python launches DPI-unaware, so without this the whole window is
    scaled up by the OS as a blurry bitmap. System awareness renders blurry on any
    monitor whose scale differs from the one that was primary at login, so we use
    Per-Monitor V2, which lets WebView2 re-rasterize at the real current monitor
    scale. The trade-off is that top-level windows now receive WM_DPICHANGED when
    dragged between monitors of different scaling; the main window handles that via
    _hook_dpi_changed so it keeps a consistent physical size instead of shrinking."""
    if platform.system() != "Windows":
        return
    try:
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4 (Windows 10 1703+).
        if ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return
    except (AttributeError, OSError):
        pass
    try:
        # PROCESS_PER_MONITOR_DPI_AWARE = 2 (Windows 8.1+).
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


def main():
    _enable_high_dpi_awareness()
    autostart = launched_at_startup()
    is_primary, mutex_handle = _acquire_single_instance()
    if not is_primary:
        # Another instance is already running: ask it to surface its window
        # (item 4 - clicking the exe while running unminimizes from the tray).
        signal_existing_instance()
        return
    _SINGLE_INSTANCE_HANDLES.append(mutex_handle)
    show_event_handle = create_show_event()
    _SINGLE_INSTANCE_HANDLES.append(show_event_handle)
    try:
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        webview.settings["ALLOW_FILE_URLS"] = False
    except Exception:
        pass
    app = ClientApp()
    app.launched_at_startup = autostart
    app._show_event_handle = show_event_handle
    # Start minimized (to tray) only when launched at startup AND already logged in
    # and configured to connect to a server. Otherwise start "loudly" (visible),
    # and manual launches always show the window.
    app.start_minimized = bool(autostart and app.origin and app.token)
    if not app.origin:
        result = run_on_tk_thread(lambda: ServerAddressDialog(app).run())
        if result:
            raw_input_value, info, origin = result
            app._pending_server = (raw_input_value, info, origin)
        else:
            app.quit()
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
    try:
        window.events.before_load += app.on_main_window_before_load
    except Exception:
        pass
    window.events.loaded += app.on_main_window_loaded
    storage = CONFIG_DIR / "webview"
    try:
        storage.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        webview.start(app.bootstrap, private_mode=False, storage_path=str(storage), gui="edgechromium")
    except Exception:
        try:
            webview.start(app.bootstrap, private_mode=False, storage_path=str(storage))
        except Exception:
            pass
    finally:
        app.quit()


if __name__ == "__main__":
    main()