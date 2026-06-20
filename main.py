import asyncio
import logging
import subprocess
import sys
from proxy.server import start
from proxy.stats import tracker
from config.settings import LOG_LEVEL, PROXY_HOST, PROXY_PORT

logger = logging.getLogger(__name__)


# ── macOS: networksetup ───────────────────────────────────────────────────────

def _mac_detect_service():
    try:
        out = subprocess.check_output(
            ["networksetup", "-listallnetworkservices"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            name = line.strip()
            if not name or name.startswith("An asterisk") or name.startswith("*"):
                continue
            info = subprocess.check_output(
                ["networksetup", "-getinfo", name],
                text=True, stderr=subprocess.DEVNULL
            )
            has_ipv4 = any(
                l.startswith("IP address:") and "none" not in l
                for l in info.splitlines()
            )
            if has_ipv4:
                return name
    except Exception:
        pass
    return None


def _mac_proxy_was_enabled(service):
    try:
        out = subprocess.check_output(
            ["networksetup", "-getsocksfirewallproxy", service],
            text=True, stderr=subprocess.DEVNULL
        )
        return "Enabled: Yes" in out
    except Exception:
        return False


def _mac_enable_proxy(service):
    subprocess.run(
        ["networksetup", "-setsocksfirewallproxy", service, PROXY_HOST, str(PROXY_PORT)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["networksetup", "-setsocksfirewallproxystate", service, "on"],
        check=True, capture_output=True,
    )


def _mac_disable_proxy(service):
    subprocess.run(
        ["networksetup", "-setsocksfirewallproxystate", service, "off"],
        capture_output=True,
    )


# ── Windows: WinINet registry ─────────────────────────────────────────────────

_WIN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _win_get_state():
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_REG_PATH, 0, winreg.KEY_READ)
        def qv(name, default):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except OSError:
                return default
        state = (int(qv("ProxyEnable", 0)), str(qv("ProxyServer", "")), str(qv("ProxyOverride", "")))
        winreg.CloseKey(key)
        return state
    except Exception:
        return (0, "", "")


def _win_apply_proxy(enabled, server, override):
    import winreg
    import ctypes
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_REG_PATH, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ProxyEnable",   0, winreg.REG_DWORD, enabled)
    winreg.SetValueEx(key, "ProxyServer",   0, winreg.REG_SZ,    server)
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,    override)
    winreg.CloseKey(key)
    # Tell Chrome/Edge to pick up the new settings immediately
    try:
        wininet = ctypes.WinDLL("Wininet.dll")
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


# ── cross-platform orchestration ──────────────────────────────────────────────

def _setup_proxy():
    """Set OS-level SOCKS5 proxy. Returns a context tuple for teardown."""
    if sys.platform == "darwin":
        service = _mac_detect_service()
        if not service:
            logger.warning("No active network service — set SOCKS5 127.0.0.1:%d in browser manually", PROXY_PORT)
            return None
        was_enabled = _mac_proxy_was_enabled(service)
        try:
            _mac_enable_proxy(service)
            logger.info("System SOCKS5 proxy enabled on '%s' → open Chrome or Safari normally", service)
            return ("darwin", service, was_enabled)
        except Exception as e:
            logger.warning("Could not set macOS system proxy (%s) — set manually", e)
            return None

    elif sys.platform == "win32":
        prev = _win_get_state()
        try:
            _win_apply_proxy(1, f"socks={PROXY_HOST}:{PROXY_PORT}", "localhost;127.0.0.1;<local>")
            logger.info("System SOCKS5 proxy enabled on Windows → open Chrome or Edge normally")
            return ("win32", *prev)
        except Exception as e:
            logger.warning("Could not set Windows system proxy (%s) — set manually", e)
            return None

    else:
        logger.warning("Auto proxy not supported on %s — set SOCKS5 127.0.0.1:%d in browser manually", sys.platform, PROXY_PORT)
        return None


def _teardown_proxy(ctx):
    """Restore OS proxy to whatever state it was in before we started."""
    if ctx is None:
        return
    try:
        if ctx[0] == "darwin":
            _, service, was_enabled = ctx
            if not was_enabled:
                _mac_disable_proxy(service)
            logger.info("System proxy restored on '%s'", service)
        elif ctx[0] == "win32":
            _, prev_enabled, prev_server, prev_override = ctx
            _win_apply_proxy(prev_enabled, prev_server, prev_override)
            logger.info("Windows system proxy restored")
    except Exception as e:
        logger.warning("Could not restore system proxy: %s", e)


# ── entry point ───────────────────────────────────────────────────────────────

async def main():
    ctx = _setup_proxy()
    try:
        await start()
    except asyncio.CancelledError:
        pass
    finally:
        tracker.summary()
        _teardown_proxy(ctx)


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=getattr(logging, LOG_LEVEL, logging.INFO),
    )
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
