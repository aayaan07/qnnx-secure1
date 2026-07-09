import winreg
import ctypes
import logging

logger = logging.getLogger("QVPN_SystemProxy")

# WinINet constants
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

def _refresh_system():
    """Trigger a refresh of the Windows system proxy configuration."""
    try:
        # Call InternetSetOptionW(0, 39, None, 0)
        # and InternetSetOptionW(0, 37, None, 0)
        wininet = ctypes.windll.wininet
        
        # INTERNET_OPTION_SETTINGS_CHANGED
        res1 = wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        # INTERNET_OPTION_REFRESH
        res2 = wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, None, 0)
        
        if res1 and res2:
            logger.info("Windows internet settings refreshed successfully.")
        else:
            logger.warning(f"Windows internet settings refresh returned status: settings_changed={res1}, refresh={res2}")
    except Exception as e:
        logger.error(f"Failed to refresh Windows internet settings: {e}", exc_info=True)

def set_system_proxy(proxy_address: str) -> None:
    """
    Write to Windows Registry to enable system proxy.
    Path: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
      - ProxyEnable = 1
      - ProxyServer = proxy_address
    """
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        # Open registry key for writing
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_address)
        logger.info(f"System proxy registry values updated: ProxyEnable=1, ProxyServer={proxy_address}")
        _refresh_system()
    except Exception as e:
        logger.error(f"Failed to enable system proxy in registry: {e}", exc_info=True)

def clear_system_proxy() -> None:
    """
    Write to Windows Registry to disable system proxy and remove the proxy URL.
    Path: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
      - ProxyEnable = 0
      - ProxyServer (deleted)
    """
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(key, "ProxyServer")
            except FileNotFoundError:
                pass  # already absent
        logger.info("System proxy disabled and ProxyServer registry value removed.")
        _refresh_system()
    except Exception as e:
        logger.error(f"Failed to disable system proxy in registry: {e}", exc_info=True)
