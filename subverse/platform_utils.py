"""Cross-platform helpers: locate a Chromium-family browser, open files, name
package managers. Kept dependency-free so it works the same on macOS, Linux and
Windows.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

IS_MAC = sys.platform == "darwin"
IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


def find_browser() -> str | None:
    """Return a path to a headless-capable Chromium/Chrome/Edge, or None."""
    # 1) explicit override
    env = os.environ.get("SUBVERSE_BROWSER")
    if env and os.path.exists(env):
        return env

    # 2) on PATH (Linux mostly, but works anywhere)
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "chrome", "msedge", "brave-browser"):
        p = shutil.which(name)
        if p:
            return p

    # 3) well-known install locations per OS
    candidates: list[str] = []
    if IS_MAC:
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    elif IS_WIN:
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            rf"{pf}\Google\Chrome\Application\chrome.exe",
            rf"{pfx86}\Google\Chrome\Application\chrome.exe",
            rf"{local}\Google\Chrome\Application\chrome.exe",
            rf"{pf}\Microsoft\Edge\Application\msedge.exe",
            rf"{pfx86}\Microsoft\Edge\Application\msedge.exe",
            rf"{pf}\Chromium\Application\chrome.exe",
        ]
    else:  # linux
        candidates = [
            "/usr/bin/google-chrome", "/usr/bin/chromium",
            "/usr/bin/chromium-browser", "/snap/bin/chromium",
            "/usr/bin/microsoft-edge", "/usr/bin/brave-browser",
        ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def screenshot_html(browser: str, html_path: str, out_png: str,
                    width: int = 1240, height: int = 1400, scale: int = 2,
                    timeout: int = 90) -> bool:
    """Render an HTML file to a PNG via headless Chromium. Returns ok.

    `height` should be the full content height (the caller estimates it) so the
    whole page is captured rather than just the first viewport.
    """
    url = _file_url(html_path)

    def run(mode: str, no_sandbox: bool) -> bool:
        cmd = _screenshot_argv(browser, mode, url, out_png, width, height,
                               scale, no_sandbox=no_sandbox)
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return os.path.exists(out_png) and os.path.getsize(out_png) > 0

    # Keep Chrome's OS sandbox ON: it renders a page built from untrusted scan
    # data. Only when running as root (common in CI/containers), Chrome refuses
    # the sandbox, so fall back to --no-sandbox if the sandboxed attempt yields
    # nothing. new headless captures the exact window size; old is the fallback
    # for older Chrome builds.
    for no_sandbox in (False, True):
        for mode in ("--headless=new", "--headless=old"):
            if run(mode, no_sandbox):
                return True
    return False


def _screenshot_argv(browser: str, mode: str, url: str, out_png: str,
                     width: int, height: int, scale: int,
                     no_sandbox: bool) -> list[str]:
    """Build the headless-Chrome command line for one screenshot attempt.

    --no-sandbox is added only when `no_sandbox` is set, so the OS sandbox
    stays on by default and is dropped solely as a fallback (see caller).
    """
    cmd = [browser, mode, "--disable-gpu", "--hide-scrollbars",
           "--default-background-color=00000000",
           f"--force-device-scale-factor={scale}",
           f"--window-size={width},{height}",
           f"--screenshot={out_png}", url]
    if no_sandbox:
        cmd.insert(3, "--no-sandbox")
    return cmd


def _file_url(path: str) -> str:
    ap = os.path.abspath(path)
    if IS_WIN:
        return "file:///" + ap.replace("\\", "/")
    return "file://" + ap


def open_path(path: str) -> None:
    """Open a file with the OS default application."""
    try:
        if IS_MAC:
            subprocess.run(["open", path], check=False)
        elif IS_WIN:
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", path], check=False)
    except OSError:
        pass
