"""Cross-platform dependency bootstrap.

Subverse itself is pure Python (one pip dependency, dnspython). Three
*optional* external tools make it fuller:

  * nmap      — service/version probing (-sV)
  * graphviz  — the static node-graph image (`--graph`)
  * a Chromium-family browser — rasterizing the card map to PNG

This module detects what's missing on macOS / Linux / Windows, prints the exact
install command for the detected package manager, and (with consent) runs it.
Nothing is installed unless the caller asks (`--install-deps`).
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from .platform_utils import IS_MAC, IS_WIN, IS_LINUX, find_browser

# Per-tool package names for each package manager.
# key -> {manager: package}; "browser" casks differ, handled below.
_PKGS = {
    "nmap": {
        "brew": "nmap", "apt": "nmap", "dnf": "nmap", "pacman": "nmap",
        "zypper": "nmap", "winget": "Insecure.Nmap", "choco": "nmap",
    },
    "graphviz": {
        "brew": "graphviz", "apt": "graphviz", "dnf": "graphviz",
        "pacman": "graphviz", "zypper": "graphviz",
        "winget": "Graphviz.Graphviz", "choco": "graphviz",
    },
    "browser": {
        "brew": "--cask google-chrome", "apt": "chromium-browser",
        "dnf": "chromium", "pacman": "chromium", "zypper": "chromium",
        "winget": "Google.Chrome", "choco": "googlechrome",
    },
}


def detect_pkg_manager() -> tuple[str | None, bool]:
    """Return (manager, needs_sudo). manager is None if none found."""
    if IS_MAC:
        return ("brew", False) if shutil.which("brew") else (None, False)
    if IS_WIN:
        if shutil.which("winget"):
            return "winget", False
        if shutil.which("choco"):
            return "choco", False
        return None, False
    # linux: try in rough order of prevalence
    for mgr in ("apt-get", "dnf", "pacman", "zypper", "apt"):
        if shutil.which(mgr):
            name = "apt" if mgr in ("apt", "apt-get") else mgr
            needs_sudo = shutil.which("sudo") is not None
            return name, needs_sudo
    return None, False


def _install_cmd(manager: str, needs_sudo: bool, pkg: str) -> list[str]:
    pre = (["sudo"] if needs_sudo else [])
    if manager == "brew":
        # brew must not run as root; never prepend sudo
        return ["brew", "install"] + pkg.split()
    if manager == "apt":
        return pre + ["apt-get", "install", "-y"] + pkg.split()
    if manager == "dnf":
        return pre + ["dnf", "install", "-y"] + pkg.split()
    if manager == "pacman":
        return pre + ["pacman", "-S", "--noconfirm"] + pkg.split()
    if manager == "zypper":
        return pre + ["zypper", "install", "-y"] + pkg.split()
    if manager == "winget":
        return ["winget", "install", "-e", "--id"] + pkg.split()
    if manager == "choco":
        return ["choco", "install", "-y"] + pkg.split()
    return []


def _have(tool: str) -> bool:
    if tool == "browser":
        return find_browser() is not None
    if tool == "graphviz":
        return shutil.which("dot") is not None
    return shutil.which(tool) is not None


def missing(want_scan=True, want_png=True, want_graph=False) -> list[str]:
    wanted = []
    if want_scan:
        wanted.append("nmap")
    if want_png:
        wanted.append("browser")
    if want_graph:
        wanted.append("graphviz")
    return [t for t in wanted if not _have(t)]


def report(want_scan=True, want_png=True, want_graph=False) -> list[str]:
    """Print status of optional tools; return the list of missing ones."""
    miss = missing(want_scan, want_png, want_graph)
    mgr, needs_sudo = detect_pkg_manager()
    label = {"nmap": "nmap (service probe)",
             "browser": "Chrome/Chromium (card PNG)",
             "graphviz": "graphviz (node-graph image)"}
    wanted = ([("nmap")] if want_scan else []) + \
             (["browser"] if want_png else []) + \
             (["graphviz"] if want_graph else [])
    for tool in wanted:
        mark = "✓" if _have(tool) else "✗"
        print(f"  [{mark}] {label[tool]}")
    if miss:
        print("\n  Missing optional tools:", ", ".join(miss))
        if mgr:
            print(f"  Detected package manager: {mgr}")
            print("  Install with:")
            for tool in miss:
                pkg = _PKGS[tool].get(mgr)
                if pkg:
                    print("    " + " ".join(_install_cmd(mgr, needs_sudo, pkg)))
            print("  ...or re-run with --install-deps to do it automatically.")
        else:
            print("  No supported package manager found — install them manually:")
            for tool in miss:
                print(f"    - {tool}")
    return miss


def install(want_scan=True, want_png=True, want_graph=False) -> bool:
    """Attempt to install missing tools via the detected package manager."""
    miss = missing(want_scan, want_png, want_graph)
    if not miss:
        print("[*] All optional tools already present.")
        return True
    mgr, needs_sudo = detect_pkg_manager()
    if not mgr:
        print("[!] No supported package manager found; please install manually:",
              ", ".join(miss), file=sys.stderr)
        return False
    ok = True
    for tool in miss:
        pkg = _PKGS[tool].get(mgr)
        if not pkg:
            print(f"[!] Don't know how to install {tool} with {mgr}.", file=sys.stderr)
            ok = False
            continue
        cmd = _install_cmd(mgr, needs_sudo, pkg)
        print(f"[*] Installing {tool}: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True)
        except (subprocess.CalledProcessError, OSError) as exc:
            print(f"[!] Failed to install {tool}: {exc}", file=sys.stderr)
            ok = False
    return ok


def ensure_python_deps(auto: bool = True) -> bool:
    """Make sure dnspython is importable; optionally pip-install it if missing."""
    try:
        import dns  # noqa: F401
        return True
    except ImportError:
        if not auto:
            print("[!] Missing Python dependency 'dnspython'. "
                  "Install with: pip install dnspython", file=sys.stderr)
            return False
        print("[*] Installing missing Python dependency: dnspython")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "dnspython"],
                           check=True)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            print(f"[!] Could not install dnspython automatically: {exc}\n"
                  f"    Please run: {sys.executable} -m pip install dnspython",
                  file=sys.stderr)
            return False
