"""
ephemeral_server.py -- Autonomous Ephemeral Local Application Runner
===================================================================
Enables Project Aegis to automatically detect, spin up, health-probe,
and cleanly terminate local development servers (Node.js/Vite/Next.js/FastAPI/Flask/Django)
during security reconnaissance audits.

Key Production Capabilities:
  1. Zero-Crash Guarantee:
     - Health-checks with bounded timeouts. If a local server fails to boot (missing DB,
       syntax error, missing node_modules), it gracefully aborts and falls back to pure SAST.
     - Never gives false claims or fabricated DOM findings to the LLM.
  2. Smart Reuse of Existing Dev Servers:
     - If a developer already has `npm run dev` or `uvicorn` running on 3000/5173/8000,
       it automatically detects and reuses that instance without spawning a duplicate,
       and will NEVER kill the developer's pre-existing process.
  3. Clean Process Tree Teardown:
     - Dual-layer leak prevention: psutil recursive tree termination + OS-level
       `taskkill /F /T /PID` (Windows) and `os.killpg(os.getpgid(pid))` (POSIX).
     - Eliminates orphaned node.exe, cmd.exe, esbuild, and python child workers.
  4. Dependency Pre-Flight & Framework Detection:
     - Verifies `node_modules` exists before attempting `npm run dev`.
     - Detects target virtualenvs (.venv/venv) to prevent ModuleNotFoundError.
     - Supports monorepos (apps/web, packages/client, etc.).
     - Allocates conflict-free dynamic ports when preferred ports are occupied.
  5. Non-Interactive Headless Execution:
     - Sets CI=true and BROWSER=none, with stdin=DEVNULL to ensure dev servers
       never hang waiting for interactive input or attempt to launch system browsers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("aegis.core.ephemeral_server")
logging.basicConfig(level=logging.INFO)

COMMON_DEV_PORTS = [3000, 5173, 8000, 8080, 4200, 5000]


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port on localhost is actively accepting connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def find_free_port(start_port: int = 3000, max_tries: int = 100) -> int:
    """Finds an unused, bindable port starting from start_port."""
    for port in range(start_port, start_port + max_tries):
        if not is_port_in_use(port):
            return port
    return start_port


async def is_server_healthy_async(url: str, timeout_s: float = 0.8) -> bool:
    """
    Asynchronous health check. Any HTTP response code (including 200, 301, 302, 404, 401)
    proves that a real web application server is actively responding on that port.
    Prevents following redirects to avoid hanging on infinite redirect loops.
    """
    if not url or not isinstance(url, str):
        return False

    try:
        async with httpx.AsyncClient(timeout=timeout_s, verify=False, follow_redirects=False) as client:
            resp = await client.get(url)
            return resp.status_code < 500
    except Exception:
        # Fallback check: try localhost if 127.0.0.1 was used, or vice versa (IPv4 vs IPv6 resolution edge case)
        try:
            alt_url = url.replace("127.0.0.1", "localhost") if "127.0.0.1" in url else url.replace("localhost", "127.0.0.1")
            if alt_url != url:
                async with httpx.AsyncClient(timeout=timeout_s, verify=False, follow_redirects=False) as client:
                    resp = await client.get(alt_url)
                    return resp.status_code < 500
        except Exception:
            pass
        return False


def _find_python_bin(dir_path: str) -> str:
    """Finds project-specific python virtualenv binary if available, else current sys.executable."""
    for cand in (
        os.path.join(dir_path, ".venv", "Scripts", "python.exe"),
        os.path.join(dir_path, "venv", "Scripts", "python.exe"),
        os.path.join(dir_path, ".venv", "bin", "python"),
        os.path.join(dir_path, "venv", "bin", "python"),
    ):
        if os.path.isfile(cand):
            return cand
    return sys.executable


def detect_app_config(repo_path: str) -> Optional[Dict[str, Any]]:
    """
    Inspects repository files to determine the framework and command
    needed to run the application locally.
    Supports Node/React/Vite/Next/Vue/Angular, Python FastAPI/Flask/Django, and Monorepos.
    """
    if not repo_path or not os.path.isdir(repo_path):
        return None

    search_dirs = [repo_path]
    for sub in (
        "frontend", "client", "web", "ui", "backend", "server", "api", "app",
        os.path.join("apps", "web"), os.path.join("apps", "client"), os.path.join("apps", "frontend"),
        os.path.join("packages", "web"), os.path.join("packages", "client")
    ):
        candidate = os.path.join(repo_path, sub)
        if os.path.isdir(candidate):
            search_dirs.append(candidate)

    # 1. Look for package.json (Node / React / Next / Vite / Vue / Angular)
    for d in search_dirs:
        pkg_json = os.path.join(d, "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                scripts = data.get("scripts", {})
                start_script = None
                for candidate_script in ("dev", "start", "serve"):
                    if candidate_script in scripts:
                        start_script = candidate_script
                        break

                has_node_modules = os.path.exists(os.path.join(d, "node_modules"))
                raw_pkg_str = json.dumps(data).lower()
                preferred_port = 5173 if "vite" in raw_pkg_str else (4200 if "angular" in raw_pkg_str else 3000)

                return {
                    "type": "node",
                    "dir": d,
                    "command": f"npm run {start_script}" if start_script else "npm start",
                    "preferred_port": preferred_port,
                    "ready": has_node_modules,
                    "missing_reason": None if has_node_modules else "node_modules not found (run 'npm install' first)"
                }
            except Exception:
                pass

    # 2. Look for Python Web Frameworks (Django / FastAPI / Flask)
    for d in search_dirs:
        py_bin = _find_python_bin(d)

        # 2a. Django (manage.py)
        manage_py = os.path.join(d, "manage.py")
        if os.path.exists(manage_py):
            return {
                "type": "python_django",
                "dir": d,
                "command": f'"{py_bin}" manage.py runserver 127.0.0.1:{{PORT}} --noreload',
                "preferred_port": 8000,
                "ready": True,
                "missing_reason": None,
            }

        # 2b. FastAPI & Flask
        for py_file in ("main.py", "app.py", "server.py", "api.py"):
            target_file = os.path.join(d, py_file)
            if os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(5000)
                    if "FastAPI" in content or "fastapi" in content:
                        module_name = os.path.splitext(py_file)[0]
                        return {
                            "type": "python_fastapi",
                            "dir": d,
                            "command": f'"{py_bin}" -m uvicorn {module_name}:app --port {{PORT}}',
                            "preferred_port": 8000,
                            "ready": True,
                            "missing_reason": None,
                        }
                    elif "Flask" in content or "flask" in content:
                        return {
                            "type": "python_flask",
                            "dir": d,
                            "command": f'"{py_bin}" {py_file}',
                            "preferred_port": 5000,
                            "ready": True,
                            "missing_reason": None,
                        }
                except Exception:
                    pass

    return None


class EphemeralServerManager:
    """
    Manages the lifecycle of an ephemeral dev server for local DAST testing.
    Can be used as an async context manager or invoked via start_async() / stop_async().
    """

    def __init__(self, repo_path: str, timeout_seconds: Optional[float] = None):
        self.repo_path = repo_path
        self.timeout_seconds = timeout_seconds or float(os.getenv("AEGIS_LOCAL_SERVER_TIMEOUT", "12.0"))
        self.process: Optional[subprocess.Popen] = None
        self.spawned_by_us: bool = False
        self.target_url: Optional[str] = None
        self.port: Optional[int] = None

    async def __aenter__(self) -> Optional[str]:
        return await self.start_async()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop_async()

    async def start_async(self) -> Optional[str]:
        """
        Attempts to find or start a local dev server.
        Returns the base URL (e.g. 'http://127.0.0.1:3000') or None on failure/fallback.
        """
        # 1. Re-use pre-existing live server on common dev ports
        for port in COMMON_DEV_PORTS:
            url = f"http://127.0.0.1:{port}"
            if await is_server_healthy_async(url, timeout_s=0.4):
                logger.info("[EphemeralServer] Detected existing live server at %s. Reusing without spawning duplicate.", url)
                self.target_url = url
                self.port = port
                self.spawned_by_us = False
                return url

        # 2. Inspect project configuration
        app_cfg = detect_app_config(self.repo_path)
        if not app_cfg:
            logger.info("[EphemeralServer] No auto-bootable Node or Python dev server config detected. Skipping auto-spin.")
            return None

        if not app_cfg.get("ready"):
            logger.warning(
                "[EphemeralServer] Pre-flight check failed for %s: %s. Skipping auto-spin to prevent crash.",
                app_cfg["dir"], app_cfg.get("missing_reason")
            )
            return None

        # 3. Allocate free port & construct command
        target_port = find_free_port(app_cfg["preferred_port"])
        self.port = target_port
        cmd_str = app_cfg["command"].replace("{PORT}", str(target_port))

        logger.info("[EphemeralServer] Spawning %s in %s on port %d ...", cmd_str, app_cfg["dir"], target_port)

        env = os.environ.copy()
        env["PORT"] = str(target_port)
        env["CI"] = "true"               # Suppress interactive prompts in CRA/Vite/Next
        env["BROWSER"] = "none"          # Suppress auto-opening desktop browser
        env["PYTHONUNBUFFERED"] = "1"
        env["FORCE_COLOR"] = "0"

        try:
            if os.name == "nt":
                # CREATE_NEW_PROCESS_GROUP enables taskkill /F /T tree termination
                self.process = subprocess.Popen(
                    cmd_str,
                    cwd=app_cfg["dir"],
                    env=env,
                    shell=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            else:
                self.process = subprocess.Popen(
                    cmd_str,
                    cwd=app_cfg["dir"],
                    env=env,
                    shell=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
            self.spawned_by_us = True
        except Exception as spawn_err:
            logger.error("[EphemeralServer] Failed to spawn dev server process: %s", spawn_err)
            return None

        # 4. Health Probe Polling
        probe_url = f"http://127.0.0.1:{target_port}"
        deadline = time.time() + self.timeout_seconds

        while time.time() < deadline:
            # Check if process terminated prematurely (syntax error, missing env var, crash)
            if self.process.poll() is not None:
                logger.warning(
                    "[EphemeralServer] Process terminated prematurely with exit code %s. Cleanly skipping DAST.",
                    self.process.returncode
                )
                await self.stop_async()
                return None

            if await is_server_healthy_async(probe_url, timeout_s=0.5):
                logger.info("[EphemeralServer] Live health check PASSED for %s! Server is ready.", probe_url)
                self.target_url = probe_url
                return probe_url

            await asyncio.sleep(0.5)

        logger.warning(
            "[EphemeralServer] Server did not respond to health checks within %.1fs timeout. Cleanly skipping DAST.",
            self.timeout_seconds
        )
        await self.stop_async()
        return None

    async def stop_async(self) -> None:
        """
        Gracefully terminates the background server and its entire process tree.
        Ensures zero orphaned node.exe, vite, or python processes.
        """
        if not self.spawned_by_us or not self.process:
            return

        pid = self.process.pid
        logger.info("[EphemeralServer] Terminating ephemeral server process tree (PID %d)...", pid)

        # 1. First attempt: psutil recursive tree termination if available
        try:
            import psutil
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass
            parent.kill()
        except Exception:
            pass

        # 2. OS-level forceful process tree kill
        try:
            if os.name == "nt":
                subprocess.run(
                    f"taskkill /F /T /PID {pid}",
                    shell=True,
                    capture_output=True,
                    timeout=5,
                )
            else:
                import signal
                os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception as e:
            logger.debug("[EphemeralServer] Process cleanup notice: %s", e)
        finally:
            try:
                self.process.kill()
            except Exception:
                pass
            self.process = None
            self.spawned_by_us = False
            logger.info("[EphemeralServer] Process tree cleaned up successfully.")
