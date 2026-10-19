#!/usr/bin/env python3
"""Verify an installed Elytra wheel away from a source checkout.

Copy this script into a temporary directory and run it with the wheel's clean
virtual environment, using isolated Python mode:

    /tmp/elytra-venv/bin/python -I /tmp/verify_installed_release.py \
        --expected-version 0.3.0a1

Only the standard library is used before installation checks. All service data,
fixture effects and process working directories live in a private temporary
directory. No benchmark artifacts are written into the installation.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from html.parser import HTMLParser
import importlib
from importlib import metadata
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import sysconfig
import tempfile
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        path = values.get("src") if tag == "script" else values.get("href") if tag == "link" else None
        if path and path.startswith("/") and not path.startswith("//"):
            self.paths.add(path)


@contextmanager
def private_working_directory():
    original = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="elytra-installed-wheel-") as directory:
        work = Path(directory)
        work.chmod(0o700)
        os.chdir(work)
        try:
            yield work
        finally:
            os.chdir(original)


def verify(expected_version=None):
    require(sys.flags.isolated == 1, "Run this script with isolated Python: python -I /tmp/verify_installed_release.py")
    # Isolated mode ignores PYTHONPATH. Remove it for fixture subprocesses too.
    os.environ.pop("PYTHONPATH", None)
    checks = {}
    with private_working_directory() as work:
        distribution = metadata.distribution("elytra-mcp")
        version = distribution.version
        require(not expected_version or version == expected_version,
                f"Installed version {version!r} differs from expected {expected_version!r}")
        direct_url = distribution.read_text("direct_url.json")
        if direct_url:
            require(not json.loads(direct_url).get("dir_info", {}).get("editable"),
                    "Editable installations cannot verify wheel completeness")
        package = importlib.import_module("mirage_mcp")
        package_file = Path(package.__file__).resolve()
        package_root = package_file.parent
        library_roots = {Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")}
        require(any(package_file.is_relative_to(root) for root in library_roots),
                f"Package was imported outside installed site-packages: {package_file}")
        expected_file = Path(distribution.locate_file("mirage_mcp/__init__.py")).resolve()
        require(package_file == expected_file, "Import origin does not match the installed distribution")
        require(getattr(package, "__version__", None) == version, "Package/distribution versions disagree")
        checks["installed_distribution"] = {"version": version, "package_path": str(package_root), "isolated_python": True}

        def installed_module(name):
            module = importlib.import_module(name)
            require(Path(module.__file__).resolve().is_relative_to(package_root),
                    f"Module {name} escaped the installed package")
            return module

        visualizer = installed_module("mirage_mcp.visualizer")
        asset_root = visualizer.get_ui_dist_path().resolve()
        require(asset_root.is_relative_to(package_root), "UI lookup fell back to a source checkout")
        index = asset_root / "index.html"
        require(index.is_file(), "Installed wheel is missing the application entry HTML")
        asset_paths = sorted(path for path in asset_root.rglob("*") if path.is_file())
        require(any(path.suffix == ".js" for path in asset_paths), "Installed wheel is missing JavaScript assets")
        require(any(path.suffix == ".css" for path in asset_paths), "Installed wheel is missing CSS assets")
        require(len(asset_paths) <= 1000, "Unexpectedly large release asset inventory")
        checks["bundled_ui"] = {"files": len(asset_paths), "path": str(asset_root)}

        server_module = installed_module("mirage_mcp.server.control_plane")
        sdk = installed_module("mirage_mcp.sdk")
        owner_token = secrets.token_urlsafe(48)
        server = server_module.ControlPlaneServer(host="127.0.0.1", port=0,
            db_path=work / "state" / "live.db", token_file=work / "state" / "unused.token",
            auth_token=owner_token)
        opener = build_opener(ProxyHandler({}))

        def http(path, *, token=None, method="GET", payload=None, headers=None):
            request_headers = dict(headers or {})
            if token:
                request_headers["Authorization"] = "Bearer " + token
            data = json.dumps(payload).encode() if payload is not None else None
            if data is not None:
                request_headers["Content-Type"] = "application/json"
            request = Request(server.base_url + path, data=data, method=method, headers=request_headers)
            try:
                with opener.open(request, timeout=10) as response:
                    return response.status, response.headers, response.read()
            except HTTPError as exc:
                return exc.code, exc.headers, exc.read()

        try:
            server.start_background()
            status, headers, body = http("/")
            require(status == 200 and "text/html" in headers.get("Content-Type", ""), "Public homepage route is unavailable")
            html = body.decode("utf-8")
            require("elytra" in html.lower(), "Public entry HTML does not identify Elytra")
            references = AssetReferences()
            references.feed(html)
            require(references.paths, "Homepage entry HTML contains no local asset references")
            for path in references.paths:
                asset_status, _, asset = http(path)
                require(asset_status == 200 and asset, f"Homepage asset is unavailable: {path}")
            for file in asset_paths:
                route = "/" + file.relative_to(asset_root).as_posix()
                asset_status, _, served = http(route)
                require(asset_status == 200 and served == file.read_bytes(), f"Bundled asset was not served correctly: {route}")
            require(http("/app/")[0] == 200, "Application route is unavailable")
            checks["public_routes_and_assets"] = {"homepage": 200, "app": 200, "assets_checked": len(asset_paths)}

            require(http("/api/v1/overview")[0] == 401, "Unauthenticated overview access was not rejected")
            require(http("/api/v1/overview", token="incorrect-owner-token")[0] == 401,
                    "Incorrect owner credential was not rejected")
            require(http("/api/v1/runtime/runs", token=owner_token, method="POST", payload={"intent": "Must not be created"},
                         headers={"Origin": "https://untrusted.example"})[0] == 403,
                    "Cross-origin owner write was not rejected")
            owner = sdk.RuntimeClient(server.base_url, token=owner_token)
            overview = owner._request("GET", "/api/v1/overview")
            for field in ("total_events", "active_sessions", "pending_approvals", "schema_pins_verified"):
                require(overview[field] == 0, f"Clean installation unexpectedly seeded {field}")
            require(overview["attack_block_rate_pct"] is None and overview["false_positive_rate_pct"] is None,
                    "Clean installation claims unmeasured security rates")
            require(owner.list_tools()["tools"] == [] and owner.list_runs()["runs"] == [],
                    "Clean installation contains unexpected tools or runs")
            checks["authenticated_empty_runtime"] = True
        finally:
            server.shutdown()

        graph_module = installed_module("mirage_mcp.evaluation.runner")
        graph = graph_module.run_full_benchmark(write_artifacts=False)
        summary = graph["summary"]
        require(summary["total_exploit_scenarios"] == len(graph["exploit_results"]) > 0,
                "Packaged graph fixtures did not execute")
        require(summary["baseline_status"] == "not_measured" and summary["unprotected_exploit_success_rate_pct"] is None,
                "Packaged fixtures claim a fabricated compromise baseline")
        checks["packaged_graph_fixtures"] = {"attack_fixtures": len(graph["exploit_results"]),
                                               "clean_fixtures": len(graph["clean_workflow_results"])}

        observed_module = installed_module("mirage_mcp.evaluation.measured_runner")
        observed = observed_module.run_measured_benchmark(write_artifacts=False, exploit_limit=1)
        require(observed["passed"] is True, "Packaged subprocess effect/authorization checks failed")
        require(observed["agent_calls"] == 0 and observed["unprotected_agent_compromise_rate"] is None,
                "Scripted effects are incorrectly presented as agent compromise measurements")
        require(observed["pairs"] and observed["checks"], "Observed benchmark recorded no fixture attempts")
        for pair in observed["pairs"]:
            require(pair["bypass"]["mutation_delta"] == 1, "Bypass fixture did not actually reach the destination ledger")
            expected = 0 if pair["kind"] == "scripted_adversarial_call" else 1
            require(pair["protected"]["mutation_delta"] == expected,
                    "Protected fixture produced an unexpected destination effect")
        checks["packaged_subprocess_effects"] = {"pairs": len(observed["pairs"]), "boundary_checks": len(observed["checks"])}

        cli = subprocess.run([sys.executable, "-I", "-m", "mirage_mcp.cli.main", "--help"],
                             cwd=work, capture_output=True, text=True, timeout=15)
        require(cli.returncode == 0 and "elytra" in cli.stdout.lower(), "Installed CLI cannot start outside the checkout")
        entry_names = {entry.name for entry in distribution.entry_points if entry.group == "console_scripts"}
        require({"elytra", "mirage-mcp"}.issubset(entry_names), "Release is missing CLI entrypoints")
        checks["installed_cli"] = True
        require(not (work / "benchmarks").exists() and not (work / "src").exists(),
                "Verification unexpectedly acquired a source-tree fallback")
    return {"passed": True, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--expected-version", help="Require this installed distribution version")
    args = parser.parse_args()
    try:
        report = verify(args.expected_version)
    except Exception as exc:
        print(json.dumps({"passed": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
