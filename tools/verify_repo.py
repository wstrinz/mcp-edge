"""Offline source/package checks. Does not run helpers, build or access secrets."""
from hashlib import sha256
from pathlib import Path
import json

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML is required for this offline check")

root = Path(__file__).resolve().parents[1]
compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
# Reviewed phase 2 deployment shape: unprivileged, read-only, capability-free,
# bounded; reachable only through the proxy network (expose, no host ports);
# one named volume for the SQLite store and the assertion (and iroh) keys.
expected = {
    "services": {
        "edge": {
            "build": {"context": ".", "dockerfile": "Dockerfile"},
            "user": "65532:65532",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "environment": {
                "EDGE_MODE": "edge",
                "EDGE_PUBLIC_URL": "${EDGE_PUBLIC_URL:-https://mcp.app.stri.nz}",
                "EDGE_BIND": "0.0.0.0:8080",
                "EDGE_DATA_DIR": "/data",
                "EDGE_ROUTES": "/etc/mcp-edge/routes.toml",
                "EDGE_ENROLL_CODE": "${EDGE_ENROLL_CODE:-}",
                "EDGE_ORIGIN_WISKIT": "${EDGE_ORIGIN_WISKIT:-}",
            },
            "expose": ["8080"],
            "volumes": ["edge-data:/data"],
            "pids_limit": 64,
            "mem_limit": "256m",
            "cpus": 0.5,
            "restart": "unless-stopped",
            "stop_grace_period": "10s",
            "healthcheck": {
                "test": ["CMD", "/mcp-edge", "--healthcheck"],
                "interval": "30s", "timeout": "5s", "start_period": "10s", "retries": 3,
            },
            "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "3"}},
        }
    },
    "volumes": {"edge-data": None},
}
if compose != expected:
    raise SystemExit("Compose differs from the reviewed deployment definition")

manifest = json.loads((root / "docs/evidence/fixture-files.json").read_text(encoding="utf-8"))
expected_paths = set()
for row in manifest:
    relative = row["path"]
    path = root / relative
    if not relative.startswith("fixtures/") or path.resolve().is_relative_to(root) is False:
        raise SystemExit("Unexpected fixture manifest path")
    if not path.is_file() or sha256(path.read_bytes()).hexdigest() != row["sha256"]:
        raise SystemExit("Fixture differs from its archived baseline: " + relative)
    expected_paths.add(relative)
actual_paths = {path.relative_to(root).as_posix() for path in (root / "fixtures").rglob("*") if path.is_file()}
if expected_paths != actual_paths or len(expected_paths) != 23:
    raise SystemExit("Fixture source set differs from the archived baseline")

skipped = {"target", "tmp", ".git", "fixtures"}


def source_files():
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if path.is_file() and not any(p in skipped for p in parts):
            yield path


runtime = ["Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore", "compose.yaml"]
runtime += [p.relative_to(root).as_posix() for p in source_files()
            if p.suffix in {".rs", ".toml", ".js", ".css", ".md"}]
for relative in runtime:
    if b"\r\n" in (root / relative).read_bytes():
        raise SystemExit("Runtime sources should use LF: " + relative)
forbidden_names = {".env", "secrets.env", "credentials.json"}
for path in source_files():
    if path.name in forbidden_names or path.suffix.lower() in {".pem", ".key"}:
        raise SystemExit("Unexpected sensitive file name in source package")

print(json.dumps({"compose": "reviewed deployment policy matches", "fixtureFilesUnchanged": len(expected_paths),
                  "lfFilesChecked": len(runtime), "credentialsRead": False, "networkCalls": 0,
                  "helpersExecuted": False}, indent=2))
