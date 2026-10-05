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
expected = {
    "services": {
        "gateway": {
            "build": {"context": ".", "dockerfile": "Dockerfile"},
            "user": "65532:65532",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "environment": {"WISKIT_GATEWAY_MODE": "deny-all"},
            "network_mode": "none",
            "pids_limit": 64,
            "mem_limit": "128m",
            "cpus": 0.25,
            "restart": "unless-stopped",
            "stop_grace_period": "10s",
            "healthcheck": {
                "test": ["CMD", "/gateway", "--healthcheck"],
                "interval": "30s", "timeout": "5s", "start_period": "10s", "retries": 3,
            },
            "logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "2"}},
        }
    }
}
if compose != expected:
    raise SystemExit("Compose differs from the reviewed inert definition")

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

for relative in ["Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore", "src/lib.rs", "src/main.rs", "tests/inert.rs"]:
    if b"\r\n" in (root / relative).read_bytes():
        raise SystemExit("Root runtime should use LF: " + relative)
forbidden_names = {".env", "secrets.env", "config.toml", "credentials.json"}
for path in root.rglob("*"):
    if path.is_file() and (path.name in forbidden_names or path.suffix.lower() in {".pem", ".key"}):
        raise SystemExit("Unexpected sensitive file name in source package")

print(json.dumps({"compose": "reviewed inert policy matches", "fixtureFilesUnchanged": len(expected_paths),
                  "credentialsRead": False, "networkCalls": 0, "helpersExecuted": False}, indent=2))
