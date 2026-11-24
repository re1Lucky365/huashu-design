[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'
[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'
#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def to_ocsf_event(
    item: dict[str, Any],
    batch_id: str,
    ingested_at: str,
    epoch_ms: int,
    rec_hash: str,
) -> dict[str, Any]:
    severity_raw = str(item.get("severity", item.get("status", "info"))).lower()
    if severity_raw in {"crit", "critical", "error", "err", "fail", "failed"}:
        severity_id, severity = 4, "High"
    elif severity_raw in {"warn", "warning"}:
        severity_id, severity = 2, "Low"
    else:
        severity_id, severity = 1, "Informational"

    return {
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "severity_id": severity_id,
        "severity": severity,
        "time": epoch_ms,
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Master-Hub", "vendor_name": "Local-First"},
            "batch_id": batch_id,
            "ingested_at": ingested_at,
            "record_hash": rec_hash,
        },
        "observables": [{"name": "record_hash", "type_id": 10, "value": rec_hash}],
        "data": item,
    }


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            ocsf_class_uid INTEGER NOT NULL,
            severity_id INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def format_openmetrics(
    inserted: int,
    duplicates: int,
    duration_sec: float,
) -> str:
    lines = [
        "# HELP master_pipeline_records_total Total records processed in batch",
        "# TYPE master_pipeline_records_total counter",
        f'master_pipeline_records_total{{status="inserted"}} {inserted}',
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}',
        "# HELP master_pipeline_batch_duration_seconds Batch processing duration in seconds",
        "# TYPE master_pipeline_batch_duration_seconds histogram",
    ]
    for bound in HISTOGRAM_BUCKETS:
        count = 1 if duration_sec <= bound else 0
        lines.append(
            f'master_pipeline_batch_duration_seconds_bucket{{le="{bound}"}} {count}'
        )
    lines.append(f'master_pipeline_batch_duration_seconds_bucket{{le="+Inf"}} 1')
    lines.append(f"master_pipeline_batch_duration_seconds_sum {duration_sec:.6f}")
    lines.append("master_pipeline_batch_duration_seconds_count 1")
    lines.append("# EOF")
    return "\n".join(lines) + "\n"


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, Any]:
    start = time.perf_counter()
    now_dt = datetime.now(timezone.utc)
    batch_id = now_dt.strftime("%Y%m%dT%H%M%SZ")
    ingested_at = now_dt.isoformat()
    epoch_ms = int(now_dt.timestamp() * 1000)

    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                event = to_ocsf_event(item, batch_id, ingested_at, epoch_ms, rec_hash)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, ocsf_class_uid, severity_id, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        batch_id,
                        ingested_at,
                        rec_hash,
                        event["class_uid"],
                        event["severity_id"],
                        json.dumps(event, sort_keys=True),
                    ),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(event, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    elapsed = time.perf_counter() - start
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(
        format_openmetrics(inserted, duplicates, elapsed),
        encoding="utf-8",
    )

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
        "duration_seconds": round(elapsed, 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="OCSF-normalized local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
name: Master Pipeline CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  pipeline-and-security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies & run pytest
        run: |
          python -m pip install --upgrade pip pytest cryptography
          PYTHONPATH=. pytest -v

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build & test integrity-cli
        working-directory: crates/integrity-cli
        run: cargo test --locked || cargo test
from pathlib import Path

from scripts.hash_manifest import generate, verify
from scripts.pipeline_ingest import run_pipeline
from scripts.vault_encrypt import decrypt_file, encrypt_file


def test_pipeline_dedup_and_outputs(tmp_path: Path) -> None:
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("event_id,status\n1,ok\n1,ok\n2,warn\n", encoding="utf-8")

    db_file = tmp_path / "pipeline.sqlite"
    jsonl_file = tmp_path / "out.jsonl"
    metrics_file = tmp_path / "metrics.prom"

    stats = run_pipeline(csv_file, db_file, jsonl_file, metrics_file)
    assert stats["total_input"] == 3
    assert stats["inserted"] == 2
    assert stats["duplicates"] == 1
    assert db_file.exists()
    assert jsonl_file.exists()
    assert "master_pipeline_records_total" in metrics_file.read_text(encoding="utf-8")


def test_manifest_and_vault_roundtrip(tmp_path: Path) -> None:
    sample = tmp_path / "payload.txt"
    sample.write_text("pipeline-state\n", encoding="utf-8")
    manifest = tmp_path / "MANIFEST.sha256"

    generate(tmp_path, manifest)
    assert verify(tmp_path, manifest) == 0

    enc = tmp_path / "payload.enc"
    dec = tmp_path / "restored.txt"
    encrypt_file(sample, enc, "test-passphrase")
    decrypt_file(enc, dec, "test-passphrase")
    assert dec.read_text(encoding="utf-8") == "pipeline-state\n"
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_dir(root: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut map = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path: PathBuf = entry.path().to_path_buf();
            if path.components().any(|c| {
                let s = c.as_os_str();
                s == ".git" || s == "target" || s == "__pycache__" || s == "data"
            }) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            map.insert(rel, hash_file(&path)?);
        }
    }
    Ok(map)
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "scan".to_string());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".to_string()));

    match cmd.as_str() {
        "scan" => {
            let entries = scan_dir(&root).expect("failed scanning directory");
            for (rel, digest) in entries {
                println!("{digest}  {rel}");
            }
        }
        "check" => {
            let manifest_path =
                PathBuf::from(args.next().unwrap_or_else(|| "MANIFEST.sha256".to_string()));
            let content = fs::read_to_string(&manifest_path).expect("failed reading manifest");
            let current = scan_dir(&root).expect("failed scanning directory");
            let mut mismatches = 0;
            for line in content.lines() {
                if let Some((expected, rel)) = line.split_once("  ") {
                    match current.get(rel) {
                        Some(actual) if actual == expected => {}
                        _ => {
                            eprintln!("DRIFT: {rel}");
                            mismatches += 1;
                        }
                    }
                }
            }
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: integrity-cli <scan|check> <dir> [manifest_path]");
            std::process::exit(2);
        }
    }
}
[package]
name = "integrity-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
walkdir = "2.5"
#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Encrypted backup created: ${ZST_FILE}.enc"
else
  echo "Backup created: ${ZST_FILE}"
fi

echo "Manifest created: ${MANIFEST_FILE}"
#!/usr/bin/env python3
import argparse
import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(src.read_bytes())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symmetric file encryption/decryption")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt")
    enc_p.add_argument("src", type=Path)
    enc_p.add_argument("dst", type=Path)

    dec_p = sub.add_parser("decrypt")
    dec_p.add_argument("src", type=Path)
    dec_p.add_argument("dst", type=Path)

    args = parser.parse_args()
    password = os.environ.get("VAULT_PASSPHRASE") or input("Enter vault passphrase: ")
    if args.cmd == "encrypt":
        encrypt_file(args.src, args.dst, password)
    else:
        decrypt_file(args.src, args.dst, password)


if __name__ == "__main__":
    main()
encrypt.py
#!/usr/bin/env python3
import argparse
import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(src.read_bytes())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symmetric file encryption/decryption")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt")
    enc_p.add_argument("src", type=Path)
    enc_p.add_argument("dst", type=Path)

    dec_p = sub.add_parser("decrypt")
    dec_p.add_argument("src", type=Path)
    dec_p.add_argument("dst", type=Path)

    args = parser.parse_args()
    password = os.environ.get("VAULT_PASSPHRASE") or input("Enter vault passphrase: ")
    if args.cmd == "encrypt":
        encrypt_file(args.src, args.dst, password)
    else:
        decrypt_file(args.src, args.dst, password)


if __name__ == "__main__":
    main()
#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Encrypted backup created: ${ZST_FILE}.enc"
else
  echo "Backup created: ${ZST_FILE}"
fi

echo "Manifest created: ${MANIFEST_FILE}"
#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

EXCLUDE_DIRS = {".git", "__pycache__", "target", ".pytest_cache", "backups", "vault", "data"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(root: Path, output: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.resolve() == output.resolve():
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def verify(root: Path, manifest: Path) -> int:
    mismatches = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        target = root / rel
        if not target.exists() or sha256_file(target) != expected:
            print(f"MISMATCH: {rel}")
            mismatches += 1
    return mismatches


def main() -> None:
    parser = argparse.ArgumentParser(description="SHA-256 manifest generator and verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen_p = sub.add_parser("generate")
    gen_p.add_argument("--root", type=Path, default=Path("."))
    gen_p.add_argument("--output", type=Path, default=Path("MANIFEST.sha256"))

    ver_p = sub.add_parser("verify")
    ver_p.add_argument("--root", type=Path, default=Path("."))
    ver_p.add_argument("--manifest", type=Path, default=Path("MANIFEST.sha256"))

    args = parser.parse_args()
    if args.cmd == "generate":
        generate(args.root, args.output)
    else:
        bad = verify(args.root, args.manifest)
        raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
path.is
#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, int]:
    batch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ingested_at = datetime.now(timezone.utc).isoformat()
    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                envelope = {
                    "batch_id": batch_id,
                    "ingested_at": ingested_at,
                    "record_hash": rec_hash,
                    "data": item,
                }
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, payload_json)
                    VALUES (?, ?, ?, ?);
                    """,
                    (batch_id, ingested_at, rec_hash, json.dumps(envelope, sort_keys=True)),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(envelope, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_text = (
        "# HELP master_pipeline_records_total Total records processed in batch\n"
        "# TYPE master_pipeline_records_total counter\n"
        f'master_pipeline_records_total{{status="inserted"}} {inserted}\n'
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}\n'
        "# EOF\n"
    )
    metrics_out.write_text(metrics_text, encoding="utf-8")

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-pipeline-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   ├── backup_all.sh
│   └── pipeline_ingest.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_pipeline_and_tools.py
README.md
bootstrap.sh
name: Master-Hub CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan for secrets with Gitleaks
        uses: gitleaks/gitleaks-action@v2

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python test dependencies & run pytest
        run: |
          python -m pip install --upgrade pip pytest cryptography
          pytest -v

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Run Rust integrity-cli tests
        working-directory: crates/integrity-cli
        run: cargo test --locked || cargo test
title = "Master-Hub Secret Scanning Rules"

[extend]
useDefault = true

[[rules]]
id = "generic-private-key-or-token"
description = "Detect high-entropy private keys or bearer tokens"
regex = '''(?i)(api_key|secret_key|private_key|access_token|auth_token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?'''
keywords = ["api_key", "secret_key", "private_key", "access_token", "auth_token"]

[allowlist]
description = "Allow test fixtures and placeholder examples"
paths = [
  '''tests/''',
  '''README\.md$'''
]
Thumbs.db
# Local secrets, keys, and sensitive artifacts
*.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.enc
vault/
secrets/
backups/

# Generated manifests & build artifacts
MANIFEST.sha256
*.sha256
*.tar
*.tar.zst
target/
__pycache__/
*.py[cod]
.pytest_cache/
.ruff_cache/

# OS & editor files
.DS_Store
Thumbs.db
*.swp
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   └── backup_all.sh
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_security_tools.py
#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

echo "[1/4] Staging files from '${SOURCE_DIR}' (excluding .git, target, __pycache__, node_modules, .venv)..."
tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

echo "[2/4] Compressing archive with zstd..."
zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"

echo "[3/4] Generating SHA-256 checksum manifest..."
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  echo "[4/4] Encrypting archive with vault_encrypt.py..."
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Backup written: ${ZST_FILE}.enc"
else
  echo "[4/4] Skipping encryption (set ENCRYPT_BACKUP=1 to encrypt). Backup written: ${ZST_FILE}"
fi

echo "Manifest written: ${MANIFEST_FILE}"
master-ci.yml
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   └── backup_all.sh
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_security_tools.py
# Local secrets, keys, and sensitive artifacts
*.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.enc
vault/
secrets/
backups/

# Generated manifests & build artifacts
MANIFEST.sha256
*.sha256
*.tar
*.tar.zst
target/
__pycache__/
*.py[cod]
.pytest_cache/
.ruff_cache/

# OS & editor files
.DS_Store
Thumbs.db
*.swp
#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

echo "[1/4] Staging files from '${SOURCE_DIR}' (excluding .git, target, __pycache__, node_modules, .venv)..."
tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

echo "[2/4] Compressing archive with zstd..."
zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"

echo "[3/4] Generating SHA-256 checksum manifest..."
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  echo "[4/4] Encrypting archive with vault_encrypt.py..."
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Backup written: ${ZST_FILE}.enc"
else
  echo "[4/4] Skipping encryption (set ENCRYPT_BACKUP=1 to encrypt). Backup written: ${ZST_FILE}"
fi

echo "Manifest written: ${MANIFEST_FILE}"
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   └── vault_encrypt.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/main.rs
├── tests/
│   └── test_security_tools.py
└── README.md
#!/usr/bin/env python3
import argparse
import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(src.read_bytes())
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local symmetric file encrypt/decrypt")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt")
    enc_p.add_argument("src", type=Path)
    enc_p.add_argument("dst", type=Path)

    dec_p = sub.add_parser("decrypt")
    dec_p.add_argument("src", type=Path)
    dec_p.add_argument("dst", type=Path)

    args = parser.parse_args()
    password = os.environ.get("VAULT_PASSPHRASE") or input("Enter vault passphrase: ")
    if args.cmd == "encrypt":
        encrypt_file(args.src, args.dst, password)
    else:
        decrypt_file(args.src, args.dst, password)


if __name__ == "__main__":
    main()
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_dir(root: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut map = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path: PathBuf = entry.path().to_path_buf();
            if path.components().any(|c| c.as_os_str() == ".git" || c.as_os_str() == "target") {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            map.insert(rel, hash_file(&path)?);
        }
    }
    Ok(map)
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "scan".to_string());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".to_string()));

    match cmd.as_str() {
        "scan" => {
            let entries = scan_dir(&root).expect("failed scanning directory");
            for (rel, digest) in entries {
                println!("{digest}  {rel}");
            }
        }
        "check" => {
            let manifest_path = PathBuf::from(args.next().unwrap_or_else(|| "MANIFEST.sha256".to_string()));
            let content = fs::read_to_string(&manifest_path).expect("failed reading manifest");
            let current = scan_dir(&root).expect("failed scanning directory");
            let mut mismatches = 0;
            for line in content.lines() {
                if let Some((expected, rel)) = line.split_once("  ") {
                    match current.get(rel) {
                        Some(actual) if actual == expected => {}
                        _ => {
                            eprintln!("DRIFT: {rel}");
                            mismatches += 1;
                        }
                    }
                }
            }
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: integrity-cli <scan|check> <dir> [manifest_path]");
            std::process::exit(2);
        }
    }
}
from pathlib import Path

from scripts.hash_manifest import generate, verify
from scripts.vault_encrypt import decrypt_file, encrypt_file


def test_manifest_generate_and_verify(tmp_path: Path) -> None:
    sample = tmp_path / "notes.txt"
    sample.write_text("integrity-check\n", encoding="utf-8")
    manifest = tmp_path / "MANIFEST.sha256"

    generate(tmp_path, manifest)
    assert verify(tmp_path, manifest) == 0

    sample.write_text("tampered\n", encoding="utf-8")
    assert verify(tmp_path, manifest) == 1


def test_vault_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    plain = tmp_path / "secret.txt"
    enc = tmp_path / "secret.enc"
    restored = tmp_path / "restored.txt"
    plain.write_text("sensitive-payload", encoding="utf-8")

    encrypt_file(plain, enc, "test-passphrase-123")
    assert enc.exists()
    assert enc.read_bytes() != plain.read_bytes()

    decrypt_file(enc, restored, "test-passphrase-123")
    assert restored.read_text(encoding="utf-8") == "sensitive-payload"
security-ci.yml

<sub>🌐 <b>中文</b> · <a href="README.en.md">English</a></sub>

<div align="center">

# Huashu Design

> *「打字。回车。一份能交付的设计。」*
> *"Type. Hit enter. A finished design lands in your lap."*

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Agent-Agnostic](https://img.shields.io/badge/Agent-Agnostic-blueviolet)](https://skills.sh)
[![Skills](https://img.shields.io/badge/skills.sh-Compatible-green)](https://skills.sh)

<!-- BOOK-PROMO-START 《图解Agent Skills》京东横幅，2026-12-21下线 -->
<a href="https://item.jd.com/14829817.html"><img src="https://raw.githubusercontent.com/alchaincyf/alchaincyf/main/assets/book-agent-skills-jd-c.jpg" alt="纸质书《图解Agent Skills：让AI记住你的工作方式》已上市，点击去京东购买" width="100%"></a>
<!-- BOOK-PROMO-END -->

<br>

**在你的 agent 里打一句话，拿回一份能交付的设计。**

<br>

3 到 30 分钟，你能 ship 一段**产品发布动画**、一个能点击的 App 原型、一套能编辑的 PPT、一份印刷级的信息图。

不是「AI 做的还行」那种水平——是看起来像大厂设计团队做的。给 skill 你的品牌资产（logo、色板、UI 截图），它会读懂你的品牌气质；什么都不给，**六个候选里挑出的三个真实方向 + 92 种带样张的风格库**也能兜底到不出 AI slop。

**你看到这篇 README 里的每一页设计，都是 huashu-design 自己做的。** 不是 Figma，不是 AE，就是一句话 prompt + skill 跑通。下次产品发布要做宣传片？现在你也能做。

```
npx skills add alchaincyf/huashu-design
```

跨 agent 通用——Claude Code、Cursor、Codex、OpenClaw、Hermes 都能装。

> 📣 **已改为 MIT 协议。** 自 2026-05-14 起本 skill 完全开源（[MIT License](LICENSE)），个人和**商用都免费**，无需事先授权。原「个人使用免费、企业商用需授权」的条款已作废。([查看变更](#license))

> 🆕 **3.5：微信小程序来了，设计完能交给 WorkBuddy 做成真小程序。** 新增小程序模块，按 2026 年 11 月的微信规格设计（胶囊、导航栏、tabBar、5:4 转发卡片、主包 2MB），每个方向先想清楚它从哪被打开：群聊卡片、扫码，还是「最近使用」。定稿后一条命令导出交付包：750 宽逐屏截图、app.json 骨架、设计参数和体检。在 WorkBuddy 里可以接着把它做成原生小程序，实测 Hy4 flash 照交付包做出 6 页，主流程能点通。另外新增展示板组件（三种构图）、断网可开的离线打包，截图和体检脚本在 WorkBuddy 里也能直接跑。

> 🆕 **3.4：App 原型换了一套想法，新增 App Store 宣传图。** 走查两届 App Store Awards 的 90 个入围作品，提炼出八条界面范式（各带样张）：先定「这个 App 管的事在现实里长什么样」，再画屏。新增商店宣传图模块（1320×2868，连幅、破框、搜索结果预览）。参考改成「看原图、量数字、借一层不借一身」，做完和参照并排对回去。界面里该是图的地方放真的图：自带生图的环境（Codex、豆包、WorkBuddy）直接生成，Claude Code、DeepSeek Harness 借本机 Codex 或你给的生图 API，不再用 emoji 和占位块顶替。

> **3.1：新增小红书图文。** 一组 3:4 竖图的八种范式——标本志、贴纸本、索引、长卷、日报、集换卡、留白、信息图，每个样张同时是能直接改的模板；一条命令切成成图，顺手查字号、出界、长卷跨缝和压字。[看样张](#设计方向顾问)

> **3.0：三个方向更敢，项目之间也不再长一个样。** 先出六张缩略图再挑三版做成真稿；风格库扩到 84 种（新增 App、中文与东亚两个分区），每种都有样张；参照作品先截图再动手；带一个只量事实的设计体检，和一本记住你做过什么样子的外观账本。[详见核心机制](#核心机制)

[看效果](#30-案例) · [安装](#装上就能用) · [能做什么](#能做什么) · [核心机制](#核心机制) · [和 Claude Design 的关系](#和-claude-design-的关系)

</div>

---

<p align="center">
  <img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/launch-3.0.gif" alt="huashu-design 3.0 发布片" width="100%">
</p>

<p align="center"><sub>
  ▲ 3.0 发布片 · 32 秒 · 片里每一页设计都是 3.0 自己做的，剪辑用的是 <a href="https://github.com/alchaincyf/huashu-motion">huashu-motion</a><br>
  👉 <a href="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/launch-3.0.mp4">下载 MP4（1080p · 含配乐 · 24MB）</a> ·
  <a href="https://www.huasheng.ai/huashu-design-hero/">2.0 的带音效 HTML 互动版</a>
</sub></p>

---

## 3.0 案例

下面这些都是 3.0 跑出来的。前五个是从发布时新跑的 6 道题里挑的，每道只给一句话需求，方向是 agent 自己挑的，作者没插手；后两个一个是第三轮盲选赢下来的那版，一个是发布后作者拿它做的真实项目。

### 网页 · 《富岳三十六景》线上展

> 「给葛饰北斋的《富岳三十六景》做一个线上展览网站」

三版分别是 Rijksmuseum 官网式的暗场展厅、田中一光式的三角窗、民国书衣式的题签框。设计体检报过一次撞车：两版首屏都用了《神奈川冲浪里》，它就把暗场那版换成了《山下白雨》。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-hokusai-hero.jpg" width="100%" alt="富岳三十六景线上展首屏：暗场满屏《山下白雨》"></p>

往下一章讲普鲁士蓝，依据是大都会博物馆的光谱研究；全 46 幅都来自芝加哥艺术博物馆和大都会的开放馆藏。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-hokusai-prussian-blue.jpg" width="100%" alt="一种进口的蓝：普鲁士蓝章节"></p>
<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-hokusai-all-46.jpg" width="60%" alt="全四十六幅作品墙"></p>

### App · 鸣迹（观鸟记录）

> 「做一个观鸟记录 App 的原型」

现实参照找的是拿了 2025 年苹果设计奖的 CapWords，`ref_board.py` 先把它截成参考板，agent 亲眼看过再动手。借来的是「从照片里撕下一张贴纸」：每只鸟都从 Wikimedia 的真实照片里分割出来，贴进一年的本子里，叫声波形是拿真实录音算的。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-mingji-birding-app.jpg" width="75%" alt="鸣迹：听到一只鸟，撕下一张贴纸"></p>

### App · 今晚吃啥（家常菜谱）

> 「做一个家常菜谱 App」

秒数轮盘恰好抽到吕敬人书籍设计，最后做成了一本菜谱：一道菜一页方子，切口旁边留一条旁注栏，写「擦干再煎才不溅油」「老抽只要几滴」，朱砂只给「开做」这一方印。外观账本看到最近 6 个交付里 5 个是无衬线标题，这一版挑了宋体。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-recipe-app.jpg" width="75%" alt="今晚吃啥：一道菜一页方子"></p>

### PPT · 《千里江山图》讲座

走的是最佳设计师 Abbott Miller 式的暗场展柜，暗底取的是绢地最暗处的颜色。封面底下那条细长的位置条就是整卷缩略图，框出这一页在 11.9 米长卷的哪一段。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-qianli-cover.jpg" width="100%" alt="千里江山图讲座封面"></p>
<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-qianli-pages.jpg" width="100%" alt="一张多大的画、希孟年十八岁、小如豆、颜色来自石头"></p>

### PPT · 黑洞的照片是怎么拍出来的

现实参照是 Jonathan Corum 的讲座幻灯片：黑底、照片做主角、标注直接写在图上。每页都标了出处，事实先过核查再上页面。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-blackhole-pages.jpg" width="100%" alt="黑洞科普 PPT 四页"></p>

### App · 绿拇指（第三轮盲选赢的那版）

把植物当成会呼吸的生命体征来读。App 原型做成一张有构图的展示板，几台手机错落排开。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-plant-health-app.jpg" width="75%" alt="绿拇指：把植物当成会呼吸的生命体征来读"></p>

### 网页 · 旅居档案（作者自己的项目）

三年里所有旅行照片的地图。选的是葛西薰式的白纸明朝体长卷，开头一张卫星地图串起所有旅程，往下一段旅程一章。选完作者顺口说了句「尽量不要遗漏」，它就记进了经验：个人回忆类档案照片要全，而且注明只适用于照片档案，不外溢到产品界面。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v3.0.0/case-travel-archive.jpg" width="100%" alt="旅居档案"></p>

---

## 📺 新手教程（花叔亲录）

不知道怎么用？看花叔录的 huashu-design 上手教程：

<p align="center">
  <a href="https://www.youtube.com/watch?v=m-_BlUdcIvw"><img src="https://img.youtube.com/vi/m-_BlUdcIvw/maxresdefault.jpg" alt="huashu-design 使用教程" width="70%"></a>
</p>

<p align="center"><sub>👉 <a href="https://www.youtube.com/watch?v=m-_BlUdcIvw">在 YouTube 观看完整教程</a></sub></p>

---

## 装上就能用

```bash
npx skills add alchaincyf/huashu-design
```

> **装完先自检**：这个 skill 不只是 SKILL.md 一个文件，`references/`、`assets/`、`scripts/`、`demos/` 四个子目录里有 430+ 个被引用的配方、脚本、素材文件，缺一不可。装完看一眼安装目录（如 `~/.claude/skills/huashu-design/`），如果只有 SKILL.md、没有那几个子目录，说明你的 `skills` CLI 版本太旧（≤1.5.15 有个只同步单文件的 bug，已在 1.5.19 修复）。升级后再装一次即可：
>
> ```bash
> npm i -g skills@latest        # 或 npx skills@latest add alchaincyf/huashu-design
> ```
>
> 升级后仍异常，就用 `git clone` 兜底安装，把仓库克隆到任意 skills 目录即可：
>
> ```bash
> git clone https://github.com/alchaincyf/huashu-design.git ~/.claude/skills/huashu-design
> ```

### 在 WorkBuddy 等 agent 里装

直接在对话里说：

```
帮我去GitHub：https://github.com/alchaincyf/huashu-design 安装这个skill的最新版本
```

更新也一样，把「安装」换成「更新」。手动装也行：把仓库下载解压，整个文件夹放进 `~/.workbuddy/skills/`，它会出现在「专家·技能·连接器 → 技能 → 已安装」里。

### DeepSeek Harness 插件

本仓库同时是一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）插件。桌面端用户在「插件 → 添加插件」里填 GitHub 仓库地址，或者用命令行（桌面端的 profile 叫 `desktop`，网页版换成 `web`）：

```bash
dsh plugin --profile desktop add github:alchaincyf/huashu-design
```

命令行装之前，桌面端要先打开过一次，并且完全退出。装完再打开 DSH，插件才会加载。实测桌面端会直接用它自带的 Python 生成可编辑 PPTX；要导出 PDF 时，脚本会借用你电脑上已装的 Chrome 或 Edge。卸载：`dsh plugin --profile desktop remove huashu-design`。

然后在 Claude Code / Codex / Cursor / DeepSeek Harness 等任意支持 skills 的 agent 里直接说话：

```
「做一份 AI 心理学的演讲 PPT，推荐 3 个风格方向让我选」
「做个 AI 番茄钟 iOS 原型，4 个核心屏幕要真能点击」
「把这段逻辑做成 60 秒动画，导出 MP4 和 GIF」
「帮我对这个设计做一个 6 维度评审」
```

没有按钮、没有面板、没有 Figma 插件。

---

## Star 趋势

<p align="center">
  <a href="https://star-history.com/#alchaincyf/huashu-design&Date">
    <img src="https://api.star-history.com/svg?repos=alchaincyf/huashu-design&type=Date" alt="huashu-design Star History" width="80%">
  </a>
</p>

---

## 能做什么

| 能力 | 交付物 | 典型耗时 |
|------|--------|----------|
| 交互原型（App / Web） | 单文件 HTML · 真 iPhone bezel · 可点击 · Playwright 验证 | 10–15 min |
| 演讲幻灯片 | HTML deck（浏览器演讲）+ 可编辑 PPTX（文本框保留） | 15–25 min |
| 时间轴动画 | MP4（25fps / 60fps 插帧）+ GIF（palette 优化）+ BGM | 8–12 min |
| 设计变体 | 3+ 并排对比 · Tweaks 实时调参 · 跨维度探索 | 10 min |
| 信息图 / 可视化 | 印刷级排版 · 可导 PDF/PNG/SVG | 10 min |
| 小红书图文 / 封面 | 3:4 一组图（≤18 张）· 8 种范式模板 · 长卷连续滑动 · 一条命令切图并体检 | 10–15 min |
| App Store 宣传图 | 1320×2868 上架图（≤10 张）· 先拉同类目真实商店截图当参考 · 连幅自动切张 · 搜索结果缩略预览与体检 | 10–15 min |
| 设计方向顾问 | **三套逻辑各出两个候选**（最佳设计师 + 同媒介获奖作品 + 秒数轮盘）· 六个候选挑三版真实视觉，另三个作备选 | 10 min |
| 6 维度专家评审 | 概念/立意一票否决 + 5 个执行维度 · 雷达图 + Keep/Fix/Quick Wins · 可操作修复清单 | 3 min |

---

## Demo 画廊

### 设计方向顾问

模糊需求时的 fallback：**三套互补逻辑各出两个候选**——最佳设计师（预算无上限时最适合的设计师）+ 现实参照（同媒介的获奖作品，先截图亲眼看）+ 秒数轮盘（从风格库随机抽，打破惯性）。六个候选里挑最强、最不一样的三版做成**真实视觉**让你看着选，另外三个作为备选用一两句话告诉你。背后是 **92 种 HTML 原生风格库**（网页 20 + PPT 20 + 信息图 20 + App 12 + 中文与东亚 12 + 小红书 8，纯 CSS 无需生图），每种都有一张样张。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/w3-fallback-advisor.gif" width="100%"></p>
<p align="center"><sub>动图为 2.0 流程（三套逻辑直接各出一版）</sub></p>

3.0 新增的两个分区，每格都是一张样张（全部纯 HTML/CSS，题材与数字虚构）：

<p align="center"><img src="assets/style-specimens/sheet-east.jpg" width="100%" alt="中文与东亚设计 12 种：吕敬人书籍设计、宋刻本版式、民国书衣、上海摩登、中文实验字体、香港街招、传统色节气、杉浦康平、田中一光、服部一成、佐藤可士和、日式杂志密排"></p>
<p align="center"><img src="assets/style-specimens/sheet-app.jpg" width="100%" alt="App 风格 12 种：硬件面板、液态玻璃、玩味 3D、友好金融、专业相机、户外地形、内容瀑布流、命令面板、健康数据、原生精修、柔和鼓励、编辑式阅读"></p>

3.1 新增的小红书分区，每格是一个范式的封面＋内页（长卷是三张连成的一幅）。样张来自一次真实发布，八版做的是同一篇笔记：

<p align="center"><img src="assets/style-specimens/sheet-xhs.jpg" width="100%" alt="小红书图文 8 种：标本志、贴纸本、索引、长卷、日报、集换卡、留白、信息图"></p>

### iOS App 原型

iPhone 15 Pro 精确机身（灵动岛 / 状态栏 / Home Indicator）· 状态驱动多屏切换 · 真图从 Wikimedia/Met/Unsplash 取 · Playwright 自动点击测试。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c1-ios-prototype.gif" width="100%"></p>

### Motion Design 引擎

Stage + Sprite 时间片段模型 · `useTime` / `useSprite` / `interpolate` / `Easing` 四 API 覆盖所有动画需求 · 一条命令导出 MP4 / GIF / 60fps 插帧 / 带 BGM 的成片。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c3-motion-design.gif" width="100%"></p>

### HTML Slides → 可编辑 PPTX

HTML deck 浏览器演讲 · `html2pptx.js` 读 DOM 的 computedStyle 逐元素翻译成 PowerPoint 对象 · 导出的是**真文本框**，PPT 里双击即可编辑。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c2-slides-pptx.gif" width="100%"></p>

### Tweaks · 实时变体切换

配色 / 字型 / 信息密度等参数化 · 侧边面板切换 · 纯前端 + `localStorage` 持久化 · 刷新不丢。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c4-tweaks.gif" width="100%"></p>

### 信息图 / 数据可视化

杂志级排版 · CSS Grid 精准分栏 · `text-wrap: pretty` 排印细节 · 真数据驱动 · 可导 PDF 矢量 / PNG 300dpi / SVG。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c5-infographic.gif" width="100%"></p>

### 6 维度专家评审

概念/立意（权重最高，≤5 分时总评封顶）+ 哲学一致性 · 视觉层级 · 细节执行 · 功能性 · 创新性 各 0–10 分 · 雷达图可视化 · 输出 Keep / Fix / Quick Wins 清单。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/c6-expert-review.gif" width="100%"></p>

### Junior Designer 工作流

不闷头做大招：先写 assumptions + placeholders + reasoning，尽早 show 给你，再迭代。理解错了早改比晚改便宜 100 倍。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/w2-junior-designer.gif" width="100%"></p>

### 品牌资产协议 5 步硬流程

涉及具体品牌时强制执行：问 → 搜 → 下载（三条兜底）→ grep 色值 → 写 `brand-spec.md`。

<p align="center"><img src="https://github.com/alchaincyf/huashu-design/releases/download/v2.0/w1-brand-protocol.gif" width="100%"></p>

---

## Showcase · 2.0 时期的真实案例

### 鹦鹉进化史网站 · 设计方向顾问三套逻辑实战（2.0）

> **Live demo · [https://www.huasheng.ai/parrots/](https://www.huasheng.ai/parrots/)**

一句「做个介绍鹦鹉进化史的网站」、零额外要求，skill 自动跑完整 2.0 顾问流程：先判断图片是内容必需 → 抓公共领域博物插画（Edward Lear / John Gould 的鹦鹉图录）→ **三套逻辑并行**（秒数轮盘 + 现实参照获奖站 + 原研哉「白」哲学）各出一版真实视觉。**素材齐了再设计，不是边设计边用色块占位。**

### 「聊聊 skill」 · PM after-party 演讲 deck

> **Live demo · [https://skill-huasheng.vercel.app](https://skill-huasheng.vercel.app)**

13 页 HTML deck，**全部用 huashu-design 完成**：

- 黑底极简衬线视觉系统（cover / about / hook / what / why / closing）
- 2 个带 BGM + SFX 的 22 秒 cinematic demo（Nuwa skill workflow + Darwin skill workflow），各采用**完全独立的视觉语言**：
  - **Nuwa**：3D 知识 orbit + Pentagon 提炼 + SKILL.md typewriter + 「21 分钟」hero reveal
  - **Darwin**：autoresearch loop spin + v1/v5 并列 diff + Hill-Climb 全屏曲线 + Ratchet gear lock
- 每个 cinematic 默认显示**完整静态 workflow dashboard**（观众随时能看清 skill 怎么跑），点 ▶ 才触发动画，跑完自动 fade 回 dashboard
- 嵌入 huasheng.ai 的 25 秒 hero 动画（iframe 本地化兜底）
- 真实数据：14,495 stargazers 真实曲线（gh API 拉取）+ DeepSeek V4 真实 specs（WebSearch 验证）
- 真实 AI 素材：用 `huashu-gpt-image` 跑 4×2 grid 大图，`extract_grid.py` 抠出 8 张独立透明 PNG，做 3D orbit 漂浮

**适合参考的页面**：
- `/slides/slide-04b-nuwa-flow.html` · 静态 dashboard + cinematic overlay 双层架构
- `/slides/slide-06b-darwin-flow.html` · 完全独立视觉语言的对照案例
- `/slides/slide-03b-deepseek-cover.html` · AI slop vs 真实设计师视角的对比页

详细 cinematic patterns 见 `references/cinematic-patterns.md`。

---

## 核心机制

### 品牌资产协议

skill 里最硬的一段规则。涉及具体品牌（Stripe、Linear、Anthropic、自家公司等）时强制执行 5 步：

| 步骤 | 动作 | 目的 |
|------|------|------|
| 1 · 问 | 用户有 brand guidelines 吗？ | 尊重已有资源 |
| 2 · 搜官方品牌页 | `<brand>.com/brand` · `brand.<brand>.com` · `<brand>.com/press` | 抓权威色值 |
| 3 · 下载资产 | SVG 文件 → 官网 HTML 全文 → 产品截图取色 | 三条兜底，前一条失败立刻走下一条 |
| 4 · grep 提取色值 | 从资产里抓所有 `#xxxxxx`，按频率排序，过滤黑白灰 | **绝不从记忆猜品牌色** |
| 5 · 固化 spec | 写 `brand-spec.md` + CSS 变量，所有 HTML 引用 `var(--brand-*)` | 不固化就会忘 |

A/B 测试（v1 vs v2，各跑 6 agent）：**v2 的稳定性方差比 v1 低 5 倍**。稳定性的稳定性，这是 skill 真正的护城河。

### 设计方向顾问（Fallback）

当用户需求模糊到无法着手时触发（3.0 重做）：

- 先对话澄清 + 主动索要参考（名字 / logo / 品牌色 / 喜欢的参考站），只问一轮
- 取齐内容必需的真图（公共领域 / 免版权，脚本一键抓），再开工
- **三套逻辑各出两个候选，共六个**：① 最佳设计师（两位气质不同的设计师，用他们的思维从头做）② 现实参照（两件**同媒介**的获奖作品——做 App 找 App、做 deck 找出版物；`scripts/ref_board.py` 先截图亲眼看，再拆网格、字号比和色彩比例）③ 秒数轮盘（`date +%S` 取秒，在产出形态对应的分区和中文东亚分区各抽一号，先看样张再动手）
- **六个候选 → 挑三版做完整稿**：单看够好、彼此不一样、不撞你最近的项目；没选上的三个作为备选告诉你，看中哪个再做
- **绝不让你在没看到视觉时盲选风格**——摆出来就停，看着选
- 底层是 **92 种 HTML 原生风格库**，每种配一张样张和源码（`assets/style-specimens/`），作弹药，不是教条

为什么这样做：我们拿固定题目做了三轮改前改后盲选（内部测试）。第一轮强制每版套一个大隐喻，页面被做成道具，4 题只赢 1 题；第二轮为了躲 AI 默认外观加了一堆禁令，三版一起变得「太规整，太无聊」，2 题全输；第三轮改成加选项、不加禁令——多出候选、给看得见的样张、看真参考——同两道题都赢了。

### 越用越懂你：经验、外观账本与设计体检

- **经验**：`scripts/learn.py` 开工前带出你说过的品味原话（「太素了」「A 的结构加 C 的颜色」）和过去的教训，收工时把值得记的记下来；记录前会告诉你，不想记可以拒绝
- **外观账本**：每次交付记一笔「长什么样」（底色、色板、字体、版式骨架，连同项目名和所在路径），下个项目主动避开——单个项目看都不错、放在一起却长得像，这种单调靠它管
- **打磨环**：`scripts/polish.py` 把页面按原尺寸逐屏截图，模型看着自己的截图改一轮再交；它会报「连续几屏只有文字和框」这类事实，打磨记录空着也会提醒。轻量模型或脚本报警时走稳妥轨道（`references/steady-track.md`）：从样张改起、先写逐屏稿、每屏从形式菜单里挑
- **设计体检**：`scripts/design_lint.py` 只量能核对的事实——图裂了、字小到读不了、对比度不够、控制台报错是红灯；全大写小标签、「A · B · C」这类顺手的模板装饰是黄灯；三版是不是换皮、和最近的项目撞没撞，`compare` 和 `ledger check` 来查。好不好看归你判断，它不打分
- 这些记录只存在你本机的 `~/.huashu-design/`，不随 skill 分发，删掉文件夹就全部忘记

### Junior Designer 工作流

默认工作模式，贯穿所有任务：

- 开工前 show 问题清单一次性发给用户，等批量答完再动手
- HTML 里先写 assumptions + placeholders + reasoning comments
- 尽早 show 给用户（哪怕只是灰色方块）
- 填充实际内容 → variations → Tweaks 这三步分别再 show 一次
- 交付前用 Playwright 肉眼过一遍浏览器

### 反 AI slop 规则

避免一眼 AI 的视觉最大公约数：紫渐变、emoji 图标、圆角+左 border accent、SVG 画人脸、Inter 做 display，以及 2026 年的新一代模板装饰（每个标题上一行全大写小标签、「A · B · C」中点连接、按钮尾巴的「→」、标题只给一个词换色）。不编造数据、评价和 logo 墙。

暖纸衬线、深底单点缀这类「外观家族」不在禁令里：盲选里被用户认可的几版，恰好就有这两类。真正要避免的是三版挤在同一个家族、每个项目都长一个样——那交给外观账本。

---

## 和 Claude Design 的关系

我大方承认：品牌资产协议的哲学是从 Claude Design 流传出来的提示词里偷师的。那份提示词反复强调**好的高保真设计不是从白纸开始，而是从已有的设计上下文长出来**。这个原则是 65 分作品和 90 分作品的分水岭。

定位差异：

| | Claude Design | huashu-design |
|---|---|---|
| 形态 | 网页产品（浏览器里用） | skill（Claude Code 里用） |
| 配额 | 订阅 quota | API 消耗 · 并行跑 agent 不受 quota 限 |
| 交付物 | 画布内 + 可导 Figma | HTML / MP4 / GIF / 可编辑 PPTX / PDF |
| 操作方式 | GUI（点、拖、改） | 对话（说话、等 agent 做完） |
| 复杂动画 | 有限 | Stage + Sprite 时间轴 · 60fps 导出 |
| 跨 agent | 专属 Claude.ai | 任意 skill 兼容 agent |

Claude Design 是**更好的图形工具**，huashu-design 是**让图形工具这层消失**。两条路，不同受众。

---

## 安全与数据流

核心链路（设计→渲染→MP4/PDF/PPTX导出）**100%本地运行，零网络零key**。云能力（豆包TTS配音、AI看片评审）全部隔离在 `scripts/cloud/`，完全可选：用你自己的key、只发对应厂商官方API、首次调用需 `--yes` 显式确认。无telemetry，没有任何数据发往作者服务器。3.0 新增的本机记录（品味经验、外观账本）只写在 `~/.huashu-design/`，从不上传；参考板只在你让 agent 截参考作品时访问那些网址。全部出站域名、密钥处理、删除边界的穷举声明见 [SECURITY.md](SECURITY.md)，欢迎用你的agent对着代码逐条核验。

---

## Limitations

- **不支持图层级可编辑的 PPTX 到 Figma**。产出 HTML，可截图、录屏、导图，但不能拖进 Keynote 改文字位置。
- **Framer Motion 级别的复杂动画不行**。3D、物理模拟、粒子系统超出 skill 边界。
- **完全空白的品牌从零设计质量会掉到 60–65 分**。凭空画 hi-fi 本来就是 last resort。

这是一个 80 分的 skill，不是 100 分的产品。对不愿意打开图形界面的人，80 分的 skill 比 100 分的产品好用。

---

## 仓库结构

```
huashu-design/
├── SKILL.md                 # 主文档（给 agent 读）
├── README.md                # 中文 README（默认，本文件）
├── README.en.md             # 英文 README
├── test-prompts.json        # 手动冒烟提示词（8 条）
├── assets/                  # Starter Components
│   ├── animations.jsx       # Stage + Sprite + Easing + interpolate
│   ├── ios_frame.jsx        # iPhone 15 Pro bezel
│   ├── android_frame.jsx
│   ├── macos_window.jsx
│   ├── browser_window.jsx
│   ├── deck_stage.js        # HTML 幻灯片引擎
│   ├── deck_index.html      # 多文件 deck 拼接器
│   ├── design_canvas.jsx    # 并排变体展示
│   ├── showcases/           # 24 个预制样例（8 场景 × 3 风格，索引见 INDEX.md）
│   ├── style-specimens/     # 92 种风格的样张（html 源码 + jpg）与分区总览；xhs/ 的样张同时是模板；paradigm/ 是 8 条 App 界面范式
│   ├── appstore/            # App Store 宣传图模板
│   └── bgm-*.mp3            # 6 首场景化背景音乐
├── references/              # 按任务深入读的子文档
│   ├── animation-pitfalls.md
│   ├── directions.md        # 三方向：六个候选 → 挑三版
│   ├── polish-loop.md       # 打磨环：逐屏截图、看图、改一轮
│   ├── steady-track.md      # 稳妥轨道：样张起步、逐屏稿、形式菜单
│   ├── design-styles.md     # 92 种 HTML 原生风格库（网页 20 + PPT 20 + 信息图 20 + App 12 + 中文与东亚 12 + 小红书 8）
│   ├── modules/             # 网页 / deck / 信息图 / 小红书 / App Store 宣传图 / 动画 六个模块手册
│   ├── app-paradigms.md     # App 界面八条范式：两届 App Store Awards 入围作品的拆解与取图 id
│   ├── slide-decks.md
│   ├── editable-pptx.md
│   ├── critique-guide.md
│   ├── video-export.md
│   └── ...
├── scripts/                 # 导出工具链
│   ├── render-video.js      # HTML → MP4
│   ├── xhs_render.py        # 小红书图文 → 3:4 成图 + 体检
│   ├── appstore_shots.py    # 拉真实 App 的商店截图拼成参考板
│   ├── ref_card.py          # 量参考原图的色板与版面；做完和参照并排对回去（借一层，不借一身）
│   ├── gen_image.py         # 不能生图的环境里借本机 Codex 生成素材图，只认真生成的
│   ├── appstore_render.py   # App Store 宣传图 → 可上传成图 + 搜索结果预览 + 体检
│   ├── convert-formats.sh   # MP4 → 60fps + GIF
│   ├── add-music.sh         # MP4 + BGM
│   ├── export_deck_pdf.mjs
│   ├── export_deck_pptx.mjs
│   ├── html2pptx.js
│   ├── design_lint.py       # 设计体检、三版撞色撞骨架、外观账本
│   ├── polish.py            # 打磨环：逐屏截图、打磨记录
│   ├── learn.py             # 品味经验的读写
│   ├── ref_board.py         # 把参考作品截成参考板
│   ├── capabilities.py      # 探测本机能力（生图、兄弟 skill、Node、ffmpeg）
│   ├── verify.py
│   └── tests/               # pytest 回归（python3 -m pytest scripts/tests/ -q）
└── demos/                   # 9 个能力演示 (c*/w*) 中英双版 HTML（动图/视频走 Release 外链）+ hero v10（英文版）
```

---

## 起源

Anthropic 发布 Claude Design 那天我玩到凌晨四点。几天之后发现自己再也没点开过它，不是它不好——它是这个赛道目前最成熟的产品——是我宁愿让 agent 在终端里帮我干活，也不愿意打开任何图形界面。

于是让 agent 拆解 Claude Design 本身（包括社区流传的系统提示词、品牌资产协议、组件机制），蒸馏成结构化 spec，再写成 skill 装进自己的 Claude Code。

感谢 Anthropic 把 Claude Design 的提示词写得清晰。这种基于其他产品灵感的二次创作，是开源文化在 AI 时代的新形态。

---

## 用 huashu-design 做的产品

**[FanBox · Coding Agent 的驾驶舱](https://github.com/alchaincyf/fanbox)** 的三套界面皮肤，就是用 huashu-design 设计的。指挥 Claude Code / Codex 干活，看清它碰过的每个文件、每一行改动。

[![FanBox · Coding Agent 的驾驶舱](https://raw.githubusercontent.com/alchaincyf/fanbox/master/assets/promo-banner.jpg)](https://github.com/alchaincyf/fanbox)

---

## 社区翻译版本

社区维护的翻译版本。翻译质量与各版本 license 条款由对应维护者负责，使用前请先确认。

| 语言 | 维护者 | 仓库 |
|---|---|---|
| English | [@namandhakad712](https://github.com/namandhakad712) | [namandhakad712/huashu-design-en](https://github.com/namandhakad712/huashu-design-en) |
| 한국어（韩语） | [@ktkarchive](https://github.com/ktkarchive) | [ktkarchive/ktk-design](https://github.com/ktkarchive/ktk-design) |
| Tiếng Việt（越南语） | [@letrquan](https://github.com/letrquan) | [letrquan/huashu-design](https://github.com/letrquan/huashu-design) |

想加你的语言？fork 仓库、翻译 `SKILL.md` + `README.md`，然后回这边开个 issue，我会把链接加进来。

---

## License

**2026-05-14 起改为 MIT 协议。** 此前版本采用「个人使用免费、企业商用需授权」的 Personal Use License，对商用做了限制——现在这层限制完全解除。

按 [MIT License](LICENSE)，你可以**自由使用、修改、分发**本 skill，**包括商业用途**——公司内部用、客户商单交付、做成付费产品对外卖，都没问题。无需事先授权、无需付费、无需打招呼。注明出处不强制，但欢迎。

唯一例外：`assets/style-specimens/xhs/_kit/stickers/` 里的演示贴纸来自 [huashu-bird-sticker](https://github.com/alchaincyf/huashu-bird-sticker)，按 PolyForm Shield 1.0.0 授权（见该文件夹的 LICENSE.md），只用来演示版式，你的作品请换成自己的素材。

---

## Connect · 花生（花叔）

花生是 AI Native Coder、独立开发者、AI 自媒体博主。代表作：小猫补光灯（AppStore 付费榜 Top 1）、《一本书玩转 DeepSeek》、女娲 .skill（GitHub 3 万+ star）。自媒体全平台 30 万+ 粉丝。

| 平台 | 账号 | 链接 |
|---|---|---|
| X / Twitter | @AlchainHust | https://x.com/AlchainHust |
| 公众号 | 花叔 | 微信搜索「花叔」 |
| B 站 | 花叔 | https://space.bilibili.com/14097567 |
| YouTube | 花叔 | https://www.youtube.com/@Alchain |
| 小红书 | 花叔 | https://www.xiaohongshu.com/user/profile/5abc6f17e8ac2b109179dfdf |
| 官网 | huasheng.ai | https://www.huasheng.ai/ |
| 开发者主页 | bookai.top | https://bookai.top |

合作咨询、自媒体约稿 → 以上任一平台私信花生即可。

<p align="center"><img src="https://raw.githubusercontent.com/alchaincyf/alchaincyf/main/assets/follow.svg" width="100%" alt="关注花叔：公众号「花叔」· B站「花叔v」· 小红书「花叔」"></p>
