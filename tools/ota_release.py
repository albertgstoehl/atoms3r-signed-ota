#!/usr/bin/env python3
"""Create and verify signed AtomS3R OTA releases.

Production private keys must be generated and retained only in the local/private
qwen36 environment. This script never prints private-key material.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with tmp.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def canonical_payload(version: int, size: int, sha256: str, url: str) -> bytes:
    return (
        f"version={version}\n"
        f"size={size}\n"
        f"sha256={sha256.lower()}\n"
        f"url={url}\n"
    ).encode("ascii")


def parse_manifest(path: Path) -> tuple[bytes, bytes, dict[str, str]]:
    raw = path.read_text(encoding="ascii")
    lines = raw.splitlines()
    expected = ["version", "size", "sha256", "url", "signature"]
    if len(lines) != len(expected):
        raise ValueError("manifest must contain exactly five lines")
    values: dict[str, str] = {}
    for line, key in zip(lines, expected, strict=True):
        prefix = key + "="
        if not line.startswith(prefix) or not line[len(prefix) :]:
            raise ValueError(f"invalid {key} line")
        values[key] = line[len(prefix) :]
    version = int(values["version"])
    size = int(values["size"])
    digest = values["sha256"].lower()
    if version <= 0 or size <= 0 or len(digest) != 64:
        raise ValueError("invalid version, size, or SHA-256")
    if urlparse(values["url"]).scheme != "https":
        raise ValueError("firmware URL must use HTTPS")
    payload = canonical_payload(version, size, digest, values["url"])
    signature = base64.b64decode(values["signature"], validate=True)
    return payload, signature, values


def command_generate(args: argparse.Namespace) -> None:
    private_path = Path(args.private)
    public_path = Path(args.public)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing key")
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    atomic_write(private_path, private_pem, 0o600)
    atomic_write(public_path, public_pem, 0o644)
    print(f"created private key: {private_path} (mode 0600)")
    print(f"created public key:  {public_path}")


def command_header(args: argparse.Namespace) -> None:
    public_pem = Path(args.public).read_text(encoding="ascii").strip() + "\n"
    serialization.load_pem_public_key(public_pem.encode("ascii"))
    header = (
        "#pragma once\n\n"
        "static constexpr char OTA_SIGNING_PUBLIC_KEY[] = R\"PEM(\n"
        f"{public_pem}"
        ")PEM\";\n"
    ).encode("ascii")
    atomic_write(Path(args.output), header, 0o644)
    print(f"wrote public-key header: {args.output}")


def command_release(args: argparse.Namespace) -> None:
    version = int(args.version)
    if version <= 0:
        raise ValueError("version must be positive")
    source = Path(args.firmware)
    firmware = source.read_bytes()
    if not firmware:
        raise ValueError("firmware is empty")
    digest = hashlib.sha256(firmware).hexdigest()
    filename = f"atoms3r-v{version}.bin"
    base_url = args.base_url.rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("base URL must be an absolute HTTPS URL")
    url = f"{base_url}/{filename}"
    payload = canonical_payload(version, len(firmware), digest, url)
    private_key = serialization.load_pem_private_key(
        Path(args.private).read_bytes(), password=None
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ValueError("signing key must be ECDSA P-256")
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    manifest = payload + b"signature=" + base64.b64encode(signature) + b"\n"

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    firmware_path = output / filename
    manifest_path = output / "manifest.txt"
    atomic_write(firmware_path, firmware, 0o644)
    # Publish manifest last so clients never observe it before the binary exists.
    atomic_write(manifest_path, manifest, 0o644)
    print(f"firmware: {firmware_path}")
    print(f"manifest: {manifest_path}")
    print(f"version={version} size={len(firmware)} sha256={digest}")


def command_verify(args: argparse.Namespace) -> None:
    payload, signature, values = parse_manifest(Path(args.manifest))
    public_key = serialization.load_pem_public_key(Path(args.public).read_bytes())
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("verification key must be ECDSA P-256")
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    firmware = Path(args.firmware).read_bytes()
    actual = hashlib.sha256(firmware).hexdigest()
    if len(firmware) != int(values["size"]):
        raise ValueError("firmware size does not match manifest")
    if actual != values["sha256"].lower():
        raise ValueError("firmware SHA-256 does not match manifest")
    print(
        f"verified version={values['version']} size={len(firmware)} sha256={actual}"
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate-key")
    generate.add_argument("--private", required=True)
    generate.add_argument("--public", required=True)
    generate.set_defaults(func=command_generate)

    header = sub.add_parser("make-header")
    header.add_argument("--public", required=True)
    header.add_argument("--output", required=True)
    header.set_defaults(func=command_header)

    release = sub.add_parser("release")
    release.add_argument("--private", required=True)
    release.add_argument("--firmware", required=True)
    release.add_argument("--version", required=True, type=int)
    release.add_argument("--base-url", required=True)
    release.add_argument("--output-dir", required=True)
    release.set_defaults(func=command_release)

    verify = sub.add_parser("verify")
    verify.add_argument("--public", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--firmware", required=True)
    verify.set_defaults(func=command_verify)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.func(args)
        return 0
    except (ValueError, OSError, InvalidSignature) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
