from __future__ import annotations

import argparse
import ipaddress
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import types
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence


if __name__ not in sys.modules:
    sys.modules[__name__] = types.ModuleType(__name__)


DOMAIN_RE = re.compile(
    r"(?<![@A-Za-z0-9_-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?![A-Za-z0-9_-])"
)
XML_HOST_RE = re.compile(r"<host>([^<]+)</host>", re.IGNORECASE)
XML_PORT_RE = re.compile(r"<port>(\d{2,5})</port>", re.IGNORECASE)
LABELED_HOST_RE = re.compile(r"[`'\"]?host[`'\"]?\s*[:=]\s*[`'\"]?([0-9.; ]{7,})", re.IGNORECASE)
LABELED_PORT_RE = re.compile(r"[`'\"]?port[`'\"]?\s*[:=]\s*[`'\"]?(\d{2,5})", re.IGNORECASE)
URL_RE = re.compile(r"\b(https?)://([A-Za-z0-9.-]+)(?::(\d{2,5}))?(?:[/?#]|$)", re.IGNORECASE)
DOMAIN_PORT_RE = re.compile(r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}):(\d{2,5})\b")
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")
LOGON_XML_RE = re.compile(r"(?is)<logon\b[^>]*>.*?</logon>")

HOSTS_BLOCK_BEGIN = "# >>> RF4 MONITOR BEGIN"
HOSTS_BLOCK_END = "# <<< RF4 MONITOR END"
LEGACY_HOSTS_BLOCK_BEGIN = "# >>> RF4 MITM CHAT BEGIN"
LEGACY_HOSTS_BLOCK_END = "# <<< RF4 MITM CHAT END"
HOSTS_BLOCK_BEGIN_MARKERS = {HOSTS_BLOCK_BEGIN, LEGACY_HOSTS_BLOCK_BEGIN}
HOSTS_BLOCK_END_MARKERS = {HOSTS_BLOCK_END, LEGACY_HOSTS_BLOCK_END}
TEXT_SUFFIXES = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
DEFAULT_DOMAIN_SUFFIXES = ("rf4game.ru", "rf4game.com")
PREFERRED_REVERSE_HOSTS = ("api.rf4game.ru",)


@dataclass(frozen=True)
class ReferenceTrafficInfo:
    domains: tuple[str, ...]
    realtime_hosts: tuple[str, ...]
    realtime_port: int | None
    reverse_targets: tuple["ReverseProxyTarget", ...]
    https_upstream_overrides: tuple["HttpsUpstreamOverride", ...]
    source_files: tuple[Path, ...]


@dataclass(frozen=True)
class HostsUpdateResult:
    path: Path
    backup_path: Path | None
    entries: tuple[str, ...]
    updated: bool


@dataclass(frozen=True)
class GeneratedCertificate:
    cert_path: Path
    key_path: Path
    pem_path: Path
    common_name: str
    domains: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ReverseProxyTarget:
    scheme: str
    host: str
    upstream_port: int
    listen_port: int

    def mode_spec(self) -> str:
        return f"reverse:{self.scheme}://{self.host}:{self.upstream_port}@{self.listen_port}"


@dataclass(frozen=True, order=True)
class HttpsUpstreamOverride:
    domain: str
    connect_host: str
    port: int = 443


@dataclass(frozen=True)
class LoginLogonInfo:
    hosts: tuple[str, ...]
    port: int
    region: str | None
    server: str | None
    userid: str | None
    token: str | None


@dataclass(frozen=True)
class LoginRewriteResult:
    text: str
    original: LoginLogonInfo
    redirected_hosts: tuple[str, ...]
    redirected_port: int


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
BUNDLED_REFERENCE_PATH = THIS_DIR / "reference_defaults.txt"


def default_reference_paths(repo_root: Path) -> list[Path]:
    return [repo_root / "数据包"]


def default_hosts_path() -> Path:
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        return system_root / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def extract_reference_info(
    paths: Sequence[Path],
    *,
    include_all_domains: bool = False,
    allowed_domain_suffixes: Sequence[str] = DEFAULT_DOMAIN_SUFFIXES,
    max_scan_bytes: int = 2_000_000,
) -> ReferenceTrafficInfo:
    domains: set[str] = set()
    realtime_hosts: list[str] = []
    reverse_targets: set[ReverseProxyTarget] = set()
    https_upstream_overrides: set[HttpsUpstreamOverride] = set()
    realtime_port: int | None = None
    source_files: list[Path] = []

    for file_path in iter_reference_text_files(paths):
        text = safe_read_text(file_path, max_scan_bytes=max_scan_bytes)
        if text is None:
            continue
        source_files.append(file_path)
        domains.update(extract_domains_from_text(text))
        extend_unique(realtime_hosts, extract_realtime_hosts_from_text(text))
        reverse_targets.update(extract_reverse_targets_from_text(text))
        https_upstream_overrides.update(extract_https_upstream_overrides_from_text(text))
        if realtime_port is None:
            realtime_port = extract_realtime_port_from_text(text)

    filtered_domains = sorted(
        domain
        for domain in domains
        if include_all_domains or domain_matches_suffixes(domain, allowed_domain_suffixes)
    )
    filtered_reverse_target_set = {
        target
        for target in reverse_targets
        if include_all_domains or domain_matches_suffixes(target.host, allowed_domain_suffixes)
    }
    filtered_reverse_target_set.update(infer_default_reverse_targets(filtered_domains))
    filtered_reverse_targets = tuple(sorted(filtered_reverse_target_set))
    filtered_https_upstream_overrides = tuple(
        sorted(
            override
            for override in https_upstream_overrides
            if include_all_domains or domain_matches_suffixes(override.domain, allowed_domain_suffixes)
        )
    )

    return ReferenceTrafficInfo(
        domains=tuple(filtered_domains),
        realtime_hosts=tuple(realtime_hosts),
        realtime_port=realtime_port,
        reverse_targets=filtered_reverse_targets,
        https_upstream_overrides=filtered_https_upstream_overrides,
        source_files=tuple(source_files),
    )


def iter_reference_text_files(paths: Sequence[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for path in paths:
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            continue
        if resolved.is_file():
            if resolved not in seen and should_scan_file(resolved):
                seen.add(resolved)
                yield resolved
            continue
        for file_path in sorted(resolved.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path in seen or not should_scan_file(file_path):
                continue
            seen.add(file_path)
            yield file_path


def should_scan_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def safe_read_text(path: Path, *, max_scan_bytes: int) -> str | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_scan_bytes)
    except OSError:
        return None
    return raw.decode("utf-8", errors="ignore")


def extract_domains_from_text(text: str) -> set[str]:
    domains = {match.group(1).strip(".").lower() for match in DOMAIN_RE.finditer(text)}
    return {domain for domain in domains if "." in domain}


def extract_realtime_hosts_from_text(text: str) -> tuple[str, ...]:
    hosts: list[str] = []
    for match in XML_HOST_RE.finditer(text):
        extend_unique(hosts, split_ip_list(match.group(1)))
    for match in LABELED_HOST_RE.finditer(text):
        extend_unique(hosts, split_ip_list(match.group(1)))
    return tuple(hosts)


def extract_realtime_port_from_text(text: str) -> int | None:
    for regex in (XML_PORT_RE, LABELED_PORT_RE):
        match = regex.search(text)
        if not match:
            continue
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return None


def extract_reverse_targets_from_text(text: str) -> set[ReverseProxyTarget]:
    targets: set[ReverseProxyTarget] = set()
    for match in URL_RE.finditer(text):
        scheme = match.group(1).lower()
        host = match.group(2).lower()
        port = int(match.group(3)) if match.group(3) else (443 if scheme == "https" else 80)
        if scheme == "https" and port == 443:
            targets.add(ReverseProxyTarget(scheme=scheme, host=host, upstream_port=port, listen_port=port))

    for match in DOMAIN_PORT_RE.finditer(text):
        host = match.group(1).lower()
        port = int(match.group(2))
        if port == 443:
            targets.add(ReverseProxyTarget(scheme="https", host=host, upstream_port=443, listen_port=443))

    return targets


def extract_https_upstream_overrides_from_text(text: str) -> set[HttpsUpstreamOverride]:
    overrides: set[HttpsUpstreamOverride] = set()
    for raw_line in text.splitlines():
        if "<->" not in raw_line:
            continue
        domain_match = DOMAIN_PORT_RE.search(raw_line)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower()
        port = int(domain_match.group(2))
        if port != 443:
            continue

        connect_host = ""
        for candidate_host, candidate_port in IP_PORT_RE.findall(raw_line):
            if candidate_port != "443":
                continue
            try:
                ipaddress.ip_address(candidate_host)
            except ValueError:
                continue
            connect_host = candidate_host

        if connect_host:
            overrides.add(HttpsUpstreamOverride(domain=domain, connect_host=connect_host, port=443))
    return overrides


def infer_default_reverse_targets(domains: Sequence[str]) -> list[ReverseProxyTarget]:
    return [ReverseProxyTarget(scheme="https", host=domain, upstream_port=443, listen_port=443) for domain in domains]


def select_reverse_targets(targets: Sequence[ReverseProxyTarget]) -> tuple[ReverseProxyTarget, ...]:
    selected_by_port: dict[int, ReverseProxyTarget] = {}
    for target in sorted(targets, key=_reverse_target_priority):
        if target.listen_port in selected_by_port:
            continue
        selected_by_port[target.listen_port] = target
    return tuple(sorted(selected_by_port.values()))


def managed_proxy_domains(domains: Sequence[str], reverse_targets: Sequence[ReverseProxyTarget]) -> tuple[str, ...]:
    selected_hosts = tuple(sorted({target.host for target in select_reverse_targets(reverse_targets)}))
    if selected_hosts:
        return selected_hosts
    return tuple(sorted({domain.lower() for domain in domains if domain.strip()}))


def _reverse_target_priority(target: ReverseProxyTarget) -> tuple[int, int, str, int]:
    if target.host in PREFERRED_REVERSE_HOSTS:
        host_rank = 0
    elif target.host.endswith(".rf4game.ru"):
        host_rank = 1
    elif target.host.endswith(".rf4game.com"):
        host_rank = 2
    else:
        host_rank = 3
    scheme_rank = 0 if target.scheme == "https" else 1
    return (host_rank, scheme_rank, target.host, target.upstream_port)


def select_https_upstream_overrides(
    overrides: Sequence[HttpsUpstreamOverride],
    reverse_targets: Sequence[ReverseProxyTarget],
) -> tuple[HttpsUpstreamOverride, ...]:
    selected_hosts = {
        target.host
        for target in select_reverse_targets(reverse_targets)
        if target.scheme in ("https", "tls")
    }
    selected_by_domain: dict[str, HttpsUpstreamOverride] = {}
    for override in sorted(overrides):
        if selected_hosts and override.domain not in selected_hosts:
            continue
        selected_by_domain.setdefault(override.domain, override)
    return tuple(sorted(selected_by_domain.values()))


def build_https_upstream_map_option(overrides: Sequence[HttpsUpstreamOverride]) -> str:
    return ";".join(f"{override.domain}={override.connect_host}" for override in overrides)


def parse_https_upstream_map(raw_value: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for chunk in re.split(r"[;,]", raw_value):
        entry = chunk.strip()
        if not entry or "=" not in entry:
            continue
        domain, connect_host = entry.split("=", 1)
        normalized_domain = domain.strip().lower()
        normalized_host = connect_host.strip()
        if not normalized_domain or not normalized_host:
            continue
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError:
            continue
        mapping[normalized_domain] = normalized_host
    return mapping


def split_ip_list(raw: str) -> tuple[str, ...]:
    out: list[str] = []
    for candidate in split_host_list(raw):
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in out:
            out.append(candidate)
    return tuple(out)


def extend_unique(target: list[str], values: Iterable[str]) -> None:
    seen = set(target)
    for value in values:
        if value in seen:
            continue
        target.append(value)
        seen.add(value)


def split_host_list(raw: str) -> tuple[str, ...]:
    hosts = []
    for value in raw.split(";"):
        candidate = value.strip().strip("`'\"")
        if candidate:
            hosts.append(candidate)
    return tuple(hosts)


def parse_login_logon_info(text: str) -> LoginLogonInfo | None:
    fragment = extract_logon_xml_fragment(text)
    if fragment is None:
        return None
    try:
        root = ET.fromstring(fragment)
    except ET.ParseError:
        return None

    host_text = (root.findtext("host") or "").strip()
    port_text = (root.findtext("port") or "").strip()
    if not host_text or not port_text:
        return None

    try:
        port = int(port_text)
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None

    hosts = split_host_list(host_text)
    if not hosts:
        return None

    return LoginLogonInfo(
        hosts=hosts,
        port=port,
        region=_optional_xml_text(root, "region"),
        server=_optional_xml_text(root, "server"),
        userid=_optional_xml_text(root, "userid"),
        token=_optional_xml_text(root, "token"),
    )


def rewrite_login_logon_info(
    text: str,
    *,
    redirect_host: str,
    redirect_port: int,
    repeat_host_count: bool = True,
) -> LoginRewriteResult | None:
    if not redirect_host.strip():
        raise ValueError("redirect_host must not be empty")
    if not (1 <= redirect_port <= 65535):
        raise ValueError("redirect_port must be between 1 and 65535")

    fragment_match = LOGON_XML_RE.search(text)
    if not fragment_match:
        return None
    original = parse_login_logon_info(fragment_match.group(0))
    if original is None:
        return None

    try:
        root = ET.fromstring(fragment_match.group(0))
    except ET.ParseError:
        return None

    host_element = root.find("host")
    port_element = root.find("port")
    if host_element is None or port_element is None:
        return None

    redirected_hosts = build_redirect_host_list(
        redirect_host,
        original_count=len(original.hosts),
        repeat_host_count=repeat_host_count,
    )
    host_element.text = ";".join(redirected_hosts)
    port_element.text = str(redirect_port)
    rewritten_fragment = ET.tostring(root, encoding="unicode", method="xml")
    rewritten_text = text[:fragment_match.start()] + rewritten_fragment + text[fragment_match.end():]

    return LoginRewriteResult(
        text=rewritten_text,
        original=original,
        redirected_hosts=redirected_hosts,
        redirected_port=redirect_port,
    )


def build_redirect_host_list(
    redirect_host: str,
    *,
    original_count: int,
    repeat_host_count: bool,
) -> tuple[str, ...]:
    count = max(1, original_count if repeat_host_count else 1)
    return tuple(redirect_host for _ in range(count))


def extract_logon_xml_fragment(text: str) -> str | None:
    match = LOGON_XML_RE.search(text)
    if not match:
        return None
    return match.group(0)


def _optional_xml_text(root: ET.Element, tag: str) -> str | None:
    value = root.findtext(tag)
    if value is None:
        return None
    value = value.strip()
    return value or None


def domain_matches_suffixes(domain: str, suffixes: Sequence[str]) -> bool:
    normalized = domain.lower()
    return any(normalized == suffix or normalized.endswith(f".{suffix}") for suffix in suffixes)


def build_tcp_hosts_regex(hosts: Sequence[str], port: int | None) -> str | None:
    normalized = [host.strip() for host in hosts if host.strip()]
    if not normalized:
        return None
    host_group = "|".join(re.escape(host) for host in normalized)
    if port is not None:
        return rf"^(?:{host_group})(?::{port})?$"
    return rf"^(?:{host_group})(?::\d+)?$"


def update_hosts_file(
    path: Path,
    target_ip: str,
    domains: Sequence[str],
    *,
    dry_run: bool = False,
) -> HostsUpdateResult:
    ordered_domains = tuple(sorted({domain.lower() for domain in domains if domain.strip()}))
    entries = tuple(f"{target_ip} {domain}" for domain in ordered_domains)
    block = render_hosts_block(entries)

    existing = ""
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="ignore")
    updated_text = replace_hosts_block(existing, block)
    changed = updated_text != existing
    backup_path: Path | None = None

    if changed and not dry_run:
        if path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = path.with_name(f"{path.name}.rf4_monitor.{timestamp}.bak")
            shutil.copy2(path, backup_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(updated_text, encoding="utf-8")

    return HostsUpdateResult(
        path=path,
        backup_path=backup_path,
        entries=entries,
        updated=changed,
    )


def render_hosts_block(entries: Sequence[str]) -> str:
    return "\n".join([HOSTS_BLOCK_BEGIN, *entries, HOSTS_BLOCK_END])


def replace_hosts_block(existing_text: str, block: str) -> str:
    normalized = existing_text.rstrip("\n")
    lines = normalized.splitlines() if normalized else []

    output: list[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped in HOSTS_BLOCK_BEGIN_MARKERS:
            in_block = True
            continue
        if stripped in HOSTS_BLOCK_END_MARKERS:
            in_block = False
            continue
        if not in_block:
            output.append(line)

    while output and output[-1] == "":
        output.pop()
    if output:
        output.append("")
    output.extend(block.splitlines())
    return "\n".join(output) + "\n"


def generate_self_signed_certificate(
    cert_dir: Path,
    domains: Sequence[str],
    *,
    common_name: str | None = None,
    days: int = 3650,
    force: bool = False,
) -> GeneratedCertificate:
    normalized_domains = tuple(sorted({domain for domain in domains if domain.strip()}))
    if not normalized_domains:
        raise ValueError("cannot generate a certificate without at least one domain")

    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "rf4_monitor.key"
    cert_path = cert_dir / "rf4_monitor.crt"
    pem_path = cert_dir / "rf4_monitor.pem"
    final_common_name = common_name or normalized_domains[0]

    if force or not (key_path.exists() and cert_path.exists() and pem_path.exists()):
        openssl = shutil.which("openssl")
        if not openssl:
            raise FileNotFoundError("openssl executable not found in PATH")
        san_value = ",".join(f"DNS:{domain}" for domain in normalized_domains)
        command = [
            openssl,
            "req",
            "-x509",
            "-sha256",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            str(days),
            "-subj",
            f"/CN={final_common_name}",
            "-addext",
            f"subjectAltName={san_value}",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"openssl certificate generation failed: {stderr}")
        pem_path.write_text(
            key_path.read_text(encoding="utf-8") + cert_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    return GeneratedCertificate(
        cert_path=cert_path,
        key_path=key_path,
        pem_path=pem_path,
        common_name=final_common_name,
        domains=normalized_domains,
    )


def quote_command(args: Sequence[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(args))
    return shlex.join(list(args))


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Run RF4 Monitor as a single entrypoint. By default the launcher auto-updates hosts, prepares certs, rewrites login realtime targets, and starts mitmdump."
    )
    parser.add_argument(
        "--reference-path",
        action="append",
        dest="reference_paths",
        help="File or directory used to extract RF4 domains and realtime hosts. Defaults to the repo 数据包 directory.",
    )
    parser.add_argument(
        "--include-all-domains",
        action="store_true",
        help="Do not filter extracted domains to RF4-owned suffixes.",
    )
    parser.add_argument(
        "--apply-hosts",
        action="store_true",
        help="Compatibility flag. Hosts update is enabled by default; use --skip-hosts to disable it.",
    )
    parser.add_argument(
        "--hosts-file",
        default=str(default_hosts_path()),
        help="Hosts file path to update. Defaults to the current OS hosts path.",
    )
    parser.add_argument(
        "--hosts-target",
        default="127.0.0.1",
        help="IP address written for each extracted domain when --apply-hosts is enabled.",
    )
    parser.add_argument(
        "--hosts-dry-run",
        action="store_true",
        help="Preview the hosts block without writing it to disk.",
    )
    parser.add_argument(
        "--update-hosts-only",
        action="store_true",
        help="Only update the managed hosts block and exit without preparing certs or starting mitmdump.",
    )
    parser.add_argument(
        "--generate-cert",
        action="store_true",
        help="Compatibility flag. Certificate preparation is enabled by default; use --skip-cert to disable it.",
    )
    parser.add_argument(
        "--cert-dir",
        default=str(THIS_DIR / "certs"),
        help="Output directory for the generated certificate bundle.",
    )
    parser.add_argument(
        "--cert-common-name",
        default="",
        help="Override the certificate common name. Defaults to the first extracted domain.",
    )
    parser.add_argument(
        "--cert-days",
        type=int,
        default=3650,
        help="Certificate validity period in days.",
    )
    parser.add_argument(
        "--force-cert",
        action="store_true",
        help="Regenerate the certificate even if the files already exist.",
    )
    parser.add_argument(
        "--skip-hosts",
        action="store_true",
        help="Do not update the hosts file automatically.",
    )
    parser.add_argument(
        "--skip-cert",
        action="store_true",
        help="Do not prepare the self-signed certificate automatically.",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Prepare hosts/certs and print the mitmdump command without starting it.",
    )
    parser.add_argument(
        "--print-command-only",
        action="store_true",
        help="Alias for --prepare-only that only prints the final command and exits.",
    )
    parser.add_argument(
        "--no-auto-tcp-hosts",
        action="store_true",
        help="Do not derive --tcp-hosts from the reference realtime server list.",
    )
    parser.add_argument(
        "--no-auto-reverse-modes",
        action="store_true",
        help="Do not derive reverse listener modes from extracted RF4 domains.",
    )
    parser.add_argument(
        "--no-auto-realtime-mode",
        action="store_true",
        help="Do not derive a reverse TCP listener for the realtime game socket.",
    )
    parser.add_argument(
        "--no-auto-login-rewrite",
        action="store_true",
        help="Do not inject realtime host/port rewrite options into the mitm addon.",
    )
    parser.add_argument(
        "--realtime-listen-host",
        default="127.0.0.1",
        help="Host value written back into the login logon response for the realtime socket.",
    )
    parser.add_argument(
        "--realtime-listen-port",
        type=int,
        default=0,
        help="Local port written back into the login logon response. Defaults to the extracted realtime port.",
    )
    parser.add_argument(
        "--realtime-upstream-host",
        default="",
        help="Override the realtime upstream host used by the reverse TCP listener.",
    )
    parser.add_argument(
        "--realtime-upstream-port",
        type=int,
        default=0,
        help="Override the realtime upstream port used by the reverse TCP listener.",
    )
    parser.add_argument(
        "--no-auto-verbose",
        action="store_true",
        help="Do not append the default parser-visible logging options.",
    )
    parser.add_argument(
        "--mitmdump-bin",
        default="",
        help="Path to the mitmdump executable. Defaults to tools/rf4_monitor/.venv/bin/mitmdump when available, otherwise PATH.",
    )
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    args, passthrough = parse_args(list(sys.argv[1:] if argv is None else argv))
    reference_paths = resolve_reference_paths(args.reference_paths)
    reference = extract_reference_info(reference_paths, include_all_domains=args.include_all_domains)
    selected_reverse_targets = select_reverse_targets(reference.reverse_targets)
    managed_domains = managed_proxy_domains(reference.domains, reference.reverse_targets)
    if args.update_hosts_only and not managed_domains:
        print("[rf4-monitor-runner] error: no RF4 domains were found in the reference paths.", file=sys.stderr)
        return 2
    auto_apply_hosts = not args.skip_hosts
    auto_generate_cert = not args.skip_cert

    selected_https_upstream_overrides = select_https_upstream_overrides(
        reference.https_upstream_overrides,
        selected_reverse_targets,
    )
    print_reference_summary(
        reference,
        selected_reverse_targets=selected_reverse_targets,
        selected_https_upstream_overrides=selected_https_upstream_overrides,
    )

    if auto_apply_hosts or args.apply_hosts or args.hosts_dry_run:
        try:
            hosts_result = update_hosts_file(
                Path(args.hosts_file).expanduser(),
                args.hosts_target,
                managed_domains,
                dry_run=args.hosts_dry_run,
            )
        except OSError as exc:
            if args.apply_hosts:
                print(
                    f"[rf4-monitor-runner] error: failed to update hosts file {args.hosts_file}: {exc}",
                    file=sys.stderr,
                )
                return 2
            print(
                f"[rf4-monitor-runner] warning: failed to auto-update hosts file {args.hosts_file}: {exc}. "
                "Continue only if the RF4 domains are already mapped to the local machine, or rerun with elevated privileges.",
                file=sys.stderr,
            )
        else:
            print_hosts_summary(hosts_result, dry_run=args.hosts_dry_run)
            if args.update_hosts_only:
                return 0

    certificate = None
    if auto_generate_cert or args.generate_cert:
        try:
            certificate = generate_self_signed_certificate(
                Path(args.cert_dir).expanduser(),
                managed_domains,
                common_name=args.cert_common_name or None,
                days=args.cert_days,
                force=args.force_cert,
            )
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            if args.generate_cert:
                print(f"[rf4-monitor-runner] error: failed to prepare certificate: {exc}", file=sys.stderr)
                return 2
            print(
                f"[rf4-monitor-runner] warning: failed to auto-prepare certificate: {exc}. "
                "HTTPS login interception may fail unless a usable certificate is already configured.",
                file=sys.stderr,
            )
        else:
            print_certificate_summary(certificate)

    command = build_mitmdump_command(
        reference,
        passthrough,
        certificate,
        auto_verbose=not args.no_auto_verbose,
        auto_tcp_hosts=not args.no_auto_tcp_hosts,
        auto_reverse_modes=not args.no_auto_reverse_modes,
        auto_realtime_mode=not args.no_auto_realtime_mode,
        auto_login_rewrite=not args.no_auto_login_rewrite,
        realtime_listen_host=args.realtime_listen_host,
        realtime_listen_port=args.realtime_listen_port,
        realtime_upstream_host=args.realtime_upstream_host,
        realtime_upstream_port=args.realtime_upstream_port,
    )
    command[0] = resolve_mitmdump_binary(args.mitmdump_bin)
    print(f"[rf4-monitor-runner] command: {quote_command(command)}")

    if args.prepare_only or args.print_command_only:
        return 0

    if not mitmdump_binary_exists(command[0]):
        print(
            f"[rf4-monitor-runner] error: '{command[0]}' was not found in PATH. "
            "Install mitmproxy first, or use the bundled tools/rf4_monitor/.venv environment.",
            file=sys.stderr,
        )
        return 2

    process = subprocess.Popen(command)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait()


def resolve_reference_paths(raw_paths: list[str] | None) -> list[Path]:
    if raw_paths:
        return [Path(value).expanduser() for value in raw_paths]
    default_paths = default_reference_paths(REPO_ROOT)
    if any(path.expanduser().exists() for path in default_paths):
        return default_paths
    if BUNDLED_REFERENCE_PATH.exists():
        return [BUNDLED_REFERENCE_PATH]
    return default_paths


def resolve_mitmdump_binary(raw_value: str, *, base_dir: Path = THIS_DIR) -> str:
    if raw_value.strip():
        return str(Path(raw_value).expanduser())

    bundled_candidates = (
        base_dir / ".venv" / "bin" / "mitmdump",
        base_dir / ".venv" / "Scripts" / "mitmdump.exe",
        base_dir / ".venv" / "Scripts" / "mitmdump",
    )
    for candidate in bundled_candidates:
        if candidate.exists():
            return str(candidate)

    detected = shutil.which("mitmdump")
    return detected or "mitmdump"


def mitmdump_binary_exists(raw_value: str) -> bool:
    candidate = Path(raw_value).expanduser()
    if candidate.exists():
        return True
    return shutil.which(raw_value) is not None


def print_reference_summary(
    reference: ReferenceTrafficInfo,
    *,
    selected_reverse_targets: Sequence[ReverseProxyTarget],
    selected_https_upstream_overrides: Sequence[HttpsUpstreamOverride],
) -> None:
    print(f"[rf4-monitor-runner] scanned {len(reference.source_files)} reference file(s)")
    if reference.domains:
        print(f"[rf4-monitor-runner] extracted domains: {', '.join(reference.domains)}")
    else:
        print("[rf4-monitor-runner] extracted domains: <none>")
    if reference.realtime_hosts:
        port_text = reference.realtime_port if reference.realtime_port is not None else "unknown"
        print(
            f"[rf4-monitor-runner] extracted realtime hosts: {', '.join(reference.realtime_hosts)} "
            f"(port={port_text})"
        )
    else:
        print("[rf4-monitor-runner] extracted realtime hosts: <none>")
    if reference.reverse_targets:
        print(
            "[rf4-monitor-runner] extracted reverse targets: "
            + ", ".join(target.mode_spec() for target in reference.reverse_targets)
        )
    else:
        print("[rf4-monitor-runner] extracted reverse targets: <none>")
    if reference.https_upstream_overrides:
        print(
            "[rf4-monitor-runner] extracted https upstreams: "
            + ", ".join(
                f"{override.domain}:{override.port} -> {override.connect_host}:{override.port}"
                for override in reference.https_upstream_overrides
            )
        )
    else:
        print("[rf4-monitor-runner] extracted https upstreams: <none>")
    if selected_reverse_targets:
        print(
            "[rf4-monitor-runner] active reverse targets: "
            + ", ".join(target.mode_spec() for target in selected_reverse_targets)
        )
    else:
        print("[rf4-monitor-runner] active reverse targets: <none>")
    if selected_https_upstream_overrides:
        print(
            "[rf4-monitor-runner] active https upstreams: "
            + ", ".join(
                f"{override.domain}:{override.port} -> {override.connect_host}:{override.port}"
                for override in selected_https_upstream_overrides
            )
        )
    else:
        print("[rf4-monitor-runner] active https upstreams: <none>")
    dropped_targets = [target for target in reference.reverse_targets if target not in selected_reverse_targets]
    for target in dropped_targets:
        print(
            "[rf4-monitor-runner] skipped reverse target due to listen-port conflict: "
            f"{target.mode_spec()}"
        )


def print_hosts_summary(result: HostsUpdateResult, *, dry_run: bool) -> None:
    mode = "preview" if dry_run else "updated"
    print(f"[rf4-monitor-runner] hosts {mode}: {result.path}")
    if result.backup_path is not None:
        print(f"[rf4-monitor-runner] hosts backup: {result.backup_path}")
    if result.entries:
        print(f"[rf4-monitor-runner] hosts entries: {', '.join(result.entries)}")
    else:
        print("[rf4-monitor-runner] hosts entries: <none>")


def print_certificate_summary(certificate: GeneratedCertificate) -> None:
    print(
        f"[rf4-monitor-runner] certificate ready: cn={certificate.common_name} "
        f"pem={certificate.pem_path} domains={', '.join(certificate.domains)}"
    )


def build_mitmdump_command(
    reference: ReferenceTrafficInfo,
    passthrough: list[str],
    certificate: GeneratedCertificate | None,
    *,
    auto_verbose: bool,
    auto_tcp_hosts: bool,
    auto_reverse_modes: bool,
    auto_realtime_mode: bool,
    auto_login_rewrite: bool,
    realtime_listen_host: str,
    realtime_listen_port: int,
    realtime_upstream_host: str,
    realtime_upstream_port: int,
) -> list[str]:
    script = Path(__file__).resolve()
    command: list[str] = ["mitmdump", "-s", str(script)]
    command.extend(passthrough)
    selected_reverse_targets = select_reverse_targets(reference.reverse_targets)
    selected_https_upstream_overrides = select_https_upstream_overrides(
        reference.https_upstream_overrides,
        selected_reverse_targets,
    )

    if auto_reverse_modes and not has_flag(command, "--mode"):
        for target in selected_reverse_targets:
            command.extend(["--mode", target.mode_spec()])

    selected_realtime_host = realtime_upstream_host.strip() or (reference.realtime_hosts[0] if reference.realtime_hosts else "")
    selected_realtime_port = realtime_upstream_port or reference.realtime_port or 0
    selected_listen_port = realtime_listen_port or selected_realtime_port

    if (
        auto_realtime_mode
        and selected_realtime_host
        and selected_realtime_port
        and selected_listen_port
        and not has_mode_prefix(command, "reverse:tcp://")
    ):
        command.extend(
            [
                "--mode",
                f"reverse:tcp://{selected_realtime_host}:{selected_realtime_port}@{selected_listen_port}",
            ]
        )

    if auto_verbose:
        command = ensure_option_set(command, "flow_detail=0")
        command = ensure_option_set(command, "rf4_log_parsed_events=true")
        command = ensure_option_set(command, "rf4_verbose_logging=true")

    if selected_https_upstream_overrides:
        command = ensure_option_set(command, "keep_host_header=true")
        command = ensure_option_set(
            command,
            f"rf4_https_upstream_map={build_https_upstream_map_option(selected_https_upstream_overrides)}",
        )

    if auto_login_rewrite and selected_listen_port:
        command = ensure_option_set(command, "rf4_enable_login_rewrite=true")
        command = ensure_option_set(command, f"rf4_realtime_redirect_host={realtime_listen_host}")
        command = ensure_option_set(command, f"rf4_realtime_redirect_port={selected_listen_port}")

    if auto_tcp_hosts and not has_flag(command, "--tcp-hosts"):
        tcp_hosts = None if reference.realtime_hosts == () else build_tcp_hosts_regex(reference.realtime_hosts, reference.realtime_port)
        if tcp_hosts:
            command.extend(["--tcp-hosts", tcp_hosts])

    if certificate is not None and not has_flag(command, "--certs"):
        for domain in certificate.domains:
            command.extend(["--certs", f"{domain}={certificate.pem_path}"])

    return command


def has_flag(args: list[str], flag: str) -> bool:
    return any(value == flag or value.startswith(f"{flag}=") for value in args)


def has_mode_prefix(args: list[str], mode_prefix: str) -> bool:
    for index, value in enumerate(args):
        if value != "--mode" or index + 1 >= len(args):
            continue
        if args[index + 1].startswith(mode_prefix):
            return True
    return False


def ensure_option_set(args: list[str], option_value: str) -> list[str]:
    target_key = option_value.split("=", 1)[0]
    for index, value in enumerate(args):
        if value != "--set" or index + 1 >= len(args):
            continue
        if args[index + 1].split("=", 1)[0] == target_key:
            return args
    return [*args, "--set", option_value]

# --- Protocol profile ---
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class RF4ProtocolProfile:
    name: str
    session_main_cmd: int
    player_main_cmd: int
    server_player_main_cmd: int
    feeding_main_cmd: int
    fishing_main_cmd: int
    cast_prepare_sub_cmd: int
    cast_sub_cmd: int
    fall_sub_cmd: int
    fishing_end_sub_cmd: int
    fish_setup_push_sub_cmd: int
    keep_fish_sub_cmd: int
    release_fish_sub_cmd: int
    fight_step_sub_cmd: int
    fight_load_sub_cmd: int
    fight_pull_sub_cmd: int
    fish_gen_sub_cmd: int
    fight_stage_sub_cmd: int
    contact_left_sub_cmd: int
    fish_sync_push_sub_cmd: int
    social_main_cmd: int
    public_chat_sub_cmd: int
    room_message_push_sub_cmd: int
    room_message_ack_sub_cmd: int
    room_message_object_type_id: int
    room_detail_item_type_id: int
    room_ack_profile_type_id: int
    room_message_line_type_catch: int
    arg_list_code: bytes = b"507"
    detail_list_code: bytes = b"135"


RF4_4_0_24799 = RF4ProtocolProfile(
    name="4.0.24799",
    session_main_cmd=1,
    player_main_cmd=3,
    server_player_main_cmd=2,
    feeding_main_cmd=12,
    fishing_main_cmd=14,
    cast_prepare_sub_cmd=1,
    cast_sub_cmd=2,
    fall_sub_cmd=3,
    fishing_end_sub_cmd=4,
    fish_setup_push_sub_cmd=14,
    keep_fish_sub_cmd=5,
    release_fish_sub_cmd=6,
    fight_step_sub_cmd=7,
    fight_load_sub_cmd=8,
    fight_pull_sub_cmd=9,
    fish_gen_sub_cmd=10,
    fight_stage_sub_cmd=11,
    contact_left_sub_cmd=12,
    fish_sync_push_sub_cmd=15,
    social_main_cmd=24,
    public_chat_sub_cmd=10,
    room_message_push_sub_cmd=27,
    room_message_ack_sub_cmd=19,
    room_message_object_type_id=401,
    room_detail_item_type_id=400,
    room_ack_profile_type_id=2002,
    room_message_line_type_catch=3,
)


KNOWN_PROFILES: Dict[str, RF4ProtocolProfile] = {
    RF4_4_0_24799.name: RF4_4_0_24799,
}


def get_profile(name: str) -> RF4ProtocolProfile:
    try:
        return KNOWN_PROFILES[name]
    except KeyError as exc:
        known = ", ".join(sorted(KNOWN_PROFILES))
        raise ValueError(f"unknown RF4 profile '{name}', expected one of: {known}") from exc

# --- Binary protocol codec ---
import re
import struct
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union


UUID_RE = re.compile(
    rb"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)


def u16(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "little", signed=False)


def u32(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "little", signed=False)


def u64(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 8], "little", signed=False)


def pack_u16(value: int) -> bytes:
    return struct.pack("<H", value)


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def pack_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def guid_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def pack_guid_marker(value: str) -> bytes:
    return b"\x0c" + uuid.UUID(value).bytes_le


def pack_guid_raw(value: str) -> bytes:
    return uuid.UUID(value).bytes_le


def read_short_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] == 0xFF:
        return None, pos + 1
    size = data[pos]
    pos += 1
    return data[pos:pos + size].decode("utf-8", errors="replace"), pos + size


def read_marked_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] == 0xFF:
        return None, pos + 1
    if data[pos] != 0x14:
        raise ValueError(f"expected 0x14 string marker at {pos}, got 0x{data[pos]:02x}")
    return read_short_string(data, pos + 1)


def read_flexible_string(data: bytes, pos: int) -> Tuple[Optional[str], int]:
    if pos >= len(data):
        return None, pos
    if data[pos] in (0x14, 0xFF):
        return read_marked_string(data, pos)
    return read_short_string(data, pos)


def pack_short_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("short string exceeds 255 bytes")
    return bytes([len(raw)]) + raw


def pack_marked_string(value: str) -> bytes:
    return b"\x14" + pack_short_string(value)


def pack_marked_u32(value: int) -> bytes:
    return b"\x10" + pack_u32(value)


def pack_arg_header(type_code: bytes, count: int) -> bytes:
    if len(type_code) > 255:
        raise ValueError("type code exceeds 255 bytes")
    return b"\x03" + bytes([len(type_code)]) + type_code + pack_u16(count)


def read_arg_header(data: bytes, pos: int) -> Tuple[int, int]:
    if pos + 4 > len(data) or data[pos] != 0x03:
        raise ValueError("missing typed arg header")
    size = data[pos + 1]
    start = pos + 2
    end = start + size
    if end + 2 > len(data):
        raise ValueError("truncated typed arg header")
    return u16(data, end), end + 2


def pack_object_header(type_id: int) -> bytes:
    return b"\x01" + pack_u32(type_id)


def read_object_header(data: bytes, pos: int) -> Tuple[int, int]:
    if pos + 5 > len(data) or data[pos] != 0x01:
        raise ValueError(f"missing object marker at {pos}")
    return u32(data, pos + 1), pos + 5


def read_guid(data: bytes, pos: int, marker: bool) -> Tuple[str, int]:
    if marker:
        if pos >= len(data) or data[pos] != 0x0C:
            raise ValueError(f"missing guid marker at {pos}")
        pos += 1
    if pos + 16 > len(data):
        raise ValueError("truncated guid")
    return guid_le(data[pos:pos + 16]), pos + 16


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    buf: List[str] = []
    for value in data:
        if 32 <= value < 127:
            buf.append(chr(value))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def plausible_fish_key(value: str) -> bool:
    if value.startswith(("level_", "rig_", "tele_", "worm_", "bait_", "dough_", "nav", "loc")):
        return False
    if value in {"test233"} or "@" in value or "[" in value or "]" in value:
        return False
    return bool(re.fullmatch(r"[a-z][a-z0-9_.]*", value))


def windows_filetime_now() -> int:
    return int((time.time() + 11644473600) * 10000000)


@dataclass(frozen=True)
class AppFrame:
    raw: bytes
    body_len: int
    frame_type: int
    wire_id: int
    payload: bytes

    @property
    def is_zero_marker(self) -> bool:
        return self.body_len == 0


@dataclass(frozen=True)
class RpcEnvelope:
    marker: int
    call_id: int
    main_cmd: Optional[int]
    sub_cmd: Optional[int]
    payload: bytes


@dataclass(frozen=True)
class FishSetupMeta:
    fish_setup_id: str
    fish_key: str
    fishing_gear_id: Optional[str] = None
    setup_enum: Optional[int] = None
    weight_hint_raw: Optional[int] = None
    length_hint: Optional[float] = None


@dataclass(frozen=True)
class KeepFishRequest:
    call_id: int
    fishing_gear_id: Optional[str]
    fish_setup_id: Optional[str]


@dataclass(frozen=True)
class PublicChatRequest:
    call_id: int
    message: Optional[str]


@dataclass(frozen=True)
class CatchSummary:
    fish_key: Optional[str]
    weight_raw: Optional[int]
    size_enum: Optional[int] = None


@dataclass(frozen=True)
class RoomDetailItem:
    slot: int
    kind: str
    value: Optional[Union[str, int]]


@dataclass(frozen=True)
class RoomBroadcast:
    line_type: int
    event_id: int
    fish_key: Optional[str]
    weight_raw: Optional[int]
    location_id: Optional[str]
    users_count: Optional[int]
    details: Tuple[RoomDetailItem, ...] = ()


@dataclass(frozen=True)
class RoomAckRequest:
    event_id: Optional[int]


@dataclass(frozen=True)
class RoomAckResponse:
    event_id: Optional[int]
    sender_name: Optional[str]
    avatar_url: Optional[str]
    sender_rank: Optional[int]


@dataclass(frozen=True)
class BusinessPayloadSummary:
    arg_count: Optional[int]
    strings: Tuple[str, ...]
    guids: Tuple[str, ...]
    u32_values: Tuple[int, ...]
    float_groups: Tuple[Tuple[float, ...], ...]


class RC4Stream:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("RC4 key must not be empty")
        self._s = list(range(256))
        self._i = 0
        self._j = 0
        j = 0
        key_bytes = list(key)
        for i in range(256):
            j = (j + self._s[i] + key_bytes[i % len(key_bytes)]) & 0xFF
            self._s[i], self._s[j] = self._s[j], self._s[i]

    def keystream(self, size: int) -> bytes:
        out = bytearray()
        s = self._s
        i = self._i
        j = self._j
        for _ in range(size):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(s[(s[i] + s[j]) & 0xFF])
        self._i = i
        self._j = j
        return bytes(out)

    def crypt(self, data: bytes) -> bytes:
        return xor_bytes(data, self.keystream(len(data)))


def try_parse_auth_packet(data: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 6 or data[:2] != b"\x01\x00":
        return None
    token_len = u32(data, 2)
    total = 6 + token_len
    if token_len <= 0 or len(data) < total:
        return None
    token = data[6:total].decode("utf-8", errors="strict")
    if token.count("|") < 3:
        return None
    return token, total


def try_parse_uuid_packet(data: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 36:
        return None
    candidate = data[:36]
    if not UUID_RE.match(candidate):
        return None
    return candidate.decode("ascii"), 36


def try_parse_first_frame(data: bytes) -> Optional[AppFrame]:
    if len(data) < 4:
        return None
    body_len = u32(data, 0)
    if body_len == 0:
        return AppFrame(raw=data[:4], body_len=0, frame_type=0, wire_id=0, payload=b"")
    if body_len == 1:
        if len(data) < 5:
            return None
        return AppFrame(raw=data[:5], body_len=1, frame_type=data[4], wire_id=0, payload=b"")
    if body_len < 9:
        raise ValueError(f"invalid body_len {body_len}")
    if len(data) < 13:
        return None
    total = 4 + body_len
    if len(data) < total:
        return None
    frame_type = data[4]
    wire_id = u64(data, 5)
    raw = data[:total]
    payload = data[13:total]
    return AppFrame(raw=raw, body_len=body_len, frame_type=frame_type, wire_id=wire_id, payload=payload)


def take_complete_frames(buffer: bytearray) -> List[AppFrame]:
    frames: List[AppFrame] = []
    while True:
        frame = try_parse_first_frame(buffer)
        if frame is None:
            break
        frames.append(frame)
        del buffer[:len(frame.raw)]
    return frames


def build_frame(frame_type: int, wire_id: int, payload: bytes) -> bytes:
    body_len = 9 + len(payload)
    return pack_u32(body_len) + bytes([frame_type]) + pack_u64(wire_id) + payload


def build_ack_frame(wire_id: int) -> bytes:
    return build_frame(1, wire_id, b"")


def parse_envelope(plain_body: bytes) -> Optional[RpcEnvelope]:
    if len(plain_body) < 9 or plain_body[0] != 0x01:
        return None
    marker = int.from_bytes(plain_body[1:5], "little", signed=True)
    if marker not in (-1, -2):
        return None
    call_id = u32(plain_body, 5)
    if marker == -1:
        if len(plain_body) < 11:
            return None
        return RpcEnvelope(
            marker=marker,
            call_id=call_id,
            main_cmd=plain_body[9],
            sub_cmd=plain_body[10],
            payload=plain_body[11:],
        )
    return RpcEnvelope(marker=marker, call_id=call_id, main_cmd=None, sub_cmd=None, payload=plain_body[9:])


def build_request_envelope(call_id: int, main_cmd: int, sub_cmd: int, payload: bytes) -> bytes:
    return b"\x01" + struct.pack("<iI", -1, call_id) + bytes([main_cmd, sub_cmd]) + payload


def build_response_envelope(call_id: int, payload: bytes) -> bytes:
    return b"\x01" + struct.pack("<iI", -2, call_id) + payload


def parse_fish_setup_push(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[FishSetupMeta]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.fish_setup_push_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        _, pos = read_object_header(envelope.payload, pos)
        fish_setup_id, pos = read_guid(envelope.payload, pos, marker=False)
        fish_key, pos = read_short_string(envelope.payload, pos)
        setup_enum = None
        length_hint = None
        weight_hint_raw = None
        if pos < len(envelope.payload):
            setup_enum = envelope.payload[pos]
            pos += 1
        if pos + 4 <= len(envelope.payload):
            length_hint = struct.unpack_from("<f", envelope.payload, pos)[0]
            pos += 4
        if pos + 4 <= len(envelope.payload):
            weight_hint_raw = u32(envelope.payload, pos)
    except (ValueError, IndexError):
        return None
    if not fish_key:
        return None
    return FishSetupMeta(
        fish_setup_id=fish_setup_id,
        fish_key=fish_key,
        fishing_gear_id=fishing_gear_id,
        setup_enum=setup_enum,
        weight_hint_raw=weight_hint_raw,
        length_hint=length_hint,
    )


def parse_keep_fish_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[KeepFishRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.fishing_main_cmd or envelope.sub_cmd != profile.keep_fish_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        fishing_gear_id = None
        fish_setup_id = None
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fishing_gear_id, pos = read_guid(envelope.payload, pos, marker=True)
        if pos < len(envelope.payload) and envelope.payload[pos] == 0x0C:
            fish_setup_id, pos = read_guid(envelope.payload, pos, marker=True)
    except (ValueError, IndexError):
        return None
    return KeepFishRequest(
        call_id=envelope.call_id,
        fishing_gear_id=fishing_gear_id,
        fish_setup_id=fish_setup_id,
    )


def parse_public_chat_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[PublicChatRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.public_chat_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
        message, _ = read_flexible_string(envelope.payload, pos)
    except (ValueError, IndexError):
        return None
    return PublicChatRequest(call_id=envelope.call_id, message=message)


def extract_catch_summary_from_response(plain_body: bytes) -> CatchSummary:
    strings = ascii_strings(plain_body)
    fish_key = None
    for value in strings:
        if plausible_fish_key(value):
            fish_key = value
            break
    if not fish_key:
        return CatchSummary(fish_key=None, weight_raw=None, size_enum=None)

    needle = bytes([len(fish_key)]) + fish_key.encode("utf-8")
    idx = plain_body.find(needle)
    if idx < 0:
        return CatchSummary(fish_key=fish_key, weight_raw=None, size_enum=None)

    pos = idx + len(needle)
    weight_raw = None
    size_enum = None
    if pos + 4 <= len(plain_body):
        candidate = u32(plain_body, pos)
        if 0 < candidate < 10000000:
            weight_raw = candidate
    if pos + 10 <= len(plain_body):
        candidate = u16(plain_body, pos + 8)
        if 0 < candidate < 256:
            size_enum = candidate
    return CatchSummary(fish_key=fish_key, weight_raw=weight_raw, size_enum=size_enum)


def parse_room_broadcast(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomBroadcast]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.room_message_push_sub_cmd:
        return None

    data = envelope.payload
    try:
        _, pos = read_arg_header(data, 0)
        _, pos = read_object_header(data, pos)
        line_type = data[pos]
        pos += 1
        pos += 2
        event_id = u32(data, pos)
        pos += 4
        pos += 8

        details: List[RoomDetailItem] = []
        if data[pos:pos + 5] == pack_arg_header(profile.detail_list_code, 0)[:5]:
            detail_count = u16(data, pos + 5)
            pos += 7
            for _ in range(detail_count):
                _, pos = read_object_header(data, pos)
                slot = data[pos]
                pos += 1
                marker = data[pos]
                if marker == 0x14:
                    value, pos = read_marked_string(data, pos)
                    details.append(RoomDetailItem(slot=slot, kind="string", value=value))
                elif marker == 0x10:
                    pos += 1
                    value = u32(data, pos)
                    pos += 4
                    details.append(RoomDetailItem(slot=slot, kind="u32", value=value))
                else:
                    break

        location_id = None
        if pos < len(data) and data[pos] == 0x14:
            location_id, pos = read_marked_string(data, pos)

        users_count = None
        if pos < len(data) and data[pos] == 0x10:
            users_count = u32(data, pos + 1)

        fish_key = None
        weight_raw = None
        for item in details:
            if item.slot == 1 and item.kind == "string":
                fish_key = item.value
            elif item.slot == 2 and item.kind == "u32":
                weight_raw = item.value

        return RoomBroadcast(
            line_type=line_type,
            event_id=event_id,
            fish_key=fish_key,
            weight_raw=weight_raw,
            location_id=location_id,
            users_count=users_count,
            details=tuple(details),
        )
    except (ValueError, IndexError):
        return None


def parse_room_ack_request(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomAckRequest]:
    if envelope.marker != -1:
        return None
    if envelope.main_cmd != profile.social_main_cmd or envelope.sub_cmd != profile.room_message_ack_sub_cmd:
        return None
    try:
        _, pos = read_arg_header(envelope.payload, 0)
    except (ValueError, IndexError):
        return None
    if pos + 5 <= len(envelope.payload) and envelope.payload[pos] == 0x10:
        return RoomAckRequest(event_id=u32(envelope.payload, pos + 1))
    return RoomAckRequest(event_id=None)


def parse_room_ack_response(envelope: RpcEnvelope, profile: RF4ProtocolProfile) -> Optional[RoomAckResponse]:
    if envelope.marker != -2:
        return None

    data = envelope.payload
    pos = 0
    if pos + 5 > len(data) or data[pos] != 0x08:
        return None
    pos += 5

    if pos + 5 > len(data) or data[pos] != 0x01:
        return None
    if u32(data, pos + 1) != profile.room_ack_profile_type_id:
        return None
    pos += 5

    if pos + 4 > len(data):
        return None
    event_id = u32(data, pos)
    pos += 4

    if pos >= len(data):
        return RoomAckResponse(
            event_id=event_id,
            sender_name=None,
            avatar_url=None,
            sender_rank=None,
        )

    name_len = data[pos]
    pos += 1
    if pos + name_len > len(data):
        return None
    sender_name = data[pos:pos + name_len].decode("utf-8", errors="replace")
    pos += name_len

    if pos < len(data) and data[pos] == 0x51:
        pos += 1
    if pos < len(data) and data[pos] == 0x00:
        pos += 1

    avatar_url = None
    if pos + 4 <= len(data) and data[pos:pos + 4] == b"http":
        end = data.find(b"\x00", pos)
        if end == -1:
            return None
        avatar_url = data[pos:end].decode("utf-8", errors="replace")
        pos = end + 1

    if pos < len(data) and data[pos] == 0x00 and pos + 15 <= len(data):
        pos += 1

    sender_rank = None
    if pos + 14 <= len(data):
        sender_rank = u32(data, pos)

    return RoomAckResponse(
        event_id=event_id,
        sender_name=sender_name or None,
        avatar_url=avatar_url,
        sender_rank=sender_rank,
    )


def build_room_message_push_body(
    profile: RF4ProtocolProfile,
    call_id: int,
    event_id: int,
    fish_key: str,
    weight_raw: int,
    location_id: str,
    users_count: int,
    message_time_raw: Optional[int] = None,
    line_type: Optional[int] = None,
) -> bytes:
    detail_items = bytearray()
    detail_items.extend(pack_object_header(profile.room_detail_item_type_id))
    detail_items.extend(b"\x01")
    detail_items.extend(pack_marked_string(fish_key))
    detail_items.extend(pack_object_header(profile.room_detail_item_type_id))
    detail_items.extend(b"\x02")
    detail_items.extend(pack_marked_u32(weight_raw))

    payload = bytearray()
    payload.extend(pack_arg_header(profile.arg_list_code, 3))
    payload.extend(pack_object_header(profile.room_message_object_type_id))
    payload.extend(bytes([line_type if line_type is not None else profile.room_message_line_type_catch]))
    payload.extend(b"\xff\xff")
    payload.extend(pack_u32(event_id))
    payload.extend(pack_u64(message_time_raw if message_time_raw is not None else windows_filetime_now()))
    payload.extend(pack_arg_header(profile.detail_list_code, 2))
    payload.extend(detail_items)
    payload.extend(pack_marked_string(location_id))
    payload.extend(pack_marked_u32(users_count))
    payload.extend(b"\x01")
    return build_request_envelope(
        call_id=call_id,
        main_cmd=profile.social_main_cmd,
        sub_cmd=profile.room_message_push_sub_cmd,
        payload=bytes(payload),
    )


def build_room_ack_response_body(
    profile: RF4ProtocolProfile,
    call_id: int,
    event_id: int,
    sender_name: str,
    avatar_url: str,
    sender_level: int,
    sender_region: int,
    sender_class: int,
    sender_badge: int,
) -> bytes:
    profile_block = bytearray()
    profile_block.extend(pack_object_header(profile.room_ack_profile_type_id))
    profile_block.extend(pack_u32(event_id))
    profile_block.extend(pack_short_string(sender_name))
    if avatar_url:
        profile_block.extend(b"\x51")
        profile_block.extend(avatar_url.encode("utf-8"))
        profile_block.extend(b"\x00")
    else:
        profile_block.extend(b"\x00")
    profile_block.extend(pack_u32(sender_level))
    profile_block.extend(pack_u32(sender_region))
    profile_block.extend(pack_u16(0x0401))
    profile_block.extend(pack_u16(sender_class))
    profile_block.extend(pack_u16(sender_badge))

    payload = b"\x08" + pack_u32(len(profile_block)) + bytes(profile_block)
    return build_response_envelope(call_id=call_id, payload=payload)

# --- Fish localization ---
import json
import mmap
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional


BASE = THIS_DIR
ROOT = REPO_ROOT
CACHE_DIR = BASE / ".cache"
BUNDLED_LABEL_PATH = BASE / "fish_labels_zh.json"
SYSTEM_LABEL_RE = re.compile(
    r'"systemId":"((?:\\.|[^"\\])*)","name":"((?:\\.|[^"\\])*)","description":'
)
CJK_RE = re.compile(r"[\u3400-\u9fff]")


def _json_unescape(value: str) -> str:
    return json.loads(f'"{value}"')


def _contains_cjk(value: str) -> bool:
    return bool(CJK_RE.search(value))


def extract_system_labels_from_text(text: str) -> Dict[str, str]:
    grouped: Dict[str, list[str]] = {}
    for raw_key, raw_name in SYSTEM_LABEL_RE.findall(text):
        key = _json_unescape(raw_key).strip()
        name = _json_unescape(raw_name).strip()
        if not key or not name:
            continue
        grouped.setdefault(key, []).append(name)

    selected: Dict[str, str] = {}
    for key, values in grouped.items():
        chosen = next((value for value in values if _contains_cjk(value)), None)
        if chosen is None:
            chosen = next((value for value in values if value), None)
        if chosen:
            selected[key] = chosen
    return selected


def _find_locale_blob(resources_assets: Path, locale_id: str) -> str:
    marker = f'"localeId":"{locale_id}"'.encode("utf-8")
    next_marker = b'"localeId":"'
    with resources_assets.open("rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        start = mm.find(marker)
        if start < 0:
            raise FileNotFoundError(f"locale {locale_id!r} was not found in {resources_assets}")
        end = mm.find(next_marker, start + len(marker))
        if end < 0:
            end = len(mm)
        return mm[start:end].decode("utf-8", errors="ignore")


def extract_system_labels_from_resources(resources_assets: Path, locale_id: str = "zh_CN") -> Dict[str, str]:
    return extract_system_labels_from_text(_find_locale_blob(resources_assets, locale_id))


def _candidate_resources_assets(profile_name: str) -> Iterable[Path]:
    direct = ROOT / "version" / profile_name / "rf4_x64_Data" / "resources.assets"
    if direct.exists():
        yield direct

    for candidate in sorted((ROOT / "version").glob("*/rf4_x64_Data/resources.assets"), reverse=True):
        if candidate != direct:
            yield candidate


def _cache_path(profile_name: str) -> Path:
    return CACHE_DIR / f"fish_labels_zh_{profile_name.replace('.', '_')}.json"


def _read_cache(cache_path: Path, resources_assets: Path) -> Optional[Dict[str, str]]:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    stat = resources_assets.stat()
    if (
        payload.get("source_path") != str(resources_assets)
        or payload.get("source_size") != stat.st_size
        or payload.get("source_mtime_ns") != stat.st_mtime_ns
    ):
        return None

    labels = payload.get("labels")
    if not isinstance(labels, dict):
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _read_cache_labels_unchecked(cache_path: Path) -> Optional[Dict[str, str]]:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    labels = payload.get("labels")
    if not isinstance(labels, dict):
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _read_labels_file_unchecked(path: Path) -> Optional[Dict[str, str]]:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if isinstance(payload, dict) and isinstance(payload.get("labels"), dict):
        labels = payload["labels"]
    elif isinstance(payload, dict):
        labels = payload
    else:
        return None
    return {str(key): str(value) for key, value in labels.items() if key and value}


def _write_cache(cache_path: Path, resources_assets: Path, labels: Dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stat = resources_assets.stat()
    payload = {
        "source_path": str(resources_assets),
        "source_size": stat.st_size,
        "source_mtime_ns": stat.st_mtime_ns,
        "labels": labels,
    }
    cache_path.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


@lru_cache(maxsize=None)
def load_fish_labels(profile_name: str, locale_id: str = "zh_CN") -> Dict[str, str]:
    cache_path = _cache_path(profile_name)
    for resources_assets in _candidate_resources_assets(profile_name):
        cached = _read_cache(cache_path, resources_assets)
        if cached is not None:
            return cached

        labels = extract_system_labels_from_resources(resources_assets, locale_id=locale_id)
        if labels:
            try:
                _write_cache(cache_path, resources_assets, labels)
            except OSError:
                pass
            return labels

    bundled = _read_labels_file_unchecked(BUNDLED_LABEL_PATH)
    if bundled is not None:
        return bundled

    cached = _read_cache_labels_unchecked(cache_path)
    if cached is not None:
        return cached

    for fallback_cache_path in sorted(CACHE_DIR.glob("fish_labels_zh_*.json"), reverse=True):
        fallback = _read_cache_labels_unchecked(fallback_cache_path)
        if fallback is not None:
            return fallback

    return {}

# --- RF4 monitor bridge ---
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from mitmproxy import ctx, http, tcp
except Exception:
    from types import SimpleNamespace
    ctx = SimpleNamespace(
        options=SimpleNamespace(),
        log=SimpleNamespace(info=lambda *_args, **_kwargs: None),
        master=SimpleNamespace(commands=SimpleNamespace(call=lambda *_args, **_kwargs: None)),
    )
    http = SimpleNamespace(HTTPFlow=object)
    tcp = SimpleNamespace(TCPFlow=object)


_WINDOWS_VT_MODE_READY = False


def _enable_windows_virtual_terminal() -> bool:
    global _WINDOWS_VT_MODE_READY
    if _WINDOWS_VT_MODE_READY:
        return True
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle in (0, -1):
            return False
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        if kernel32.SetConsoleMode(handle, mode.value | 0x0004) == 0:
            return False
    except Exception:
        return False
    _WINDOWS_VT_MODE_READY = True
    return True


def _stream_is_tty(stream) -> bool:
    if stream is None:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def _supports_colored_console_output() -> bool:
    if not (_stream_is_tty(getattr(sys, "stdout", None)) or _stream_is_tty(getattr(sys, "stderr", None))):
        return False
    return _enable_windows_virtual_terminal()


def _colorize_console_text(text: str, color_code: str) -> str:
    if not _supports_colored_console_output():
        return text
    return f"\033[{color_code}m{text}\033[0m"


@dataclass
class SyntheticChatEvent:
    event_id: int
    fish_key: str
    weight_raw: int
    location_id: str
    users_count: int
    phase: str = "kept"
    sender_name: str = "【我自己】"
    line_type: int = 3


@dataclass
class FlowSession:
    profile: RF4ProtocolProfile
    token: Optional[str] = None
    auth_seen: bool = False
    uuid_seen: bool = False
    hermes_seen: bool = False
    client_buffer: bytearray = field(default_factory=bytearray)
    server_buffer: bytearray = field(default_factory=bytearray)
    client_read_rc4: Optional[RC4Stream] = None
    client_write_rc4: Optional[RC4Stream] = None
    server_read_rc4: Optional[RC4Stream] = None
    server_write_rc4: Optional[RC4Stream] = None
    fish_setup_cache: Dict[str, FishSetupMeta] = field(default_factory=dict)
    keep_requests: Dict[int, KeepFishRequest] = field(default_factory=dict)
    room_events: Dict[int, RoomBroadcast] = field(default_factory=dict)
    room_ack_calls: Dict[int, int] = field(default_factory=dict)
    synthetic_events: Dict[int, SyntheticChatEvent] = field(default_factory=dict)
    synthetic_wire_ids: set[int] = field(default_factory=set)
    announced_fish_setup_ids: set[str] = field(default_factory=set)
    latest_location_id: Optional[str] = None
    latest_users_count: Optional[int] = None
    next_synthetic_event_id: int = 0x71000000
    next_synthetic_call_id: int = 0x61000000
    next_synthetic_wire_id: int = 0x100000

    def handshake_complete(self) -> bool:
        return self.auth_seen and self.uuid_seen and self.hermes_seen

    def ensure_rc4(self) -> None:
        if not self.token:
            raise ValueError("cannot initialize RC4 without token")
        if self.client_read_rc4 is None:
            key = self.token.encode("utf-8")
            self.client_read_rc4 = RC4Stream(key)
            self.client_write_rc4 = RC4Stream(key)
            self.server_read_rc4 = RC4Stream(key)
            self.server_write_rc4 = RC4Stream(key)

    def build_client_forward_frame(self, frame_type: int, wire_id: int, plain_body: bytes) -> bytes:
        if not self.server_write_rc4:
            raise ValueError("server write RC4 stream is not initialized")
        return build_frame(frame_type, wire_id, self.server_write_rc4.crypt(plain_body))

    def alloc_event_id(self) -> int:
        value = self.next_synthetic_event_id
        self.next_synthetic_event_id += 1
        return value

    def alloc_call_id(self) -> int:
        value = self.next_synthetic_call_id
        self.next_synthetic_call_id += 1
        return value

    def alloc_wire_id(self) -> int:
        value = self.next_synthetic_wire_id
        self.next_synthetic_wire_id += 1
        return value

    def build_server_injection(self, plain_body: bytes) -> bytes:
        if not self.client_write_rc4:
            raise ValueError("client write RC4 stream is not initialized")
        wire_id = self.alloc_wire_id()
        self.synthetic_wire_ids.add(wire_id)
        encrypted = self.client_write_rc4.crypt(plain_body)
        return build_frame(0, wire_id, encrypted)

    def build_server_forward_frame(self, frame_type: int, wire_id: int, plain_body: bytes) -> bytes:
        if not self.client_write_rc4:
            raise ValueError("client write RC4 stream is not initialized")
        return build_frame(frame_type, wire_id, self.client_write_rc4.crypt(plain_body))


class RF4ChatBridge:
    SELF_EVENT_PHASE_INCOMING = "incoming"
    SELF_EVENT_PHASE_KEPT = "kept"
    TELEMETRY_CATEGORY_LABELS = {
        "fish": "钓鱼",
        "player": "人物",
        "feed": "投喂",
        "chat": "聊天",
        "room": "房间",
        "session": "会话",
        "unknown": "未知",
    }
    SESSION_COMMAND_LABELS = {
        7: "设置语言",
        8: "反作弊报告",
        9: "反作弊标志",
        15: "进入地图",
        18: "硬件/区域信息",
    }
    PLAYER_COMMAND_LABELS = {
        8: "训练状态",
        9: "人物坐标",
        10: "船只使用",
        11: "篝火操作",
        12: "落水状态",
        13: "厨房进食",
        14: "钓具辅助",
        15: "纺车辅助",
        16: "领奖",
        17: "鱼获奖杯",
        18: "警告列表",
        19: "已读警告",
        20: "改名",
        21: "改地区",
        22: "读取邮箱",
        23: "设置邮箱",
        24: "验证邮箱",
        25: "提交封禁信息",
        26: "封禁信息",
        27: "弹吉他",
    }
    SERVER_PLAYER_COMMAND_LABELS = {
        1: "下发玩家资料",
        2: "下发玩家状态",
        6: "下发技能信息",
        8: "下发成就信息",
    }
    FISHING_COMMAND_LABELS = {
        1: "准备抛竿",
        2: "抛竿",
        3: "落点/实钩上下文",
        4: "结束钓鱼",
        5: "入护请求",
        6: "放生鱼",
        7: "钓鱼过程位置上报",
        8: "搏鱼拉力",
        9: "拉线动作",
        10: "请求鱼讯",
        11: "进入搏鱼阶段",
        12: "接触/脱离",
        14: "来鱼信息",
        15: "鱼同步",
    }
    FEEDING_COMMAND_LABELS = {
        1: "打窝/投喂",
    }
    DEFAULT_FISH_LABELS_ZH = {
        "a.sleeper": "葛氏鲈塘鳢",
        "a_smelt": "亚洲胡瓜鱼",
        "barsch": "俄罗斯梭吻鲈",
        "c.carp": "金鲫",
        "c_bleak": "欧鲌",
        "c_nase": "大鼻软口鱼",
        "c.roach": "常见拟鲤",
        "crucian": "银鲫",
        "dace": "雅罗鱼",
        "e.chub": "诸子鲦",
        "osetr_ship": "裸腹鲟",
        "perch": "鲈鱼",
        "ripus": "拉多加白鲑",
        "ruffe": "梅花鲈",
        "ruffe_n": "长吻梅花鲈",
        "s.bream": "银鲷鱼",
        "s.orfe": "圆腹雅罗鱼",
        "tench": "丁鱥",
    }
    GRADE_LABELS_BY_LINE_TYPE = {
        26: "蓝",
    }
    RECORD_CLASS_LABELS = {
        "BL": "底钓",
        "DEF": "常规",
        "L": "轻",
        "PICKER": "Picker",
        "SEA": "海钓",
        "TL": "手竿",
        "UL": "超轻",
    }

    def __init__(self) -> None:
        self._profile = get_profile("4.0.24799")
        self._sessions: Dict[str, FlowSession] = {}
        self._latest_realtime_hosts: tuple[str, ...] = ()
        self._latest_realtime_port: Optional[int] = None
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        try:
            self._fish_labels_zh.update(load_fish_labels(self._profile.name))
        except Exception:
            pass

    def load(self, loader) -> None:
        loader.add_option("rf4_enable_chat_bridge", bool, True, "Enable RF4 catch-to-chat injection.")
        loader.add_option("rf4_enable_login_rewrite", bool, True, "Rewrite RF4 login logon realtime host/port to the local listener.")
        loader.add_option(
            "rf4_https_upstream_map",
            str,
            "",
            "Domain=IP map used to keep reverse HTTPS upstream traffic off the local hosts redirect.",
        )
        loader.add_option("rf4_profile", str, "4.0.24799", "RF4 protocol profile name.")
        loader.add_option("rf4_realtime_redirect_host", str, "127.0.0.1", "Realtime host written into the RF4 login logon response.")
        loader.add_option("rf4_realtime_redirect_port", int, 0, "Realtime port written into the RF4 login logon response.")
        loader.add_option("rf4_sender_name", str, "RF4Chat", "Sender name used in synthetic 24/19 responses.")
        loader.add_option("rf4_avatar_url", str, "", "Optional avatar URL for synthetic 24/19 responses.")
        loader.add_option("rf4_sender_level", int, 1, "Sender level used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_region", int, 1, "Sender region/status field used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_class", int, 0, "Sender class/icon field used in synthetic 24/19 responses.")
        loader.add_option("rf4_sender_badge", int, 0, "Sender badge/flags field used in synthetic 24/19 responses.")
        loader.add_option("rf4_default_location_id", str, "", "Fallback location id for synthetic 24/27 messages.")
        loader.add_option("rf4_default_users_count", int, 0, "Fallback users count for synthetic 24/27 messages.")
        loader.add_option(
            "rf4_enable_self_chat_injection",
            bool,
            False,
            "Inject self incoming/kept fish messages into the in-game chat stream.",
        )
        loader.add_option("rf4_log_parsed_events", bool, True, "Print parsed fishing/chat events to the mitm console.")
        loader.add_option("rf4_log_telemetry", bool, True, "Print compact RF4 business telemetry summaries.")
        loader.add_option(
            "rf4_log_room_protocol_details",
            bool,
            False,
            "Print low-level 24/19 room-message lookup request/response details.",
        )
        loader.add_option(
            "rf4_log_low_level_telemetry",
            bool,
            False,
            "Print lower-confidence server state pushes and generic protocol summaries.",
        )
        loader.add_option(
            "rf4_log_unknown_telemetry",
            bool,
            False,
            "Also print compact summaries for unrecognized RF4 RPC frames.",
        )
        loader.add_option(
            "rf4_telemetry_categories",
            str,
            "all",
            "Telemetry categories to print: all, fish, player, feed, chat, room, session, unknown. Comma-separated.",
        )
        loader.add_option("rf4_log_plain_frames", bool, False, "Log every decrypted RF4 business frame with hex/ascii details.")
        loader.add_option("rf4_verbose_logging", bool, False, "Log per-session handshake and injection details.")

    def configure(self, updated) -> None:
        self._profile = get_profile(ctx.options.rf4_profile)
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        try:
            self._fish_labels_zh.update(load_fish_labels(self._profile.name))
        except Exception:
            pass

    def server_connect(self, data) -> None:
        if data.server.address is None:
            return

        original_host, original_port = data.server.address
        upstream_map = parse_https_upstream_map(ctx.options.rf4_https_upstream_map)
        connect_host = upstream_map.get(original_host.lower())
        if connect_host:
            data.server.address = (connect_host, original_port)
            data.server.sni = original_host
            if ctx.options.rf4_verbose_logging:
                self._log(
                    f"rewrote HTTPS upstream {original_host}:{original_port} -> "
                    f"{connect_host}:{original_port}"
                )
            return

        realtime_target = self._select_realtime_upstream(original_port)
        if realtime_target is None:
            return

        realtime_host, realtime_port = realtime_target
        if (original_host, original_port) == realtime_target:
            return

        data.server.address = realtime_target
        if ctx.options.rf4_verbose_logging:
            self._log(
                f"rewrote realtime upstream {original_host}:{original_port} -> "
                f"{realtime_host}:{realtime_port}"
            )

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        self._sessions[flow.id] = FlowSession(profile=self._profile)

    def tcp_end(self, flow: tcp.TCPFlow) -> None:
        self._sessions.pop(flow.id, None)

    def tcp_error(self, flow: tcp.TCPFlow) -> None:
        self._sessions.pop(flow.id, None)

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        if not ctx.options.rf4_enable_chat_bridge:
            return
        session = self._sessions.setdefault(flow.id, FlowSession(profile=self._profile))
        message = flow.messages[-1]
        if message.from_client:
            message.content = self._process_client_bytes(flow, session, message.content)
        else:
            message.content = self._process_server_bytes(flow, session, message.content)

    def request(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.rf4_verbose_logging:
            return
        if not self._is_login_request(flow):
            return
        self._log_http_message(
            "login request plaintext",
            f"{flow.request.method} {flow.request.pretty_host}{flow.request.path}",
            flow.request.headers,
            self._extract_message_text(flow.request),
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        is_login_request = self._is_login_request(flow)
        response_text = self._extract_message_text(flow.response)
        if ctx.options.rf4_verbose_logging and is_login_request:
            self._log_http_message(
                "login response plaintext",
                f"HTTP {flow.response.status_code} {flow.request.pretty_host}{flow.request.path}",
                flow.response.headers,
                response_text,
            )

        if not ctx.options.rf4_enable_login_rewrite:
            return
        redirect_port = int(ctx.options.rf4_realtime_redirect_port or 0)
        if redirect_port <= 0:
            return

        text = response_text
        if "<logon" not in text or "<host>" not in text or "<port>" not in text:
            if ctx.options.rf4_verbose_logging and is_login_request:
                self._log(
                    "login response did not contain <logon>; "
                    f"preview={self._quote_text(text, limit=200)}"
                )
            return

        rewrite = rewrite_login_logon_info(
            text,
            redirect_host=ctx.options.rf4_realtime_redirect_host,
            redirect_port=redirect_port,
            repeat_host_count=True,
        )
        if rewrite is None:
            if ctx.options.rf4_verbose_logging:
                self._log("login response matched <logon>, but rewrite_login_logon_info returned no result")
            return
        if rewrite.text == text:
            if ctx.options.rf4_verbose_logging:
                self._log("login response already matched the configured realtime redirect target")
            return

        self._latest_realtime_hosts = rewrite.original.hosts
        self._latest_realtime_port = rewrite.original.port
        flow.response.set_text(rewrite.text)
        self._log(
            "rewrote login realtime target "
            f"{';'.join(rewrite.original.hosts)}:{rewrite.original.port} -> "
            f"{';'.join(rewrite.redirected_hosts)}:{rewrite.redirected_port}"
        )
        if ctx.options.rf4_verbose_logging and is_login_request:
            self._log_http_message(
                "login response rewritten plaintext",
                f"HTTP {flow.response.status_code} {flow.request.pretty_host}{flow.request.path}",
                flow.response.headers,
                rewrite.text,
            )

    def _log(self, text: str) -> None:
        ctx.log.info(f"[rf4-monitor] {text}")

    def _log_event(self, text: str) -> None:
        if ctx.options.rf4_log_parsed_events:
            ctx.log.info(text)

    def _log_self_event(self, text: str) -> None:
        if not ctx.options.rf4_log_parsed_events:
            return
        ctx.log.info(_colorize_console_text(text, "96"))

    def _log_telemetry(self, category: str, text: str) -> None:
        if not self._telemetry_enabled(category):
            return
        ctx.log.info(text)

    @staticmethod
    def _telemetry_enabled(category: str) -> bool:
        if not bool(getattr(ctx.options, "rf4_log_telemetry", True)):
            return False
        raw_categories = str(getattr(ctx.options, "rf4_telemetry_categories", "all") or "all")
        categories = {item.strip().lower() for item in raw_categories.split(",") if item.strip()}
        if not categories or "all" in categories or "*" in categories:
            return True
        if "none" in categories or "off" in categories or "false" in categories:
            return False
        return category.lower() in categories

    @staticmethod
    def _self_chat_injection_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_enable_self_chat_injection", False))

    @staticmethod
    def _room_protocol_details_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_room_protocol_details", False))

    @staticmethod
    def _low_level_telemetry_enabled() -> bool:
        return bool(getattr(ctx.options, "rf4_log_low_level_telemetry", False))

    def _select_realtime_upstream(self, original_port: int) -> Optional[tuple[str, int]]:
        if not self._latest_realtime_hosts or self._latest_realtime_port is None:
            return None
        if original_port != self._latest_realtime_port:
            return None
        return self._latest_realtime_hosts[0], self._latest_realtime_port

    @staticmethod
    def _is_login_request(flow: http.HTTPFlow) -> bool:
        request = flow.request
        if request is None:
            return False
        host = request.pretty_host.lower()
        path = request.path.lower()
        if host != "api.rf4game.ru":
            return False
        return path.startswith("/login.php") or path.startswith("/steam.php")

    def _process_client_bytes(self, flow: tcp.TCPFlow, session: FlowSession, chunk: bytes) -> bytes:
        session.client_buffer.extend(chunk)
        out = bytearray()

        if not session.auth_seen:
            parsed = try_parse_auth_packet(bytes(session.client_buffer))
            if parsed is None:
                return b""
            token, consumed = parsed
            session.token = token
            session.auth_seen = True
            out.extend(session.client_buffer[:consumed])
            del session.client_buffer[:consumed]
            if ctx.options.rf4_verbose_logging:
                masked = token[:24] + "..." if len(token) > 24 else token
                self._log(f"captured auth token for flow {flow.id}: {masked}")

        if session.auth_seen and not session.hermes_seen:
            frame = try_parse_first_frame(bytes(session.client_buffer))
            if frame is None:
                return bytes(out)
            if b"<hermes>" not in frame.payload:
                raise ValueError("expected Hermes plaintext frame during handshake")
            out.extend(frame.raw)
            del session.client_buffer[:len(frame.raw)]
            session.hermes_seen = True
            session.ensure_rc4()
            if ctx.options.rf4_verbose_logging:
                self._log(f"Hermes handshake completed for flow {flow.id}")

        if session.handshake_complete() and session.client_buffer:
            out.extend(self._process_app_frames(flow, session, from_client=True))

        return bytes(out)

    def _process_server_bytes(self, flow: tcp.TCPFlow, session: FlowSession, chunk: bytes) -> bytes:
        session.server_buffer.extend(chunk)
        out = bytearray()

        if not session.uuid_seen:
            parsed = try_parse_uuid_packet(bytes(session.server_buffer))
            if parsed is None:
                return b""
            _, consumed = parsed
            session.uuid_seen = True
            out.extend(session.server_buffer[:consumed])
            del session.server_buffer[:consumed]
            if ctx.options.rf4_verbose_logging:
                self._log(f"captured UUID handshake packet for flow {flow.id}")

        if session.handshake_complete() and session.server_buffer:
            out.extend(self._process_app_frames(flow, session, from_client=False))

        return bytes(out)

    def _process_app_frames(self, flow: tcp.TCPFlow, session: FlowSession, from_client: bool) -> bytes:
        buffer = session.client_buffer if from_client else session.server_buffer
        frames = take_complete_frames(buffer)
        if not frames:
            return b""

        out = bytearray()
        read_cipher = session.client_read_rc4 if from_client else session.server_read_rc4
        if read_cipher is None:
            raise ValueError("RC4 stream is not initialized")

        for frame in frames:
            if frame.frame_type == 1:
                if from_client and frame.wire_id in session.synthetic_wire_ids:
                    session.synthetic_wire_ids.discard(frame.wire_id)
                    if ctx.options.rf4_verbose_logging:
                        self._log(f"swallowed client transport ack for synthetic wire {frame.wire_id} flow {flow.id}")
                    continue
                out.extend(frame.raw)
                continue
            if not frame.payload:
                out.extend(frame.raw)
                continue

            plain_body = read_cipher.crypt(frame.payload)
            self._maybe_log_telemetry_frame(flow, session, from_client, plain_body)
            if getattr(ctx.options, "rf4_log_plain_frames", False):
                self._log(
                    f"app {'C->S' if from_client else 'S->C'} "
                    f"flow={flow.id} frame_type={frame.frame_type} wire={frame.wire_id} "
                    f"body_len={len(plain_body)} {self._describe_plain_body(plain_body)}"
                )
            if from_client:
                plain_forward, injections = self._handle_client_frame(session, plain_body)
                if plain_forward is not None:
                    out.extend(session.build_client_forward_frame(frame.frame_type, frame.wire_id, plain_forward))
                for injected in injections:
                    ctx.master.commands.call("inject.tcp", flow, True, injected)
            else:
                out.extend(session.build_server_forward_frame(frame.frame_type, frame.wire_id, plain_body))
                out.extend(self._handle_server_frame(session, plain_body))

        return bytes(out)

    def _maybe_log_telemetry_frame(
        self,
        flow: tcp.TCPFlow,
        session: FlowSession,
        from_client: bool,
        plain_body: bytes,
    ) -> None:
        if not bool(getattr(ctx.options, "rf4_log_telemetry", True)):
            return
        try:
            telemetry = self._describe_telemetry_frame(session, from_client, plain_body)
        except Exception as exc:
            if ctx.options.rf4_verbose_logging:
                self._log(f"telemetry parse failed flow={flow.id}: {exc}")
            return
        if telemetry is None:
            return
        category, text = telemetry
        self._log_telemetry(category, text)

    def _describe_telemetry_frame(
        self,
        session: FlowSession,
        from_client: bool,
        plain_body: bytes,
    ) -> Optional[tuple[str, str]]:
        envelope = parse_envelope(plain_body)
        if envelope is None:
            if not bool(getattr(ctx.options, "rf4_log_unknown_telemetry", False)):
                return None
            direction = "C->S" if from_client else "S->C"
            return "unknown", f"{self._format_direction(direction)} 原始包 | 可读文本={self._format_ascii_strings(plain_body, limit=4)}"

        direction = "C->S" if from_client else "S->C"
        kind = "request" if envelope.marker == -1 else "response"
        prefix = self._telemetry_prefix(direction, kind, envelope)

        if from_client:
            keep_request = parse_keep_fish_request(envelope, session.profile)
            if keep_request:
                return (
                    "fish",
                    f"请求把鱼入护 | 钓组={self._short_id(keep_request.fishing_gear_id)} "
                    f"鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            public_chat = parse_public_chat_request(envelope, session.profile)
            if public_chat:
                return "chat", f"发送公共聊天 | 内容={self._quote_text(self._clean_text(public_chat.message or ''))}"

            ack_request = parse_room_ack_request(envelope, session.profile)
            if ack_request:
                if self._room_protocol_details_enabled():
                    return "room", f"{prefix} 补全房间消息发送者 | 消息ID={ack_request.event_id}"
                return None

            known = self._describe_known_client_business_telemetry(session, prefix, envelope)
            if known:
                return known

        else:
            fish_setup = parse_fish_setup_push(envelope, session.profile)
            if fish_setup:
                weight = self._format_chat_weight(fish_setup.weight_hint_raw) if fish_setup.weight_hint_raw else "unknown"
                length = f"{fish_setup.length_hint:.3f}" if fish_setup.length_hint is not None else "unknown"
                return (
                    "fish",
                    f"有鱼靠近 | 鱼={self._format_fish_name(fish_setup.fish_key)} "
                    f"鱼名key={fish_setup.fish_key} 预估重量={weight} 长度={length} "
                    f"鱼编号={self._short_id(fish_setup.fish_setup_id)} 钓组={self._short_id(fish_setup.fishing_gear_id)}",
                )

            broadcast = parse_room_broadcast(envelope, session.profile)
            if broadcast:
                if not self._room_protocol_details_enabled():
                    return None
                summary = self._format_room_push_summary(broadcast)
                if summary:
                    return "room", f"{prefix} {summary}"
                return None

            request_event_id = session.room_ack_calls.get(envelope.call_id)
            ack_response = parse_room_ack_response(envelope, session.profile)
            if ack_response:
                if not self._room_protocol_details_enabled():
                    return None
                event_id = ack_response.event_id if ack_response.event_id is not None else request_event_id
                return (
                    "room",
                    f"{prefix} 房间消息发送者已补全 | 消息ID={event_id} "
                    f"玩家={self._quote_text(ack_response.sender_name or '')} 等级={ack_response.sender_rank}",
                )

            keep_request = session.keep_requests.get(envelope.call_id)
            if keep_request and envelope.marker == -2:
                catch = extract_catch_summary_from_response(plain_body)
                fish_key = catch.fish_key
                weight_raw = catch.weight_raw
                if keep_request.fish_setup_id:
                    meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
                    if meta:
                        fish_key = fish_key or meta.fish_key
                        weight_raw = weight_raw or meta.weight_hint_raw
                fish_name = self._format_fish_name(fish_key) if fish_key else "unknown"
                weight = self._format_chat_weight(weight_raw) if weight_raw else "unknown"
                return (
                    "fish",
                    f"入护结果 | 鱼={fish_name} 鱼名key={fish_key or 'unknown'} "
                    f"重量={weight} 规格={catch.size_enum} 鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            known = self._describe_known_server_business_telemetry(session, prefix, envelope)
            if known:
                return known

        if not bool(getattr(ctx.options, "rf4_log_unknown_telemetry", False)):
            return None
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            return "unknown", f"{prefix} 未识别业务包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"
        return "unknown", f"{prefix} 未识别响应包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"

    def _describe_known_client_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        main_cmd = envelope.main_cmd
        sub_cmd = envelope.sub_cmd
        if main_cmd == profile.session_main_cmd:
            label = self.SESSION_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "session", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd == profile.player_main_cmd:
            label = self.PLAYER_COMMAND_LABELS.get(sub_cmd)
            if not label:
                return None
            if sub_cmd == 9:
                return "player", self._format_business_line(label, self._format_scene_pose_payload(envelope.payload))
            return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))

        if main_cmd == profile.feeding_main_cmd:
            label = self.FEEDING_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "feed", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd != profile.fishing_main_cmd:
            return None

        label = self.FISHING_COMMAND_LABELS.get(sub_cmd)
        if not label:
            return None
        if sub_cmd == profile.fight_step_sub_cmd:
            details = self._format_fish_move_payload(envelope.payload)
        elif sub_cmd == profile.fight_load_sub_cmd:
            details = self._format_fight_load_payload(envelope.payload)
        elif sub_cmd == profile.fight_stage_sub_cmd:
            details = self._format_fight_stage_payload(envelope.payload)
        elif sub_cmd == profile.contact_left_sub_cmd:
            details = self._format_contact_left_payload(envelope.payload)
        else:
            details = self._format_generic_business_payload(envelope.payload)
        return "fish", self._format_business_line(label, details)

    def _describe_known_server_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        if envelope.main_cmd == profile.server_player_main_cmd:
            if not self._low_level_telemetry_enabled():
                return None
            label = self.SERVER_PLAYER_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if envelope.main_cmd == profile.fishing_main_cmd:
            label = self.FISHING_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "fish", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
        return None

    @staticmethod
    def _format_business_line(label: str, details: str) -> str:
        if not details:
            return label
        if details.startswith("="):
            return f"{label} {details}"
        return f"{label} | {details}"

    def _format_scene_pose_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        group = self._first_float_group(summary, minimum=4) or self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            return f"={self._format_float_tuple(group[:3])}"
        parts = self._format_summary_tail(summary, include_u32=False, include_float_groups=False)
        return self._join_business_parts(parts, payload)

    def _format_fish_move_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"钓组坐标={self._format_float_tuple(group[:3])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_fight_load_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=4)
        if group and len(group) >= 4:
            parts.append(f"拉力方向={self._format_float_tuple((group[0], group[1], group[3]))}")
            parts.append(f"负载={self._format_float(group[2])}")
        elif group and len(group) >= 3:
            parts.append(f"向量={self._format_float_tuple(group[:3])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_fight_stage_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_contact_left_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        if summary.u32_values:
            parts.append(f"原因/序号={summary.u32_values[0]}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)

    def _format_generic_business_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts = self._format_arg_prefix(summary)
        parts.extend(self._format_summary_tail(summary))
        return self._join_business_parts(parts, payload)

    def _summarize_business_payload(self, payload: bytes) -> BusinessPayloadSummary:
        arg_count = None
        try:
            arg_count, _ = read_arg_header(payload, 0)
        except (ValueError, IndexError):
            arg_count = None
        strings = self._scan_payload_strings(payload, limit=6)
        guids = self._scan_guid_markers(payload, limit=4)
        u32_values = self._scan_marked_u32_values(payload, limit=6)
        float_groups = self._scan_float_groups(payload, limit=4)
        return BusinessPayloadSummary(
            arg_count=arg_count,
            strings=strings,
            guids=guids,
            u32_values=u32_values,
            float_groups=float_groups,
        )

    def _scan_payload_strings(self, data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos < len(data):
            idx = data.find(b"\x14", pos)
            if idx < 0:
                break
            try:
                value, next_pos = read_marked_string(data, idx)
            except (ValueError, IndexError, UnicodeDecodeError):
                pos = idx + 1
                continue
            if value and self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))
            pos = max(next_pos, idx + 1)

        for value in ascii_strings(data, min_len=8):
            if len(values) >= limit:
                break
            if self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))

        return tuple(self._unique_limited(values, limit))

    @staticmethod
    def _payload_string_is_interesting(value: str) -> bool:
        text = value.strip()
        if not text or text in {"507", "135"}:
            return False
        if "\ufffd" in text:
            return False
        if len(text) <= 2 and text.isascii():
            return False
        if text.isascii() and len(text) < 6 and not any(ch in text for ch in "._[]"):
            return False
        if all(ch.isdigit() or ch in ".-_:/" for ch in text):
            return False
        return True

    @staticmethod
    def _scan_guid_markers(data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos + 17 <= len(data):
            idx = data.find(b"\x0c", pos)
            if idx < 0 or idx + 17 > len(data):
                break
            raw = data[idx + 1:idx + 17]
            if raw != b"\x00" * 16:
                try:
                    value = guid_le(raw)
                except (ValueError, AttributeError):
                    pos = idx + 1
                    continue
                if value not in values:
                    values.append(value)
            pos = idx + 17
        return tuple(values)

    @staticmethod
    def _scan_marked_u32_values(data: bytes, limit: int) -> Tuple[int, ...]:
        values: List[int] = []
        pos = 0
        while len(values) < limit and pos + 5 <= len(data):
            idx = data.find(b"\x10", pos)
            if idx < 0 or idx + 5 > len(data):
                break
            value = u32(data, idx + 1)
            if 0 <= value <= 0x7FFFFFFF and value not in values:
                values.append(value)
            pos = idx + 5
        return tuple(values)

    def _scan_float_groups(self, data: bytes, limit: int) -> Tuple[Tuple[float, ...], ...]:
        groups: List[Tuple[float, ...]] = []
        pos = 0
        while len(groups) < limit and pos + 12 <= len(data):
            group = self._read_float_group_at(data, pos, 4)
            if group is None:
                group = self._read_float_group_at(data, pos, 3)
            if group is None:
                pos += 1
                continue
            if not groups or not self._same_float_group(groups[-1], group):
                groups.append(group)
            pos += len(group) * 4
        return tuple(groups)

    def _read_float_group_at(self, data: bytes, pos: int, count: int) -> Optional[Tuple[float, ...]]:
        if pos + count * 4 > len(data):
            return None
        values = struct.unpack_from("<" + "f" * count, data, pos)
        if not self._usable_float_group(values):
            return None
        return tuple(values)

    @staticmethod
    def _usable_float_group(values: Tuple[float, ...]) -> bool:
        if not values:
            return False
        usable = []
        for value in values:
            if not math.isfinite(value):
                return False
            if abs(value) > 100000.0:
                return False
            if value != 0.0 and abs(value) < 0.000001:
                return False
            usable.append(value)
        if not any(abs(value) >= 0.01 for value in usable):
            return False
        return True

    @staticmethod
    def _same_float_group(left: Tuple[float, ...], right: Tuple[float, ...]) -> bool:
        if len(left) != len(right):
            return False
        return all(abs(a - b) < 0.0001 for a, b in zip(left, right))

    @staticmethod
    def _format_arg_prefix(summary: BusinessPayloadSummary) -> List[str]:
        return [f"参数={summary.arg_count}"] if summary.arg_count is not None else []

    def _format_summary_tail(
        self,
        summary: BusinessPayloadSummary,
        include_guids: bool = True,
        include_u32: bool = True,
        include_float_groups: bool = True,
    ) -> List[str]:
        parts: List[str] = []
        if include_guids and summary.guids:
            parts.append("编号=[" + ", ".join(self._short_id(value) for value in summary.guids) + "]")
        if summary.strings:
            parts.append("文本=[" + ", ".join(self._quote_text(value, limit=40) for value in summary.strings) + "]")
        if include_u32 and summary.u32_values:
            parts.append("数值=[" + ", ".join(str(value) for value in summary.u32_values) + "]")
        if include_float_groups and summary.float_groups:
            parts.append("浮点=[" + ", ".join(self._format_float_tuple(group) for group in summary.float_groups[:3]) + "]")
        return parts

    @staticmethod
    def _join_business_parts(parts: List[str], payload: bytes) -> str:
        if parts:
            return " ".join(parts)
        return f"原始长度={len(payload)}字节"

    @staticmethod
    def _first_guid(summary: BusinessPayloadSummary) -> Optional[str]:
        return summary.guids[0] if summary.guids else None

    @staticmethod
    def _last_u32(summary: BusinessPayloadSummary) -> Optional[int]:
        return summary.u32_values[-1] if summary.u32_values else None

    @staticmethod
    def _first_float_group(summary: BusinessPayloadSummary, minimum: int) -> Optional[Tuple[float, ...]]:
        for group in summary.float_groups:
            if len(group) >= minimum:
                return group
        return None

    def _format_float_tuple(self, values: Tuple[float, ...]) -> str:
        return "(" + ",".join(self._format_float(value) for value in values) + ")"

    @staticmethod
    def _format_float(value: float) -> str:
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "+inf" if value > 0 else "-inf"
        if abs(value) > 1000000.0 or (value != 0.0 and abs(value) < 0.000001):
            return f"{value:.3e}"
        text = f"{value:.3f}".rstrip("0").rstrip(".")
        return text if text else "0"

    @staticmethod
    def _unique_limited(values: List[str], limit: int) -> List[str]:
        out: List[str] = []
        for value in values:
            if value in out:
                continue
            out.append(value)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _telemetry_prefix(direction: str, kind: str, envelope: RpcEnvelope) -> str:
        kind_text = "请求" if kind == "request" else "响应"
        parts = [RF4ChatBridge._format_direction(direction), f"{kind_text}#{envelope.call_id}"]
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            parts.append(f"协议{envelope.main_cmd}/{envelope.sub_cmd}")
        return " ".join(parts)

    @staticmethod
    def _format_direction(direction: str) -> str:
        return "客户端->服务器" if direction == "C->S" else "服务器->客户端"

    def _format_room_push_summary(self, broadcast: RoomBroadcast) -> Optional[str]:
        if not broadcast.fish_key or not broadcast.weight_raw:
            if self._room_protocol_details_enabled():
                return f"房间状态更新 | {self._format_room_telemetry(broadcast)}"
            return None

        fish_name = self._format_fish_name(broadcast.fish_key)
        weight = self._format_chat_weight(broadcast.weight_raw)
        grade = self._format_grade_label(broadcast.line_type)
        if broadcast.line_type in {21, 22}:
            record_class = self._record_class_label(broadcast)
            label = f"频道记录[{record_class}]" if record_class else "频道记录"
            text = f"{label}：有人钓到 {fish_name} {weight}"
        elif grade:
            text = f"频道鱼获：有人钓到 [{grade}] {fish_name} {weight}"
        else:
            text = f"频道鱼获：有人钓到 {fish_name} {weight}"

        extras = []
        if broadcast.location_id:
            extras.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            extras.append(f"房间人数={broadcast.users_count}")
        if self._room_protocol_details_enabled():
            extras.append(f"消息ID={broadcast.event_id}")
            extras.append(f"类型={broadcast.line_type}")
        if extras:
            return f"{text}（{'，'.join(extras)}）"
        return text

    def _format_room_telemetry(self, broadcast: RoomBroadcast) -> str:
        parts = [
            f"事件={broadcast.event_id}",
            f"类型={broadcast.line_type}",
        ]
        if broadcast.fish_key:
            parts.append(f"鱼={self._format_fish_name(broadcast.fish_key)}")
            parts.append(f"鱼名key={broadcast.fish_key}")
        if broadcast.weight_raw:
            parts.append(f"重量={self._format_chat_weight(broadcast.weight_raw)}")
        if broadcast.location_id:
            parts.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            parts.append(f"人数={broadcast.users_count}")
        details = self._format_room_detail_items(broadcast.details)
        if details:
            parts.append(f"明细={details}")
        return " ".join(parts)

    @staticmethod
    def _format_room_detail_items(details: Tuple[RoomDetailItem, ...]) -> str:
        if not details:
            return ""
        formatted = []
        for item in details[:8]:
            kind = "文本" if item.kind == "string" else "数值" if item.kind == "u32" else item.kind
            formatted.append(f"{item.slot}:{kind}={item.value}")
        if len(details) > 8:
            formatted.append("...")
        return "[" + ", ".join(formatted) + "]"

    @staticmethod
    def _short_id(value: Optional[str]) -> str:
        if not value:
            return "unknown"
        if len(value) <= 12:
            return value
        return value[:8] + "..."

    def _handle_client_frame(
        self,
        session: FlowSession,
        plain_body: bytes,
    ) -> tuple[Optional[bytes], List[bytes]]:
        envelope = parse_envelope(plain_body)
        if not envelope:
            return plain_body, []

        keep_request = parse_keep_fish_request(envelope, session.profile)
        if keep_request:
            session.keep_requests[keep_request.call_id] = keep_request
            return plain_body, []

        public_chat = parse_public_chat_request(envelope, session.profile)
        if public_chat and public_chat.message:
            self._log_event(f"\u4f60: {self._clean_text(public_chat.message)}")
            return plain_body, []

        ack_request = parse_room_ack_request(envelope, session.profile)
        if ack_request and ack_request.event_id is not None:
            synthetic = session.synthetic_events.pop(ack_request.event_id, None)
            if synthetic:
                session.room_events.pop(ack_request.event_id, None)
            else:
                session.room_ack_calls[envelope.call_id] = ack_request.event_id

            if synthetic:
                response_body = build_room_ack_response_body(
                    profile=session.profile,
                    call_id=envelope.call_id,
                    event_id=synthetic.event_id,
                    sender_name=synthetic.sender_name,
                    avatar_url=ctx.options.rf4_avatar_url,
                    sender_level=ctx.options.rf4_sender_level,
                    sender_region=ctx.options.rf4_sender_region,
                    sender_class=ctx.options.rf4_sender_class,
                    sender_badge=ctx.options.rf4_sender_badge,
                )
                injected = session.build_server_injection(response_body)
                return None, [injected]

        return plain_body, []

    def _handle_server_frame(self, session: FlowSession, plain_body: bytes) -> bytes:
        envelope = parse_envelope(plain_body)
        out = bytearray()
        if not envelope:
            return bytes(out)

        fish_setup = parse_fish_setup_push(envelope, session.profile)
        if fish_setup:
            session.fish_setup_cache[fish_setup.fish_setup_id] = fish_setup
            if (
                fish_setup.weight_hint_raw
                and fish_setup.fish_setup_id not in session.announced_fish_setup_ids
            ):
                session.announced_fish_setup_ids.add(fish_setup.fish_setup_id)
                synthetic = self._build_self_synthetic_event(
                    session=session,
                    fish_key=fish_setup.fish_key,
                    weight_raw=fish_setup.weight_hint_raw,
                    phase=self.SELF_EVENT_PHASE_INCOMING,
                )
                out.extend(self._emit_self_event(session, synthetic))
            return bytes(out)

        broadcast = parse_room_broadcast(envelope, session.profile)
        if broadcast:
            self._remember_room_context(session, broadcast)
            session.room_events[broadcast.event_id] = broadcast
            return bytes(out)

        request_event_id = session.room_ack_calls.pop(envelope.call_id, None)
        ack_response = parse_room_ack_response(envelope, session.profile)
        if ack_response:
            event_id = ack_response.event_id if ack_response.event_id is not None else request_event_id
            broadcast = session.room_events.pop(event_id, None) if event_id is not None else None
            line = self._format_room_chat_line(
                sender_name=ack_response.sender_name,
                broadcast=broadcast,
            )
            if line:
                self._log_event(line)
            return bytes(out)

        keep_request = session.keep_requests.pop(envelope.call_id, None)
        if keep_request and envelope.marker == -2:
            synthetic = self._build_synthetic_broadcast(session, keep_request, plain_body)
            catch = extract_catch_summary_from_response(plain_body)
            if keep_request.fish_setup_id:
                session.announced_fish_setup_ids.discard(keep_request.fish_setup_id)
            if synthetic is None and catch.fish_key and catch.weight_raw:
                self._log_self_event(
                    self._format_self_event_log_line(
                        SyntheticChatEvent(
                            event_id=0,
                            fish_key=catch.fish_key,
                            weight_raw=catch.weight_raw,
                            location_id="",
                            users_count=0,
                            phase=self.SELF_EVENT_PHASE_KEPT,
                        )
                    )
                )
            if synthetic:
                out.extend(self._emit_self_event(session, synthetic))

        return bytes(out)

    def _remember_room_context(self, session: FlowSession, broadcast: RoomBroadcast) -> None:
        if broadcast.location_id is not None:
            session.latest_location_id = broadcast.location_id
        if broadcast.users_count is not None:
            session.latest_users_count = broadcast.users_count

    def _build_synthetic_broadcast(
        self,
        session: FlowSession,
        keep_request: KeepFishRequest,
        plain_body: bytes,
    ) -> Optional[SyntheticChatEvent]:
        catch = extract_catch_summary_from_response(plain_body)
        fish_key = catch.fish_key
        if not fish_key and keep_request.fish_setup_id:
            meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
            if meta:
                fish_key = meta.fish_key

        weight_raw = catch.weight_raw
        if weight_raw is None and keep_request.fish_setup_id:
            meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
            if meta:
                weight_raw = meta.weight_hint_raw
        if not fish_key or not weight_raw:
            return None

        return self._build_self_synthetic_event(
            session=session,
            fish_key=fish_key,
            weight_raw=weight_raw,
            phase=self.SELF_EVENT_PHASE_KEPT,
        )

    def _build_self_synthetic_event(
        self,
        session: FlowSession,
        fish_key: str,
        weight_raw: int,
        phase: str,
    ) -> SyntheticChatEvent:
        location_id = session.latest_location_id
        if location_id is None:
            location_id = ctx.options.rf4_default_location_id

        users_count = session.latest_users_count
        if users_count is None:
            users_count = ctx.options.rf4_default_users_count

        return SyntheticChatEvent(
            event_id=session.alloc_event_id(),
            fish_key=fish_key,
            weight_raw=weight_raw,
            location_id=location_id,
            users_count=users_count,
            phase=phase,
            sender_name=self._self_sender_name(phase),
            line_type=session.profile.room_message_line_type_catch,
        )

    def _inject_self_synthetic_event(self, session: FlowSession, synthetic: SyntheticChatEvent) -> bytes:
        session.synthetic_events[synthetic.event_id] = synthetic
        session.room_events[synthetic.event_id] = RoomBroadcast(
            line_type=synthetic.line_type,
            event_id=synthetic.event_id,
            fish_key=synthetic.fish_key,
            weight_raw=synthetic.weight_raw,
            location_id=synthetic.location_id,
            users_count=synthetic.users_count,
        )
        injected_body = build_room_message_push_body(
            profile=session.profile,
            call_id=session.alloc_call_id(),
            event_id=synthetic.event_id,
            fish_key=synthetic.fish_key,
            weight_raw=synthetic.weight_raw,
            location_id=synthetic.location_id,
            users_count=synthetic.users_count,
            line_type=synthetic.line_type,
        )
        return session.build_server_injection(injected_body)

    def _emit_self_event(self, session: FlowSession, synthetic: SyntheticChatEvent) -> bytes:
        self._log_self_event(self._format_self_event_log_line(synthetic))
        if not self._self_chat_injection_enabled():
            return b""
        return self._inject_self_synthetic_event(session, synthetic)

    @staticmethod
    def _format_weight(weight_raw: Optional[int]) -> str:
        if not weight_raw:
            return "unknown"
        return f"{weight_raw}g/{weight_raw / 1000:.3f}kg"

    def _format_room_chat_line(self, sender_name: Optional[str], broadcast: Optional[RoomBroadcast]) -> Optional[str]:
        if not broadcast:
            return None
        if broadcast.weight_raw and broadcast.fish_key:
            if broadcast.line_type in {21, 22}:
                return self._format_record_chat_line(sender_name or "unknown", broadcast)
            return self._format_catch_chat_line(
                sender_name or "unknown",
                broadcast.fish_key,
                broadcast.weight_raw,
                line_type=broadcast.line_type,
            )
        if broadcast.fish_key:
            text = self._clean_text(broadcast.fish_key)
            if sender_name:
                return f"{sender_name}: {text}"
            return text
        return None

    def _format_catch_chat_line(
        self,
        sender_name: str,
        fish_key: str,
        weight_raw: int,
        line_type: Optional[int] = None,
    ) -> str:
        fish_name = self._format_fish_name(fish_key)
        grade = self._format_grade_label(line_type)
        if grade:
            return f"{sender_name} 钓到了 [{grade}] {self._format_chat_weight(weight_raw)} {fish_name}"
        return f"{sender_name} 钓到了 {self._format_chat_weight(weight_raw)} {fish_name}"

    def _format_self_event_log_line(self, event: SyntheticChatEvent) -> str:
        fish_name = self._format_fish_name(event.fish_key)
        weight = self._format_chat_weight(event.weight_raw)
        if event.phase == self.SELF_EVENT_PHASE_INCOMING:
            return f"【我自己】： 有{fish_name} {weight} 过来了"
        return f"【我自己】： 有{fish_name} {weight} 入护了"

    def _format_record_chat_line(self, sender_name: str, broadcast: RoomBroadcast) -> str:
        fish_name = self._format_fish_name(broadcast.fish_key or "")
        record_class = self._record_class_label(broadcast)
        if record_class:
            return f"{sender_name} 记录[{record_class}] 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"
        return f"{sender_name} 记录 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"

    def _format_fish_name(self, fish_key: str) -> str:
        return self._fish_labels_zh.get(fish_key, fish_key)

    def _self_sender_name(self, phase: str) -> str:
        if phase == self.SELF_EVENT_PHASE_INCOMING:
            return "【我自己·过来了】"
        return "【我自己·入护了】"

    def _format_grade_label(self, line_type: Optional[int]) -> Optional[str]:
        if line_type is None:
            return None
        return self.GRADE_LABELS_BY_LINE_TYPE.get(line_type)

    def _record_class_label(self, broadcast: RoomBroadcast) -> Optional[str]:
        for item in broadcast.details:
            if item.slot == 6 and item.kind == "string" and item.value:
                return self.RECORD_CLASS_LABELS.get(str(item.value), str(item.value))
        return None

    @staticmethod
    def _format_chat_weight(weight_raw: int) -> str:
        if weight_raw < 1000:
            return f"{weight_raw} 克"
        return f"{weight_raw / 1000:.3f} 公斤"

    @staticmethod
    def _clean_text(text: str) -> str:
        return " ".join(text.replace("\r", " ").replace("\n", " ").split())

    def _log_http_message(self, label: str, headline: str, headers, body_text: str) -> None:
        header_lines = self._format_headers(headers)
        parts = [label, headline]
        if header_lines:
            parts.extend(header_lines)
        else:
            parts.append("<no headers>")
        parts.append("")
        parts.append(body_text if body_text else "<empty body>")
        self._log("\n".join(parts))

    def _describe_plain_body(self, plain_body: bytes) -> str:
        envelope = parse_envelope(plain_body)
        if envelope is None:
            strings = self._format_ascii_strings(plain_body)
            return (
                f"plain=raw ascii={strings} "
                f"hex={self._hex_preview(plain_body)}"
            )

        label = "request" if envelope.marker == -1 else "response"
        details = [f"plain={label}", f"call={envelope.call_id}"]
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            details.append(f"cmd={envelope.main_cmd}/{envelope.sub_cmd}")
        payload = envelope.payload or plain_body
        details.append(f"ascii={self._format_ascii_strings(payload)}")
        details.append(f"hex={self._hex_preview(payload)}")
        return " ".join(details)

    @staticmethod
    def _format_headers(headers) -> List[str]:
        if headers is None:
            return []
        items = None
        if hasattr(headers, "items"):
            try:
                items = headers.items(multi=True)
            except TypeError:
                items = headers.items()
        if items is None:
            return [str(headers)]
        return [f"{key}: {value}" for key, value in items]

    @staticmethod
    def _extract_message_text(message) -> str:
        if message is None:
            return ""
        getter = getattr(message, "get_text", None)
        if callable(getter):
            try:
                return getter(strict=False)
            except TypeError:
                try:
                    return getter()
                except ValueError:
                    pass
            except ValueError:
                pass
        raw_content = getattr(message, "raw_content", None)
        if raw_content in (None, b""):
            return ""
        if isinstance(raw_content, bytes):
            return raw_content.decode("utf-8", errors="replace")
        return str(raw_content)

    @staticmethod
    def _format_ascii_strings(data: bytes, limit: int = 8) -> str:
        values = []
        for value in ascii_strings(data, min_len=4):
            if value in values:
                continue
            values.append(value)
            if len(values) >= limit:
                break
        if not values:
            return "<none>"
        compact = [RF4ChatBridge._quote_text(value, limit=80) for value in values]
        joined = ", ".join(compact)
        if len(values) >= limit and len(ascii_strings(data, min_len=4)) > limit:
            joined += ", ..."
        return joined

    @staticmethod
    def _hex_preview(data: bytes, limit: int = 96) -> str:
        preview = data[:limit].hex()
        if len(data) > limit:
            preview += "..."
        return preview or "<empty>"

    @staticmethod
    def _quote_text(text: str, limit: int = 120) -> str:
        compact = text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
        if len(compact) > limit:
            compact = compact[:limit - 3] + "..."
        return f'"{compact}"'

if __name__ != "__main__":
    addons = [RF4ChatBridge()]
else:
    addons = []

if __name__ == "__main__":
    raise SystemExit(main())
