#!/usr/bin/env python3
"""SMB security posture audit helper.

This script performs defensive SMB checks only. It does not implement
pass-the-hash, credential spraying, or remote command execution.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import os
import platform
import socket
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


DEFAULT_PORTS = (445, 139)


@dataclass
class Risk:
    severity: str
    finding: str
    recommendation: str


@dataclass
class SMBFinding:
    host: str
    tcp_445_open: bool = False
    tcp_139_open: bool = False
    smb_reachable: bool = False
    dialect: str | None = None
    server_name: str | None = None
    server_domain: str | None = None
    server_os: str | None = None
    signing_required: bool | None = None
    anonymous_login_allowed: bool | None = None
    anonymous_shares: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    risks: list[Risk] = field(default_factory=list)


@dataclass
class LogFinding:
    severity: str
    event_id: int
    finding: str
    user: str | None = None
    source_ip: str | None = None
    host: str | None = None
    detail: str | None = None
    recommendation: str | None = None


@dataclass
class HardeningCheck:
    control: str
    status: str
    observed: str
    recommendation: str


@dataclass
class ManagementFinding:
    host: str
    winrm_http_open: bool = False
    winrm_https_open: bool = False
    ssh_open: bool = False
    risks: list[Risk] = field(default_factory=list)


@dataclass
class CommandResult:
    host: str
    protocol: str
    command: str
    executed: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


def expand_targets(
    values: Iterable[str], target_file: Path | None, max_hosts: int
) -> list[str]:
    raw_targets: list[str] = []
    for value in values:
        raw_targets.extend(split_target_line(value))

    if target_file:
        for line in target_file.read_text(encoding="utf-8").splitlines():
            raw_targets.extend(split_target_line(line))

    expanded: list[str] = []
    for target in raw_targets:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(host) for host in network.hosts()]
            if max_hosts and len(hosts) > max_hosts:
                raise ValueError(
                    f"{target} expands to {len(hosts)} hosts; "
                    f"increase --max-hosts or narrow the CIDR"
                )
            expanded.extend(hosts)
        else:
            expanded.append(target)

    return sorted(dict.fromkeys(expanded))


def split_target_line(value: str) -> list[str]:
    cleaned = value.split("#", 1)[0].strip()
    if not cleaned:
        return []
    return [part.strip() for part in cleaned.replace(",", " ").split() if part.strip()]


def check_tcp_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def audit_host(host: str, timeout: float, check_anonymous: bool) -> SMBFinding:
    finding = SMBFinding(host=host)
    finding.tcp_445_open = check_tcp_port(host, 445, timeout)
    finding.tcp_139_open = check_tcp_port(host, 139, timeout)

    if finding.tcp_445_open:
        probe_smb(host, timeout, check_anonymous, finding)

    finding.risks = evaluate_risks(finding)
    return finding


def audit_management_host(host: str, timeout: float) -> ManagementFinding:
    finding = ManagementFinding(host=host)
    finding.winrm_http_open = check_tcp_port(host, 5985, timeout)
    finding.winrm_https_open = check_tcp_port(host, 5986, timeout)
    finding.ssh_open = check_tcp_port(host, 22, timeout)
    finding.risks = evaluate_management_risks(finding)
    return finding


def run_ssh_command(
    host: str,
    command: str,
    username: str,
    password: str | None,
    key_file: Path | None,
    port: int,
    timeout: float,
    auto_add_host_key: bool,
) -> CommandResult:
    try:
        import paramiko
    except ImportError:
        return CommandResult(
            host=host,
            protocol="ssh",
            command=command,
            executed=False,
            error="paramiko is not installed; install requirements.txt",
        )

    client = paramiko.SSHClient()
    if auto_add_host_key:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=str(key_file) if key_file else None,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=key_file is None and password is None,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(
            host=host,
            protocol="ssh",
            command=command,
            executed=True,
            exit_code=exit_code,
            stdout=stdout.read().decode("utf-8", errors="replace"),
            stderr=stderr.read().decode("utf-8", errors="replace"),
        )
    except Exception as exc:  # noqa: BLE001 - paramiko has several exception types
        return CommandResult(
            host=host,
            protocol="ssh",
            command=command,
            executed=False,
            error=str(exc),
        )
    finally:
        client.close()


def run_winrm_command(
    host: str,
    command: str,
    username: str,
    password: str,
    port: int,
    timeout: float,
    transport: str,
    use_ssl: bool,
    ignore_cert: bool,
) -> CommandResult:
    try:
        import winrm
    except ImportError:
        return CommandResult(
            host=host,
            protocol="winrm",
            command=command,
            executed=False,
            error="pywinrm is not installed; install requirements.txt",
        )

    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    cert_validation = "ignore" if ignore_cert else "validate"

    try:
        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation=cert_validation,
            operation_timeout_sec=max(1, int(timeout)),
            read_timeout_sec=max(2, int(timeout) + 10),
        )
        result = session.run_cmd("cmd.exe", ["/c", command])
        return CommandResult(
            host=host,
            protocol="winrm",
            command=command,
            executed=True,
            exit_code=result.status_code,
            stdout=result.std_out.decode("utf-8", errors="replace"),
            stderr=result.std_err.decode("utf-8", errors="replace"),
        )
    except Exception as exc:  # noqa: BLE001 - pywinrm wraps transport exceptions
        return CommandResult(
            host=host,
            protocol="winrm",
            command=command,
            executed=False,
            error=str(exc),
        )


def probe_smb(
    host: str, timeout: float, check_anonymous: bool, finding: SMBFinding
) -> None:
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        finding.errors.append("impacket is not installed; SMB negotiation skipped")
        return

    conn = None
    try:
        conn = SMBConnection(
            remoteName=host,
            remoteHost=host,
            sess_port=445,
            timeout=timeout,
        )
        finding.smb_reachable = True
        finding.dialect = dialect_name(conn.getDialect())
        finding.server_name = safe_call(conn.getServerName)
        finding.server_domain = safe_call(conn.getServerDomain)
        finding.server_os = safe_call(conn.getServerOS)
        finding.signing_required = get_signing_required(conn)

        if check_anonymous:
            probe_anonymous_login(conn, finding)
    except Exception as exc:  # noqa: BLE001 - impacket exposes several exception types
        finding.errors.append(f"SMB negotiation failed: {exc}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def safe_call(func) -> str | None:
    try:
        value = func()
    except Exception:
        return None
    return str(value) if value not in (None, "") else None


def dialect_name(value) -> str:
    try:
        from impacket.smbconnection import SMB_DIALECT
        from impacket.smb3structs import (
            SMB2_DIALECT_002,
            SMB2_DIALECT_21,
            SMB2_DIALECT_30,
            SMB2_DIALECT_302,
            SMB2_DIALECT_311,
        )
    except ImportError:
        return str(value)

    dialects = {
        SMB_DIALECT: "SMBv1",
        SMB2_DIALECT_002: "SMB 2.0.2",
        SMB2_DIALECT_21: "SMB 2.1",
        SMB2_DIALECT_30: "SMB 3.0",
        SMB2_DIALECT_302: "SMB 3.0.2",
        SMB2_DIALECT_311: "SMB 3.1.1",
    }
    return dialects.get(value, str(value))


def get_signing_required(conn) -> bool | None:
    candidates = [conn, getattr(conn, "_SMBConnection", None)]
    for candidate in candidates:
        if candidate is None:
            continue
        method = getattr(candidate, "isSigningRequired", None)
        if callable(method):
            try:
                return bool(method())
            except Exception:
                continue
    return None


def probe_anonymous_login(conn, finding: SMBFinding) -> None:
    try:
        conn.login("", "")
        finding.anonymous_login_allowed = True
        finding.anonymous_shares = sorted(
            share["shi1_netname"][:-1]
            for share in conn.listShares()
            if share.get("shi1_netname")
        )
    except Exception:
        finding.anonymous_login_allowed = False


def evaluate_risks(finding: SMBFinding) -> list[Risk]:
    risks: list[Risk] = []

    if not finding.tcp_445_open and not finding.tcp_139_open:
        return risks

    if finding.dialect == "SMBv1":
        risks.append(
            Risk(
                severity="HIGH",
                finding="SMBv1 is enabled",
                recommendation="Disable SMBv1 and require SMB 2.1+ or SMB 3.x.",
            )
        )

    if finding.signing_required is False:
        risks.append(
            Risk(
                severity="MEDIUM",
                finding="SMB signing is not required",
                recommendation="Require SMB signing for servers that handle sensitive data.",
            )
        )

    if finding.anonymous_login_allowed is True:
        risks.append(
            Risk(
                severity="HIGH",
                finding="Anonymous SMB session is allowed",
                recommendation="Restrict null sessions and review share permissions.",
            )
        )

    if finding.tcp_445_open and not finding.smb_reachable:
        risks.append(
            Risk(
                severity="INFO",
                finding="TCP/445 is open but SMB details could not be collected",
                recommendation="Install impacket locally or check firewall and SMB negotiation policy.",
            )
        )

    return risks


def evaluate_management_risks(finding: ManagementFinding) -> list[Risk]:
    risks: list[Risk] = []

    if finding.winrm_http_open:
        risks.append(
            Risk(
                severity="MEDIUM",
                finding="WinRM HTTP listener is reachable",
                recommendation=(
                    "Verify WinRM authentication and message encryption policy; "
                    "prefer HTTPS or Kerberos-protected administrative networks."
                ),
            )
        )

    if finding.winrm_https_open:
        risks.append(
            Risk(
                severity="INFO",
                finding="WinRM HTTPS listener is reachable",
                recommendation="Confirm certificate trust, allowed administrators, and firewall scope.",
            )
        )

    if finding.ssh_open:
        risks.append(
            Risk(
                severity="INFO",
                finding="SSH management listener is reachable",
                recommendation="Require key-based or MFA-backed access and restrict source networks.",
            )
        )

    return risks


def load_event_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            return list(csv.DictReader(handle))
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("Events", "events", "Records", "records"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [data]
        raise ValueError("JSON event input must be an object or list of objects")
    if suffix == ".xml":
        return load_xml_event_records(path)
    raise ValueError("supported event formats: .csv, .json, .xml")


def load_xml_event_records(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    root = tree.getroot()
    events = root.findall(".//{*}Event")
    if root.tag.endswith("Event"):
        events = [root]

    records: list[dict[str, Any]] = []
    for event in events:
        record: dict[str, Any] = {}
        for child in event.findall("./{*}System/*"):
            name = strip_namespace(child.tag)
            if name == "EventID":
                record["EventID"] = child.text
            elif name == "Computer":
                record["Computer"] = child.text
            elif name == "TimeCreated":
                record["TimeCreated"] = child.attrib.get("SystemTime")

        for data in event.findall(".//{*}EventData/{*}Data"):
            key = data.attrib.get("Name")
            if key:
                record[key] = data.text
        records.append(record)
    return records


def strip_namespace(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def normalized_key(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def event_value(record: dict[str, Any], *names: str) -> str | None:
    lookup = {normalized_key(str(key)): value for key, value in record.items()}
    for name in names:
        value = lookup.get(normalized_key(name))
        if value not in (None, ""):
            return str(value)
    return None


def event_id(record: dict[str, Any]) -> int | None:
    raw = event_value(record, "EventID", "Event ID", "Id")
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def analyze_event_records(records: list[dict[str, Any]]) -> list[LogFinding]:
    findings: list[LogFinding] = []
    for record in records:
        finding = analyze_event_record(record)
        if finding:
            findings.append(finding)
    return findings


def analyze_event_record(record: dict[str, Any]) -> LogFinding | None:
    eid = event_id(record)
    if eid is None:
        return None

    user = event_value(record, "TargetUserName", "Account Name", "User")
    host = event_value(record, "Computer", "WorkstationName", "Workstation Name")
    source_ip = event_value(
        record, "IpAddress", "Source Network Address", "Client Address", "SourceIP"
    )
    logon_type = event_value(record, "LogonType", "Logon Type")
    auth_package = event_value(
        record, "AuthenticationPackageName", "Authentication Package"
    )
    share_name = event_value(record, "ShareName", "Share Name")

    if eid == 4624 and logon_type == "3" and contains(auth_package, "NTLM"):
        return LogFinding(
            severity="MEDIUM",
            event_id=eid,
            finding="Successful network logon used NTLM",
            user=user,
            source_ip=source_ip,
            host=host,
            detail=f"authentication_package={auth_package}",
            recommendation=(
                "Confirm this NTLM network logon is expected; correlate with source host, "
                "privileged group use, and administrative share access."
            ),
        )

    if eid == 4625 and logon_type == "3":
        return LogFinding(
            severity="LOW",
            event_id=eid,
            finding="Failed network logon",
            user=user,
            source_ip=source_ip,
            host=host,
            recommendation="Review repeated failures for password guessing or stale services.",
        )

    if eid == 4672:
        return LogFinding(
            severity="LOW",
            event_id=eid,
            finding="Special privileges assigned to a new logon",
            user=user,
            source_ip=source_ip,
            host=host,
            recommendation="Correlate with nearby network logon events and administrator activity.",
        )

    if eid == 4776:
        return LogFinding(
            severity="MEDIUM",
            event_id=eid,
            finding="NTLM authentication was validated",
            user=user,
            source_ip=source_ip,
            host=host,
            detail=f"auth_package={auth_package}",
            recommendation="Reduce NTLM where Kerberos is available and monitor unusual sources.",
        )

    if eid == 5140 and share_name and is_admin_share(share_name):
        return LogFinding(
            severity="MEDIUM",
            event_id=eid,
            finding="Administrative SMB share was accessed",
            user=user,
            source_ip=source_ip,
            host=host,
            detail=f"share={share_name}",
            recommendation="Confirm the admin share access matches approved operations.",
        )

    return None


def contains(value: str | None, needle: str) -> bool:
    return value is not None and needle.lower() in value.lower()


def is_admin_share(value: str) -> bool:
    share = value.replace("\\", "/").rstrip("/").split("/")[-1].upper()
    return share in {"ADMIN$", "C$", "D$", "IPC$"}


def run_hardening_checks() -> list[HardeningCheck]:
    if platform.system() != "Windows":
        return [
            HardeningCheck(
                control="Windows local SMB hardening",
                status="UNKNOWN",
                observed=f"Unsupported platform: {platform.system()}",
                recommendation="Run this check on the Windows host being assessed.",
            )
        ]

    return [
        check_reg_dword(
            "SMBv1 server disabled",
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
            pass_values={0},
            missing_status="PASS",
            missing_observed="SMB1 value is not set; modern Windows defaults to disabled.",
            recommendation="Set SMB1=0 or remove the SMBv1 feature.",
        ),
        check_reg_dword(
            "SMB server signing required",
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "RequireSecuritySignature",
            pass_values={1},
            missing_status="WARN",
            missing_observed="RequireSecuritySignature is not configured.",
            recommendation="Set RequireSecuritySignature=1 on sensitive SMB servers.",
        ),
        check_reg_dword(
            "Restrict anonymous access",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymous",
            pass_values={1, 2},
            missing_status="WARN",
            missing_observed="RestrictAnonymous is not configured.",
            recommendation="Restrict null sessions and anonymous SAM enumeration.",
        ),
        check_reg_dword(
            "NTLM compatibility level",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
            pass_values={5},
            missing_status="WARN",
            missing_observed="LmCompatibilityLevel is not configured.",
            recommendation="Prefer LmCompatibilityLevel=5 where legacy compatibility allows.",
        ),
        check_reg_dword(
            "Remote local admin token filtering",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LocalAccountTokenFilterPolicy",
            pass_values={0},
            missing_status="PASS",
            missing_observed="LocalAccountTokenFilterPolicy is not set.",
            recommendation="Keep remote UAC token filtering enabled for local accounts.",
        ),
    ]


def check_reg_dword(
    control: str,
    key_path: str,
    value_name: str,
    pass_values: set[int],
    missing_status: str,
    missing_observed: str,
    recommendation: str,
) -> HardeningCheck:
    value = read_hklm_dword(key_path, value_name)
    if value is None:
        return HardeningCheck(control, missing_status, missing_observed, recommendation)
    status = "PASS" if value in pass_values else "WARN"
    return HardeningCheck(
        control=control,
        status=status,
        observed=f"{value_name}={value}",
        recommendation=recommendation,
    )


def read_hklm_dword(key_path: str, value_name: str) -> int | None:
    try:
        import winreg
    except ImportError:
        return None

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _value_type = winreg.QueryValueEx(key, value_name)
            return int(value)
    except OSError:
        return None


def write_json(path: Path, findings: list[SMBFinding]) -> None:
    path.write_text(
        json.dumps([asdict(finding) for finding in findings], indent=2),
        encoding="utf-8",
    )


def write_json_data(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_csv(path: Path, findings: list[SMBFinding]) -> None:
    fields = [
        "host",
        "tcp_445_open",
        "tcp_139_open",
        "smb_reachable",
        "dialect",
        "server_name",
        "server_domain",
        "server_os",
        "signing_required",
        "anonymous_login_allowed",
        "anonymous_shares",
        "risk_summary",
        "errors",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["anonymous_shares"] = ";".join(finding.anonymous_shares)
            row["risk_summary"] = "; ".join(
                f"{risk.severity}: {risk.finding}" for risk in finding.risks
            )
            row["errors"] = "; ".join(finding.errors)
            row.pop("risks", None)
            writer.writerow({field: row.get(field) for field in fields})


def write_log_csv(path: Path, findings: list[LogFinding]) -> None:
    fields = [
        "severity",
        "event_id",
        "finding",
        "user",
        "source_ip",
        "host",
        "detail",
        "recommendation",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def write_management_csv(path: Path, findings: list[ManagementFinding]) -> None:
    fields = [
        "host",
        "winrm_http_open",
        "winrm_https_open",
        "ssh_open",
        "risk_summary",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "host": finding.host,
                    "winrm_http_open": finding.winrm_http_open,
                    "winrm_https_open": finding.winrm_https_open,
                    "ssh_open": finding.ssh_open,
                    "risk_summary": "; ".join(
                        f"{risk.severity}: {risk.finding}" for risk in finding.risks
                    ),
                }
            )


def write_command_csv(path: Path, results: list[CommandResult]) -> None:
    fields = [
        "host",
        "protocol",
        "command",
        "executed",
        "exit_code",
        "stdout",
        "stderr",
        "error",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def print_table(findings: list[SMBFinding]) -> None:
    rows = [
        [
            "Host",
            "445",
            "139",
            "Dialect",
            "Signing",
            "Anon",
            "Risk",
        ]
    ]
    for finding in findings:
        rows.append(
            [
                finding.host,
                yes_no(finding.tcp_445_open),
                yes_no(finding.tcp_139_open),
                finding.dialect or "-",
                tri_state(finding.signing_required),
                tri_state(finding.anonymous_login_allowed),
                summarize_risks(finding),
            ]
        )

    widths = [max(len(str(row[idx])) for row in rows) for idx in range(len(rows[0]))]
    for index, row in enumerate(rows):
        print("  ".join(str(cell).ljust(widths[col]) for col, cell in enumerate(row)))
        if index == 0:
            print("  ".join("-" * width for width in widths))


def print_log_table(findings: list[LogFinding]) -> None:
    rows = [["Severity", "Event", "Finding", "User", "Source", "Host"]]
    for finding in findings:
        rows.append(
            [
                finding.severity,
                str(finding.event_id),
                finding.finding,
                finding.user or "-",
                finding.source_ip or "-",
                finding.host or "-",
            ]
        )
    print_rows(rows)


def print_hardening_table(checks: list[HardeningCheck]) -> None:
    rows = [["Status", "Control", "Observed", "Recommendation"]]
    for check in checks:
        rows.append(
            [check.status, check.control, check.observed, check.recommendation]
        )
    print_rows(rows)


def print_management_table(findings: list[ManagementFinding]) -> None:
    rows = [["Host", "WinRM HTTP", "WinRM HTTPS", "SSH", "Risk"]]
    for finding in findings:
        rows.append(
            [
                finding.host,
                yes_no(finding.winrm_http_open),
                yes_no(finding.winrm_https_open),
                yes_no(finding.ssh_open),
                summarize_management_risks(finding),
            ]
        )
    print_rows(rows)


def print_command_table(results: list[CommandResult]) -> None:
    rows = [["Host", "Protocol", "Executed", "Exit", "Status"]]
    for result in results:
        status = result.error or preview_text(result.stderr or result.stdout) or "ok"
        rows.append(
            [
                result.host,
                result.protocol,
                yes_no(result.executed),
                "-" if result.exit_code is None else str(result.exit_code),
                status,
            ]
        )
    print_rows(rows)


def preview_text(value: str, limit: int = 80) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def print_rows(rows: list[list[str]]) -> None:
    if not rows:
        return
    widths = [max(len(str(row[idx])) for row in rows) for idx in range(len(rows[0]))]
    for index, row in enumerate(rows):
        print("  ".join(str(cell).ljust(widths[col]) for col, cell in enumerate(row)))
        if index == 0:
            print("  ".join("-" * width for width in widths))


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def tri_state(value: bool | None) -> str:
    if value is None:
        return "-"
    return "yes" if value else "no"


def summarize_risks(finding: SMBFinding) -> str:
    if not finding.risks:
        return "none"
    counts: dict[str, int] = {}
    for risk in finding.risks:
        counts[risk.severity] = counts.get(risk.severity, 0) + 1
    return ", ".join(f"{severity}:{count}" for severity, count in sorted(counts.items()))


def summarize_management_risks(finding: ManagementFinding) -> str:
    if not finding.risks:
        return "none"
    return ", ".join(risk.severity for risk in finding.risks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive SMB, Windows log, and management exposure audit helper."
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Audit SMB exposure and posture.")
    add_target_arguments(scan)
    scan.add_argument(
        "--check-anonymous",
        action="store_true",
        help="Attempt an empty SMB login to check null-session exposure.",
    )
    scan.add_argument("--json", type=Path, help="Write JSON report.")
    scan.add_argument("--csv", type=Path, help="Write CSV report.")

    logs = subparsers.add_parser(
        "logs", help="Analyze exported Windows security events for SMB/NTLM signals."
    )
    logs.add_argument("events_file", type=Path, help="CSV, JSON, or XML event export.")
    logs.add_argument("--json", type=Path, help="Write JSON findings.")
    logs.add_argument("--csv", type=Path, help="Write CSV findings.")

    hardening = subparsers.add_parser(
        "hardening", help="Check local Windows SMB/NTLM hardening settings."
    )
    hardening.add_argument("--json", type=Path, help="Write JSON findings.")

    manage = subparsers.add_parser(
        "manage-check", help="Check WinRM/SSH management listener exposure."
    )
    add_target_arguments(manage)
    manage.add_argument("--json", type=Path, help="Write JSON report.")
    manage.add_argument("--csv", type=Path, help="Write CSV report.")

    remote_exec = subparsers.add_parser(
        "exec",
        help="Run an authorized command over SSH or WinRM with normal credentials.",
    )
    add_target_arguments(remote_exec)
    remote_exec.add_argument(
        "--protocol", choices=("ssh", "winrm"), required=True, help="Remote protocol."
    )
    remote_exec.add_argument(
        "--command", dest="remote_command", required=True, help="Command to execute."
    )
    remote_exec.add_argument("--username", required=True, help="Remote username.")
    remote_exec.add_argument(
        "--password-env",
        help="Environment variable containing the remote password.",
    )
    remote_exec.add_argument(
        "--ask-password",
        action="store_true",
        help="Prompt for the remote password without echoing it.",
    )
    remote_exec.add_argument("--ssh-key", type=Path, help="SSH private key path.")
    remote_exec.add_argument(
        "--ssh-auto-add-host-key",
        action="store_true",
        help="Automatically trust unknown SSH host keys for this run.",
    )
    remote_exec.add_argument("--port", type=int, help="Override protocol port.")
    remote_exec.add_argument(
        "--winrm-transport",
        choices=("ntlm", "kerberos", "credssp", "ssl", "basic"),
        default="ntlm",
        help="WinRM authentication transport.",
    )
    remote_exec.add_argument(
        "--winrm-ssl", action="store_true", help="Use WinRM HTTPS."
    )
    remote_exec.add_argument(
        "--winrm-ignore-cert",
        action="store_true",
        help="Skip WinRM TLS certificate validation for lab/self-signed endpoints.",
    )
    remote_exec.add_argument(
        "--yes",
        action="store_true",
        help="Actually execute the command. Without this flag, only a dry run is shown.",
    )
    remote_exec.add_argument("--json", type=Path, help="Write JSON results.")
    remote_exec.add_argument("--csv", type=Path, help="Write CSV results.")

    return parser


def add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*", help="Hostnames, IPs, or CIDR ranges.")
    parser.add_argument("-f", "--targets-file", type=Path, help="File with targets.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout.")
    parser.add_argument("--workers", type=int, default=16, help="Concurrent workers.")
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help="CIDR expansion safety limit. Use 0 for no limit.",
    )


def normalize_argv(argv: list[str]) -> list[str]:
    commands = {"scan", "logs", "hardening", "manage-check", "exec"}
    if not argv or argv[0] in commands or argv[0] in {"-h", "--help"}:
        return argv
    return ["scan", *argv]


def run_scan(args: argparse.Namespace) -> int:
    try:
        targets = expand_targets(args.targets, args.targets_file, args.max_hosts)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("error: provide at least one target or --targets-file", file=sys.stderr)
        return 2

    findings: list[SMBFinding] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {
            executor.submit(audit_host, target, args.timeout, args.check_anonymous): target
            for target in targets
        }
        for future in as_completed(future_map):
            findings.append(future.result())

    findings.sort(key=lambda item: item.host)
    print_table(findings)

    if args.json:
        write_json(args.json, findings)
        print(f"\nJSON report written to {args.json}")
    if args.csv:
        write_csv(args.csv, findings)
        print(f"CSV report written to {args.csv}")

    return (
        1
        if any(risk.severity in {"HIGH", "MEDIUM"} for f in findings for risk in f.risks)
        else 0
    )


def run_logs(args: argparse.Namespace) -> int:
    try:
        records = load_event_records(args.events_file)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = analyze_event_records(records)
    print_log_table(findings)
    print(f"\nAnalyzed {len(records)} events; found {len(findings)} notable signals.")

    if args.json:
        write_json_data(args.json, [asdict(finding) for finding in findings])
        print(f"JSON findings written to {args.json}")
    if args.csv:
        write_log_csv(args.csv, findings)
        print(f"CSV findings written to {args.csv}")

    return 1 if any(f.severity in {"HIGH", "MEDIUM"} for f in findings) else 0


def run_hardening(args: argparse.Namespace) -> int:
    checks = run_hardening_checks()
    print_hardening_table(checks)
    if args.json:
        write_json_data(args.json, [asdict(check) for check in checks])
        print(f"\nJSON findings written to {args.json}")
    return 1 if any(check.status == "WARN" for check in checks) else 0


def run_manage_check(args: argparse.Namespace) -> int:
    try:
        targets = expand_targets(args.targets, args.targets_file, args.max_hosts)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("error: provide at least one target or --targets-file", file=sys.stderr)
        return 2

    findings: list[ManagementFinding] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {
            executor.submit(audit_management_host, target, args.timeout): target
            for target in targets
        }
        for future in as_completed(future_map):
            findings.append(future.result())

    findings.sort(key=lambda item: item.host)
    print_management_table(findings)

    if args.json:
        write_json_data(args.json, [asdict(finding) for finding in findings])
        print(f"\nJSON report written to {args.json}")
    if args.csv:
        write_management_csv(args.csv, findings)
        print(f"CSV report written to {args.csv}")

    return (
        1
        if any(risk.severity == "MEDIUM" for f in findings for risk in f.risks)
        else 0
    )


def resolve_password(args: argparse.Namespace) -> str | None:
    if args.password_env:
        return os.environ.get(args.password_env)
    if args.ask_password:
        return getpass.getpass("Remote password: ")
    return None


def run_remote_exec(args: argparse.Namespace) -> int:
    try:
        targets = expand_targets(args.targets, args.targets_file, args.max_hosts)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("error: provide at least one target or --targets-file", file=sys.stderr)
        return 2

    password = resolve_password(args)
    if args.password_env and password is None:
        print(f"error: environment variable {args.password_env} is not set", file=sys.stderr)
        return 2

    if args.protocol == "winrm" and password is None:
        print(
            "error: WinRM requires --password-env or --ask-password for this tool",
            file=sys.stderr,
        )
        return 2

    if args.protocol == "ssh" and password is None and args.ssh_key is None:
        print(
            "info: no SSH password or key provided; local SSH agent/default keys may be used"
        )

    port = args.port or default_exec_port(args.protocol, args.winrm_ssl)
    if not args.yes:
        results = [
            CommandResult(
                host=target,
                protocol=args.protocol,
                command=args.remote_command,
                executed=False,
                error=f"dry run: add --yes to execute on port {port}",
            )
            for target in targets
        ]
        print_command_table(results)
        return 0

    results: list[CommandResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        if args.protocol == "ssh":
            future_map = {
                executor.submit(
                    run_ssh_command,
                    target,
                    args.remote_command,
                    args.username,
                    password,
                    args.ssh_key,
                    port,
                    args.timeout,
                    args.ssh_auto_add_host_key,
                ): target
                for target in targets
            }
        else:
            future_map = {
                executor.submit(
                    run_winrm_command,
                    target,
                    args.remote_command,
                    args.username,
                    password or "",
                    port,
                    args.timeout,
                    args.winrm_transport,
                    args.winrm_ssl,
                    args.winrm_ignore_cert,
                ): target
                for target in targets
            }

        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda item: item.host)
    print_command_table(results)

    if args.json:
        write_json_data(args.json, [asdict(result) for result in results])
        print(f"\nJSON results written to {args.json}")
    if args.csv:
        write_command_csv(args.csv, results)
        print(f"CSV results written to {args.csv}")

    return 1 if any(result.error or result.exit_code not in (0, None) for result in results) else 0


def default_exec_port(protocol: str, winrm_ssl: bool) -> int:
    if protocol == "ssh":
        return 22
    return 5986 if winrm_ssl else 5985


def main(argv: list[str] | None = None) -> int:
    normalized = normalize_argv(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(normalized)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "logs":
        return run_logs(args)
    if args.command == "hardening":
        return run_hardening(args)
    if args.command == "manage-check":
        return run_manage_check(args)
    if args.command == "exec":
        return run_remote_exec(args)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
