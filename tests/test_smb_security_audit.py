from pathlib import Path

from smb_security_audit import (
    ManagementFinding,
    SMBFinding,
    analyze_event_record,
    default_exec_port,
    evaluate_management_risks,
    evaluate_risks,
    expand_targets,
    is_admin_share,
    normalize_argv,
    split_target_line,
)


def test_split_target_line_strips_comments_and_commas():
    assert split_target_line("192.0.2.1, 192.0.2.2 # lab hosts") == [
        "192.0.2.1",
        "192.0.2.2",
    ]


def test_expand_targets_deduplicates_values(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("192.0.2.2\n192.0.2.3\n", encoding="utf-8")

    assert expand_targets(["192.0.2.1", "192.0.2.2"], target_file, 10) == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    ]


def test_expand_targets_enforces_cidr_limit():
    try:
        expand_targets(["192.0.2.0/29"], None, 2)
    except ValueError as exc:
        assert "expands to" in str(exc)
    else:
        raise AssertionError("expected CIDR limit error")


def test_risks_flag_smbv1_unsigned_and_anonymous():
    finding = SMBFinding(
        host="192.0.2.10",
        tcp_445_open=True,
        smb_reachable=True,
        dialect="SMBv1",
        signing_required=False,
        anonymous_login_allowed=True,
    )

    risks = evaluate_risks(finding)
    assert [risk.severity for risk in risks] == ["HIGH", "MEDIUM", "HIGH"]
    assert any("SMBv1" in risk.finding for risk in risks)


def test_analyze_event_record_flags_ntlm_network_logon():
    finding = analyze_event_record(
        {
            "Event ID": "4624",
            "Logon Type": "3",
            "Authentication Package": "NTLM",
            "Account Name": "alice",
            "Source Network Address": "192.0.2.20",
        }
    )

    assert finding is not None
    assert finding.severity == "MEDIUM"
    assert "NTLM" in finding.finding
    assert finding.user == "alice"


def test_admin_share_detection_accepts_windows_paths():
    assert is_admin_share(r"\\HOST\ADMIN$")
    assert is_admin_share(r"\\HOST\C$")
    assert not is_admin_share(r"\\HOST\Public")


def test_management_risks_flag_winrm_http():
    risks = evaluate_management_risks(
        ManagementFinding(host="192.0.2.30", winrm_http_open=True)
    )

    assert len(risks) == 1
    assert risks[0].severity == "MEDIUM"
    assert "WinRM HTTP" in risks[0].finding


def test_old_scan_arguments_default_to_scan_command():
    assert normalize_argv(["192.0.2.10"]) == ["scan", "192.0.2.10"]
    assert normalize_argv(["logs", "events.csv"]) == ["logs", "events.csv"]


def test_exec_command_is_not_rewritten_to_scan():
    assert normalize_argv(["exec", "--protocol", "ssh"]) == ["exec", "--protocol", "ssh"]


def test_default_exec_ports():
    assert default_exec_port("ssh", False) == 22
    assert default_exec_port("winrm", False) == 5985
    assert default_exec_port("winrm", True) == 5986
