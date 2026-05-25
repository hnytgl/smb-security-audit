# SMB Security Audit

Defensive SMB and Windows lateral-movement posture checker for authorized internal assessments. The tool checks SMB exposure, Windows security logs, local hardening settings, and management listener exposure without implementing pass-the-hash, credential attacks, or remote command execution.

## Features

- `scan`: SMB exposure and posture checks.
- `logs`: Windows security event export analysis for SMB/NTLM lateral-movement signals.
- `hardening`: Local Windows SMB/NTLM hardening checks.
- `manage-check`: WinRM/SSH management listener exposure checks.
- `exec`: Authorized remote command execution over SSH or WinRM with normal credentials.

The `scan` command checks:

- TCP/445 and TCP/139 reachability.
- SMB dialect negotiation when `impacket` is installed.
- SMBv1 detection.
- SMB signing requirement detection when exposed by the SMB stack.
- Optional anonymous/null-session exposure with `--check-anonymous`.
- JSON and CSV report output.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Scan one SMB host:

```bash
python smb_security_audit.py scan 192.168.1.10
```

Scan a CIDR range and write reports:

```bash
python smb_security_audit.py scan 192.168.1.0/24 --json report.json --csv report.csv
```

Check for anonymous SMB access:

```bash
python smb_security_audit.py scan 192.168.1.10 --check-anonymous
```

Use a target file:

```bash
python smb_security_audit.py scan --targets-file targets.txt
```

Analyze exported Windows security events:

```bash
python smb_security_audit.py logs security-events.csv --json log-findings.json
```

Supported event input formats are CSV, JSON, and XML. Useful event IDs include 4624, 4625, 4672, 4776, and 5140.

Check local Windows hardening settings:

```bash
python smb_security_audit.py hardening --json hardening.json
```

Check remote management listener exposure:

```bash
python smb_security_audit.py manage-check 192.168.1.0/24 --csv management.csv
```

Preview an authorized SSH command without executing it:

```bash
python smb_security_audit.py exec 192.168.1.10 --protocol ssh --username admin --command "hostname"
```

Execute over SSH after reviewing the target and command:

```bash
python smb_security_audit.py exec 192.168.1.10 --protocol ssh --username admin --ssh-key ~/.ssh/id_ed25519 --command "hostname" --yes
```

Execute over WinRM using a password from an environment variable:

```bash
export OPS_PASSWORD='change-me'
python smb_security_audit.py exec 192.168.1.10 --protocol winrm --username 'DOMAIN\admin' --password-env OPS_PASSWORD --command "whoami" --yes
```

On Windows PowerShell:

```powershell
$env:OPS_PASSWORD = "change-me"
python smb_security_audit.py exec 192.168.1.10 --protocol winrm --username "DOMAIN\admin" --password-env OPS_PASSWORD --command "whoami" --yes
```

The `exec` command defaults to dry-run mode. Add `--yes` only after confirming the target list and command. Passwords should be supplied with `--password-env` or `--ask-password`, not directly in shell history.

## Interpreting Results

- `SMBv1 is enabled`: disable SMBv1 and require SMB 2.1+ or SMB 3.x.
- `SMB signing is not required`: require SMB signing where integrity matters.
- `Anonymous SMB session is allowed`: restrict null sessions and review share permissions.
- `TCP/445 is open but SMB details could not be collected`: install `impacket`, validate firewall policy, or inspect SMB negotiation controls.
- `Successful network logon used NTLM`: correlate source host, user, privilege events, and administrative share access.
- `WinRM HTTP listener is reachable`: verify authentication and message encryption policy; prefer HTTPS or Kerberos-protected administrative networks.

## Defensive Follow-Up

Recommended Windows hardening actions:

- Disable SMBv1.
- Require SMB signing for sensitive server roles.
- Restrict NTLM where Kerberos is available.
- Limit local administrator reuse across hosts.
- Monitor Event ID 4624 logon type 3, 4672 privileged logons, and unusual share access.
- Review administrative shares and anonymous/null-session policies.

## Scope

Use this only on systems where you have explicit authorization to perform security assessment.
