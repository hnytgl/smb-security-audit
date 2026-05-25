# SMB 安全审计与运维辅助工具

这是一个面向授权内网评估、Windows 运维和安全审计的防御型工具。它可以检查 SMB 暴露面、Windows 安全日志、本机加固配置、远程管理入口，并支持通过 SSH / WinRM 使用正常凭据执行授权运维命令。

本项目不实现 pass-the-hash、凭据喷洒或基于 SMB hash 的远程执行能力。

## 功能

- `scan`：检查 SMB 暴露面和常见安全配置风险。
- `logs`：分析 Windows 安全日志导出文件，识别 SMB / NTLM 横向移动相关信号。
- `hardening`：检查本机 Windows SMB / NTLM 加固配置。
- `manage-check`：检查 WinRM / SSH 远程管理端口暴露情况。
- `exec`：通过 SSH 或 WinRM 使用正常凭据执行授权运维命令。

`scan` 命令会检查：

- TCP/445 和 TCP/139 是否开放。
- 安装 `impacket` 后进行 SMB 协议协商。
- 是否启用 SMBv1。
- SMB 签名是否强制启用。
- 使用 `--check-anonymous` 可选检查匿名 / 空会话访问风险。
- 支持 JSON 和 CSV 报告输出。

## 安装

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 使用方法

扫描单个 SMB 主机：

```bash
python smb_security_audit.py scan 192.168.1.10
```

扫描 CIDR 网段并输出报告：

```bash
python smb_security_audit.py scan 192.168.1.0/24 --json report.json --csv report.csv
```

检查匿名 SMB 访问：

```bash
python smb_security_audit.py scan 192.168.1.10 --check-anonymous
```

使用目标文件：

```bash
python smb_security_audit.py scan --targets-file targets.txt
```

分析 Windows 安全日志导出文件：

```bash
python smb_security_audit.py logs security-events.csv --json log-findings.json
```

日志输入支持 CSV、JSON 和 XML。建议重点关注 Event ID：4624、4625、4672、4776、5140。

检查本机 Windows 加固配置：

```bash
python smb_security_audit.py hardening --json hardening.json
```

检查远程管理入口暴露情况：

```bash
python smb_security_audit.py manage-check 192.168.1.0/24 --csv management.csv
```

预览授权 SSH 命令，不实际执行：

```bash
python smb_security_audit.py exec 192.168.1.10 --protocol ssh --username admin --command "hostname"
```

确认目标和命令后，通过 SSH 执行：

```bash
python smb_security_audit.py exec 192.168.1.10 --protocol ssh --username admin --ssh-key ~/.ssh/id_ed25519 --command "hostname" --yes
```

通过 WinRM 执行，并从环境变量读取密码：

```bash
export OPS_PASSWORD='change-me'
python smb_security_audit.py exec 192.168.1.10 --protocol winrm --username 'DOMAIN\admin' --password-env OPS_PASSWORD --command "whoami" --yes
```

Windows PowerShell：

```powershell
$env:OPS_PASSWORD = "change-me"
python smb_security_audit.py exec 192.168.1.10 --protocol winrm --username "DOMAIN\admin" --password-env OPS_PASSWORD --command "whoami" --yes
```

`exec` 命令默认是 dry-run 模式，不会真正执行远程命令。确认目标列表和命令无误后再添加 `--yes`。密码建议通过 `--password-env` 或 `--ask-password` 提供，不要直接写在命令行历史中。

## 结果解读

- `SMBv1 is enabled`：目标启用了 SMBv1，建议禁用 SMBv1，并使用 SMB 2.1+ 或 SMB 3.x。
- `SMB signing is not required`：SMB 签名未强制启用，敏感服务器建议强制开启 SMB signing。
- `Anonymous SMB session is allowed`：允许匿名 SMB 会话，建议限制空会话并检查共享权限。
- `TCP/445 is open but SMB details could not be collected`：TCP/445 开放，但未能收集 SMB 细节；可安装 `impacket` 或检查防火墙、SMB 协商策略。
- `Successful network logon used NTLM`：发现 NTLM 网络登录，建议结合来源主机、账号、特权登录和管理共享访问进行关联分析。
- `WinRM HTTP listener is reachable`：WinRM HTTP 可达，建议确认认证、消息加密策略，并优先使用 HTTPS 或受 Kerberos 保护的管理网络。

## 加固建议

推荐的 Windows 加固动作：

- 禁用 SMBv1。
- 对敏感服务器强制启用 SMB signing。
- 在条件允许时限制 NTLM，优先使用 Kerberos。
- 避免多台主机复用相同本地管理员账号和密码。
- 监控 Event ID 4624 Logon Type 3、4672 特权登录，以及异常共享访问。
- 定期检查管理共享和匿名 / 空会话策略。

## 使用范围

仅在你拥有明确授权的系统、网络和账号范围内使用本工具。
