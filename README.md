# fh_tool-cli

本项目是本地管理 FiberHome `/fh_tool` 接口的 Python CLI，目标是快速管理/调整你自己的设备。

默认推荐用 `uvx`：

```bash
uvx --from . fh-tool --help
```

如果已经发布到 PyPI，使用方式会变成：

```bash
uvx --from fh_tool-cli fh-tool --help
uvx fh_tool-cli --help
```

也可以在源码目录里运行：

```bash
cd ~/fh_tool-cli
uv run fh-tool --help
```

下文示例中的 `fh-tool ...` 如果是在源码目录内运行，可以统一写成 `uv run fh-tool ...`。

## 快速配置

保存默认 IP/MAC：

```bash
fh-tool config set --ip 192.168.1.1 --mac AABBCCDDEEFF
```

查看配置：

```bash
fh-tool config show
```

配置文件默认在：

```text
~/.config/fh_tool-cli/config.json
```

所有命令也都可以临时传：

```bash
fh-tool dev-info --ip 192.168.1.1 --mac AABBCCDDEEFF
```

## 常用命令

低风险 probe：

```bash
fh-tool probe
fh-tool probe --json
```

读取设备信息：

```bash
fh-tool dev-info
fh-tool get-result
fh-tool get-port-mirror
fh-tool get-preconfig
```

读取账号类信息：

```bash
fh-tool admin-account
fh-tool reg-account
fh-tool pppoe-account
fh-tool pwd-reg-password
```

只读派生 HG5143F 管理面凭据候选，默认脱敏：

```bash
fh-tool credentials derive --mac AABBCCDDEEFF
fh-tool credentials derive --kind hg5143f-telnet --mac AABBCCDDEEFF
```

当前只实现本地验证过的 HG5143F 管理面规则：Telnet 登录候选和 runtime `su root` 候选。Web superadmin、LOID/registration、TR-069/ACS 是配置层存储值，工具通过 `/fh_tool/api`、`cfg_cmd` 或离线配置解密读取并默认脱敏，不把它们当成公式猜测。Wi-Fi SSID/PSK 不属于当前 `fh_tool-cli` 范围。

打开 runtime Telnet：

```bash
fh-tool telnet enable --yes
```

检查端口：

```bash
fh-tool ports --ports 23,80,443,8080
```

## 本地 VM 测试环境

如果已经在 `/mnt/dev-cold/HG5143F-ONU-vm` 启动本地 userspace VM，可直接用它测试 `cfg_cmd` 和 Web AJAX，不需要碰真实网关：

```bash
/mnt/dev-cold/HG5143F-ONU-vm/bin/start-fhapi-proot
/mnt/dev-cold/HG5143F-ONU-vm/bin/start-http-stack-proot

fh-tool cfg get InternetGatewayDevice.DeviceInfo.Manufacturer --backend local-vm
fh-tool cfg snapshot --backend local-vm --path InternetGatewayDevice.DeviceInfo.Manufacturer --path InternetGatewayDevice.DeviceInfo.ModelName
fh-tool web login-check --ip 127.0.0.1 --web-port 8080
fh-tool web ajax get get_factory_mode --ip 127.0.0.1 --web-port 8080
fh-tool web wan list --ip 127.0.0.1 --web-port 8080
fh-tool web port-mapping list --ip 127.0.0.1 --web-port 8080
fh-tool web vlanbind show --ip 127.0.0.1 --web-port 8080
fh-tool web diagnostics show --ip 127.0.0.1 --web-port 8080
fh-tool pon status --backend local-vm
fh-tool wan list --backend local-vm
```

`local-vm` 只是在本机 proot VM 内执行厂商 `cfg_cmd`。`--vm-root` 必须指向 VM 工作区目录，也就是包含 `bin/proot-shell` 和 `rootfs-vm/fhrom/bin/cfg_cmd` 的目录；默认是 `/mnt/dev-cold/HG5143F-ONU-vm`。不要把它指到里面的 `rootfs-vm/`。

Web AJAX 读取命令只读。需要复用已有 Web session 时加 `--sessionid`；需要登录时可显式传 `--password-stdin` 或 `--password`。未显式提供密码时默认 `--username useradmin --password-source auto`，会依次尝试 `GetAdminAccount` 和 cfg 路径读取 Web superadmin 密码；失败不会阻塞只读抓取。sessionid、密码、LOID、PPPoE 等敏感字段默认会脱敏；只有显式加 `--reveal-secrets` 才输出明文。

后台 AJAX 接口发现以 live discovery 为主路径，不需要 HAR，也不需要 rootfs：

```bash
fh-tool web discover live --ip 192.168.1.1 --web-port 8080 --output web-ajax-catalog.json
fh-tool web discover static --root /mnt/dev-cold/HG5143F-ONU-vm/rootfs-vm --output static-web-ajax-catalog.json
fh-tool web discover merge --input web-ajax-catalog.json --input static-web-ajax-catalog.json --output merged-web-ajax-catalog.json
```

`live` 只探测只读 `get_*/query_*/show_*` 候选；写候选只进入 catalog，不会自动 POST。`static` 是补充路径，用于从 rootfs/备份目录扫描 HTML/JS/CSS 里的 `ajaxmethod`、参数名和上下文。

Web AJAX 写接口默认只做 dry-run。执行 POST 需要先完成备份，并显式加 `--execute --backup-confirmed --yes --danger`：

```bash
fh-tool web ajax post set_wan_info --param VLANID=100
fh-tool web ajax replay --catalog web-ajax-catalog.json --method set_wan_info --param VLANID=100
fh-tool web port-mapping set --operation add --wan-index 1 --wan-session-index 1 --wan-iporppp ppp --external-port 8080 --protocol tcp --internal-client 192.168.1.2 --internal-port 80
fh-tool web vlanbind set --operation add --if-name eth1 --user-vlan 100 --wan-vlan 100
fh-tool web firewall set --enable 1 --level medium --dos-enable 1 --ipv6-enable 1 --execute --backup-confirmed --yes --danger
fh-tool web services set --service telnet --enabled 0 --execute --backup-confirmed --yes --danger
```

常规 Web 写接口优先使用 typed 参数。`web ajax post` 和 `web ajax replay` 支持任意已知或未知 AJAX method，默认只输出计划，不发 POST；执行同样必须加 `--execute --backup-confirmed --yes --danger`，且默认拒绝空 payload。`--json-payload` 和可重复的 `--param k=v` 仍保留为固件差异逃生口，合并顺序是 typed 参数、JSON、最后 `--param` 覆盖。

Telnet/cfg/诊断命令默认不会自动套用派生凭据。如果设备仍是 HG5143F 默认 Telnet 规则，并且已提供或保存 MAC，可以显式加 `--use-derived-credentials` 作为 fallback：

```bash
fh-tool cfg get InternetGatewayDevice.DeviceInfo.Manufacturer --use-derived-credentials
fh-tool wan list --use-derived-credentials
```

诊断命令保持只读；`ip status` 这类依赖 VM/userspace 工具的命令会分别标记每个 probe 的 `ok/output/error`，工具缺失时输出 `partial_failure=true`，不会吞掉其它已成功字段。

本地 VM 集成测试默认会跳过；需要显式指定 VM 目录才会运行：

```bash
uv run python -m unittest discover -s tests
FH_TOOL_CLI_VM_ROOT=/mnt/dev-cold/HG5143F-ONU-vm uv run python -m unittest tests.test_local_vm_integration
```

## 备份与安全回滚

创建和验证备份：

```bash
fh-tool backup --source-root / --output backup.tgz
fh-tool backup verify backup.tgz
```

`restore` 默认只做 dry-run：解析 backup、验证 manifest/sha256，并显示将恢复的文件、目标路径和风险等级，不写入任何文件。

```bash
fh-tool restore backup.tgz --dry-run
fh-tool restore backup.tgz --dry-run --path /fhconf/usrconfig_conf
```

执行恢复必须显式指定本地目标根目录，并通过 extreme 风险确认：

```bash
fh-tool restore backup.tgz \
  --target-root /tmp/fh-tool-restore-root \
  --execute \
  --yes --danger --i-know-this-can-break-my-device
```

也可以选择真实设备目标。该模式会通过 Telnet 把 allowlist 文件先写入 `/tmp/fh-tool-restore` staging，远端 sha256 校验通过后才覆盖目标路径；仍然不会自动 reboot 或 factory reset：

```bash
fh-tool restore backup.tgz \
  --target device \
  --path /fhconf/usrconfig_conf \
  --execute \
  --yes --danger --i-know-this-can-break-my-device
```

当前 restore 只恢复 allowlist 内的配置文件，且会拒绝路径穿越、绝对路径逃逸和未知文件写入。`/proc/mtd`、runtime password 文件、restore/factory reset flag 等备份内容不会被恢复。恢复后会 read-back/hash verify；不会自动 reboot，也不会自动 factory reset。

## CloudPlat / SmartSwitch

CloudPlat 默认先做只读审计和计划：

```bash
fh-tool cloud status
fh-tool cloud audit --output cloud-report.md
fh-tool cloud plan
```

`cloud status/audit/plan` 会结构化显示 SmartSwitch 当前值、配置路径、禁用值、影响面和禁止改动项。禁用 SmartSwitch 只会写入 `InternetGatewayDevice.X_CT-COM_SmartSwitch.Enable=0`，需要先完成备份，并在写入后 read-back verify：

```bash
fh-tool cloud disable-smartswitch \
  --backup-confirmed \
  --yes --danger
```

该命令不会修改 LOID、PON、WAN VLAN、ServiceList 或 TR-069 VLAN。

## 22 个 `/fh_tool/api` method 覆盖

已提供 typed command：

| func | command |
|---|---|
| `GetResult` | `fh-tool get-result` |
| `SetResult` | `fh-tool set-result --result VALUE --yes` |
| `GetPortMirror` | `fh-tool get-port-mirror` |
| `SetPortMirror` | `fh-tool set-port-mirror --enable ... --direction ... --srcport ... --dstport ... --yes` |
| `LogDownload` | `fh-tool log-download [--output log.tar.gz]` |
| `GetDevInfo` | `fh-tool dev-info` |
| `GetAdminAccount` | `fh-tool admin-account` |
| `GetRegAccount` | `fh-tool reg-account` |
| `SetRegAccount` | `fh-tool set-reg-account --regname ... --regpwd ... --yes` |
| `GetPwdRegPassword` | `fh-tool pwd-reg-password` |
| `SetPwdRegPassword` | `fh-tool set-pwd-reg-password --password ... --yes` |
| `DownloadFile` | `fh-tool download-file --file-name /var/... --output out.tar.gz --yes` |
| `RestoreDefaultSettings` | `fh-tool restore-default-settings --yes --danger --i-know-this-can-break-my-device` |
| `UploadPrepare` | `fh-tool upload-prepare` |
| `DeviceReboot` | `fh-tool reboot --yes --danger --i-know-this-can-break-my-device` |
| `GetPreconfig` | `fh-tool get-preconfig` |
| `SetPreconfig` | `fh-tool set-preconfig --fullname ... --yes --danger` |
| `TelnetEnable` | `fh-tool telnet enable --yes` / `fh-tool telnet disable --yes --danger` |
| `GetPppoeAccount` | `fh-tool pppoe-account` |
| `SetFHDebugLog` | `fh-tool set-fh-debug-log --module tr069 --data ... --yes --danger` |
| `CloseFHDebugLog` | `fh-tool close-fh-debug-log --yes` |
| `OpenFHDebugLog` | `fh-tool open-fh-debug-log --yes` |

原始调用入口：

```bash
fh-tool call --func GetDevInfo
fh-tool call --func TelnetEnable --param telnet=1 --allow-risky
```

## upload / download endpoint

下载 `LogDownload` 或 `DownloadFile` 返回的文件：

```bash
fh-tool download-url --url '/fh_tool/tool_download?file=xxx.tar.gz' --output xxx.tar.gz
```

上传前先获取 token：

```bash
fh-tool upload-plan --action preconfig --file sysinfo_conf
fh-tool upload-prepare
fh-tool upload-prepare --reveal-secrets
```

上传 firmware/preconfig 前先 dry-run：

```bash
fh-tool upload --action preconfig --file sysinfo_conf --sessionid TOKEN --dry-run
```

真正上传属于 extreme 风险，只上传文件到 staging path，不会自动 reboot、restore 或切换 preconfig：

```bash
fh-tool upload \
  --action preconfig \
  --file sysinfo_conf \
  --sessionid TOKEN \
  --yes --danger --i-know-this-can-break-my-device
```

## 风险边界

这些命令默认不会执行，必须显式确认：

- `--yes`: 会写设备状态或创建下载文件。
- `--danger`: 高风险写入、关闭 Telnet、执行 debug script。
- `--i-know-this-can-break-my-device`: restore、firmware/preconfig upload、恢复出厂或重启。

当前设备如果需要保持 Telnet 打开，不要运行：

```bash
fh-tool telnet disable --yes --danger
```

## License

AGPL-3.0-or-later
