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

## CLI 输出和日志

CLI 入口使用 Click，错误和日志输出使用 Rich。命令结果只写 stdout；错误、警告和日志写 stderr，便于脚本把 stdout 当作数据流处理。

```bash
fh-tool --verbose probe --json
fh-tool --quiet config show
fh-tool --log-file fh-tool.log dev-info
```

`--json` 输出稳定的 machine-readable JSON，不混入日志或样式。当前默认人类输出仍保持 pretty JSON，以兼容已有脚本；后续可以在不影响 `--json` 的前提下逐步增加表格化输出。

`--log-file` 写入 JSON lines 结构化日志；`-v/-vv` 控制 info/debug 事件，`-q` 只保留 error 级别。日志只记录 command、HTTP method、状态码、cfg path、风险等级等元数据，密码、session、token、LOID、PPPoE 等字段会脱敏。

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

低风险 probe（输出 `fh_port`/`fh_port_source` 与各候选端口 `fh_ports` 明细，可用于诊断 fh_tool API 所在端口）：

```bash
fh-tool probe
fh-tool probe --json
fh-tool probe --fh-port 80
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
fh-tool telnet enable
fh-tool telnet enable --confirm
```

检查端口：

```bash
fh-tool ports --ports 23,80,443,8080
```

## fh_tool 端口与型号/固件兼容性

不同型号/固件的 fh_tool 后端监听端口可能不同。大多数固件在 `8080`，但例如 **HG6142A3（固件 V03.00.M0000）** 的 fh_tool API 位于 `http://192.168.1.1:80/fh_tool/api`（80 端口）。

工具默认行为：

1. 先尝试默认端口 `8080`；
2. 仅当 `8080` TCP 不可达时，自动探测候选端口（当前为 `80`，用 `GetDevInfo` / HTTP surface 验证），并在结果 JSON 的 `fh_port`/`fh_port_source` 字段中说明最终使用的端口和来源（`argument`/`default`/`auto_detected`/`default_unverified`）；
3. 探测失败时沿用 `8080` 并在错误信息中给出引导。

也可以显式指定端口（跳过探测）：

```bash
fh-tool dev-info --fh-port 80
fh-tool call --func GetDevInfo --fh-port 80
```

已知局限：

- 如果 `8080` 与 `80` 同时 TCP 开放、但 fh_tool API 只在 `80`，TCP 快筛会停留在 `8080` 并以 HTTP/解密错误失败，此时需要 `--fh-port 80` 显式指定；`fh-tool probe --json` 的 `fh_ports` 字段可以诊断这种场景。
- 设备返回的绝对下载 URL（含端口）按原样使用，不会重写端口。
- `HTTP 4xx/5xx`、解密失败不会触发端口切换——那说明 8080 上有 HTTP 服务，问题在路径/协议/MAC 而非端口。

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

也可以从 HG5143F 原始 MTD dump 构建同类 userspace VM。`collect` 默认只输出 dry-run 计划，不读 flash；真正采集必须加 `--confirm`，自动开启 Telnet 也必须显式加 `--auto-enable-telnet --confirm`：

```bash
fh-tool vm collect --ip 192.168.1.1 --output ./hg5143f-dumps
fh-tool vm collect --ip 192.168.1.1 --output ./hg5143f-dumps --auto-enable-telnet --confirm
fh-tool vm build --dump-dir ./hg5143f-dumps --output ./HG5143F-ONU-vm
fh-tool vm verify --vm-root ./HG5143F-ONU-vm
fh-tool vm verify --vm-root ./HG5143F-ONU-vm --with-fhapi --with-http
```

`vm build` 需要 `ubireader_extract_images`、`ubireader_extract_files`、`unsquashfs`、`jefferson`、`qemu-arm-static` 和 `proot`。输出目录会包含 `rootfs-vm/`、`source/`、`logs/`、`bin/`、`build-manifest.json`、`verify-manifest.json` 和 `events.ndjson`。生成的 VM 是 32-bit ARM userspace under `qemu-arm-static`/`proot -0`，不是完整板级 QEMU 启动；默认不会运行完整 `/etc/rc.d/rcS`。

Web AJAX 读取命令只读。需要复用已有 Web session 时加 `--sessionid`；需要登录时可显式传 `--password-stdin` 或 `--password`。未显式提供密码时默认 `--username useradmin --password-source auto`，会依次尝试 `GetAdminAccount` 和 cfg 路径读取 Web superadmin 密码；cfg 来源需要 Telnet 时会默认使用 HG5143F 派生 Telnet 凭据 fallback，可用 `--no-derived-credentials` 关闭。失败不会阻塞只读抓取，并会在结果里返回脱敏 login summary。sessionid、密码、LOID、PPPoE 等敏感字段默认会脱敏；只有显式加 `--reveal-secrets` 才输出明文。

后台 AJAX 接口发现以 live discovery 为主路径，不需要 HAR，也不需要 rootfs：

```bash
fh-tool web discover live --ip 192.168.1.1 --web-port 8080 --output web-ajax-catalog.json
fh-tool web discover static --root /mnt/dev-cold/HG5143F-ONU-vm/rootfs-vm --output static-web-ajax-catalog.json
fh-tool web discover merge --input web-ajax-catalog.json --input static-web-ajax-catalog.json --output merged-web-ajax-catalog.json
```

`live` 只探测只读 `get_*/query_*/show_*` 候选；写候选只进入 catalog，不会自动 POST。`static` 是补充路径，用于从 rootfs/备份目录扫描 HTML/JS/CSS 里的 `ajaxmethod`、参数名和上下文。

Web AJAX 写接口默认只做 dry-run，并会提示重新运行时加 `--confirm` 才会执行 POST：

```bash
fh-tool web ajax post set_wan_info --param VLANID=100
fh-tool web ajax replay --catalog web-ajax-catalog.json --method set_wan_info --param VLANID=100
fh-tool web port-mapping set --operation add --wan-index 1 --wan-session-index 1 --wan-iporppp ppp --external-port 8080 --protocol tcp --internal-client 192.168.1.2 --internal-port 80
fh-tool web vlanbind set --operation add --if-name eth1 --user-vlan 100 --wan-vlan 100
fh-tool web firewall set --enable 1 --level medium --dos-enable 1 --ipv6-enable 1 --confirm
fh-tool web services set --service telnet --enabled 0 --confirm
```

常规 Web 写接口优先使用 typed 参数。`web ajax post` 和 `web ajax replay` 支持任意已知或未知 AJAX method，默认只输出计划，不发 POST；执行必须加 `--confirm`，且默认拒绝空 payload。`--json-payload` 和可重复的 `--param k=v` 仍保留为固件差异逃生口，合并顺序是 typed 参数、JSON、最后 `--param` 覆盖。旧的确认参数会直接报弃用错误。

Web AJAX 写命令 dry-run 不会登录；加 `--confirm` 后，如果没有显式 `--sessionid`，会要求自动登录成功后才发 POST。

Telnet/cfg/诊断命令在未显式传 Telnet 密码时，会默认使用 HG5143F 派生 Telnet 凭据 fallback；显式传入的用户名/密码始终优先。如果设备不是该规则，或需要保留空凭据/自定义认证，可加 `--no-derived-credentials` 关闭。`--use-derived-credentials` 仍作为兼容参数接受：

```bash
fh-tool cfg get InternetGatewayDevice.DeviceInfo.Manufacturer
fh-tool wan list
fh-tool cfg get InternetGatewayDevice.DeviceInfo.Manufacturer --no-derived-credentials
```

需要 root shell 的 Telnet 操作会自动执行 `su root`，当前 su 密码默认按 HG5143F 规则从 MAC 派生；如果 runtime su 密码已经被你改过，可显式传 `--su-password` 或 `--su-password-stdin`。例如 device restore、`cloud disable-cloudclt --confirm`、`account set-su-runtime-password --confirm` 会走 root runner。`account set-su-runtime-password` 写入的是 `/var/telsu` 的 passwd 格式 md5-crypt 行，不会把明文密码写入远端命令。

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
fh-tool restore backup.tgz
fh-tool restore backup.tgz --path /fhconf/usrconfig_conf
```

执行恢复必须显式指定本地目标根目录，并加 `--confirm`：

```bash
fh-tool restore backup.tgz \
  --target-root /tmp/fh-tool-restore-root \
  --confirm
```

也可以选择真实设备目标。该模式会通过 Telnet 把 allowlist 文件先写入 `/tmp/fh-tool-restore` staging，远端 sha256 校验通过后才覆盖目标路径；仍然不会自动 reboot 或 factory reset：

```bash
fh-tool restore backup.tgz \
  --target device \
  --path /fhconf/usrconfig_conf \
  --confirm
```

当前 restore 只恢复 allowlist 内的配置文件，且会拒绝路径穿越、绝对路径逃逸和未知文件写入。`/proc/mtd`、runtime password 文件、restore/factory reset flag 等备份内容不会被恢复。恢复后会 read-back/hash verify；不会自动 reboot，也不会自动 factory reset。

默认备份清单包含调研确认的 `/fhconf`、`/fhdata`、runtime password、CloudPlat/appframework 状态和 boot/app 信息等只读路径；这些新增调研路径不会自动加入 restore allowlist。

## CloudPlat / SmartSwitch

CloudPlat 默认先做只读审计和计划：

```bash
fh-tool cloud status
fh-tool cloud audit --output cloud-report.md
fh-tool cloud plan
```

`cloud status/audit/plan` 会结构化显示 SmartSwitch 当前值、配置路径、禁用值、影响面和禁止改动项。禁用 SmartSwitch 只会写入 `InternetGatewayDevice.X_CT-COM_SmartSwitch.Enable=0`，不加 `--confirm` 只输出 dry-run 计划；确认写入后会 read-back verify：

```bash
fh-tool cloud disable-smartswitch --confirm
```

该命令不会修改 LOID、PON、WAN VLAN、ServiceList 或 TR-069 VLAN。

只停 CloudPlat 连接优先使用 SAF container 内的 `cloudclt` init 脚本：

```bash
fh-tool cloud disable-cloudclt --confirm
```

该命令通过 `lxc-attach -n saf -- /etc/init.d/cloudclt stop/disable` 执行，需要 root runner；仍然不会 patch 启动脚本或删除 package。

## 22 个 `/fh_tool/api` method 覆盖

已提供 typed command：

| func | command |
|---|---|
| `GetResult` | `fh-tool get-result` |
| `SetResult` | `fh-tool set-result --result VALUE [--confirm]` |
| `GetPortMirror` | `fh-tool get-port-mirror` |
| `SetPortMirror` | `fh-tool set-port-mirror --enable ... --direction ... --srcport ... --dstport ... [--confirm]` |
| `LogDownload` | `fh-tool log-download [--output log.tar.gz]` |
| `GetDevInfo` | `fh-tool dev-info` |
| `GetAdminAccount` | `fh-tool admin-account` |
| `GetRegAccount` | `fh-tool reg-account` |
| `SetRegAccount` | `fh-tool set-reg-account --regname ... --regpwd ... [--confirm]` |
| `GetPwdRegPassword` | `fh-tool pwd-reg-password` |
| `SetPwdRegPassword` | `fh-tool set-pwd-reg-password --password ... [--confirm]` |
| `DownloadFile` | `fh-tool download-file --file-name /var/... --output out.tar.gz [--confirm]` |
| `RestoreDefaultSettings` | `fh-tool restore-default-settings [--confirm]` |
| `UploadPrepare` | `fh-tool upload-prepare` |
| `DeviceReboot` | `fh-tool reboot [--confirm]` |
| `GetPreconfig` | `fh-tool get-preconfig` |
| `SetPreconfig` | `fh-tool set-preconfig --fullname ... [--confirm]` |
| `TelnetEnable` | `fh-tool telnet enable [--confirm]` / `fh-tool telnet disable [--confirm]` |
| `GetPppoeAccount` | `fh-tool pppoe-account` |
| `SetFHDebugLog` | `fh-tool set-fh-debug-log --module tr069 --data ... [--confirm]` |
| `CloseFHDebugLog` | `fh-tool close-fh-debug-log [--confirm]` |
| `OpenFHDebugLog` | `fh-tool open-fh-debug-log [--confirm]` |

原始调用入口：

```bash
fh-tool call --func GetDevInfo
fh-tool call --func TelnetEnable --param telnet=1 --confirm
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

上传 firmware/preconfig 默认先 dry-run：

```bash
fh-tool upload --action preconfig --file sysinfo_conf --sessionid TOKEN
```

真正上传属于 extreme 风险，只上传文件到 staging path，不会自动 reboot、restore 或切换 preconfig：

```bash
fh-tool upload \
  --action preconfig \
  --file sysinfo_conf \
  --sessionid TOKEN \
  --confirm
```

## 风险边界

写入型命令默认不会执行，只输出 dry-run 计划和提示。确认执行只使用一个参数：

- `--confirm`: 执行写入、上传、恢复、重启等会改变设备状态的动作。
- `--reveal-secrets`: 只控制敏感字段是否明文输出，不代表写入确认。

旧确认参数 `--yes`、`--danger`、`--backup-confirmed`、`--execute`、`--dry-run`、`--allow-risky` 和 `--i-know-this-can-break-my-device` 已弃用，传入会直接报错。

当前设备如果需要保持 Telnet 打开，不要运行：

```bash
fh-tool telnet disable --confirm
```

## License

AGPL-3.0-or-later
