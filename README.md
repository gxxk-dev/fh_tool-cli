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

打开 runtime Telnet：

```bash
fh-tool telnet enable --yes
```

检查端口：

```bash
fh-tool ports --ports 23,80,443,8080
```

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

raw call 入口：

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
fh-tool upload-prepare
```

上传 firmware/preconfig：

```bash
fh-tool upload --action preconfig --file sysinfo_conf --sessionid TOKEN --yes --danger
```

## 风险边界

这些命令默认不会执行，必须显式确认：

- `--yes`: 会写设备状态或创建下载文件。
- `--danger`: 高风险写入、关闭 Telnet、执行 debug script、upload。
- `--i-know-this-can-break-my-device`: 恢复出厂或重启。

当前设备如果需要保持 Telnet 打开，不要运行：

```bash
fh-tool telnet disable --yes --danger
```

## License

AGPL-3.0-or-later
