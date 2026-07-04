# fh_tool-cli 更新计划

目标：把 `fh-tool` 从 `/fh_tool/api` 调用器升级成 HG5143F/FiberHome 本地管理工具箱。原则是先只读审计和备份，再做可回滚的配置写入；所有高风险动作默认关闭，必须显式确认。

## 1. 架构拆分

当前 `src/fh_tool_cli/cli.py` 已经覆盖 `/fh_tool/api` 22 个 method、upload 和 tool_download。下一步先拆模块，避免单文件继续膨胀。

- `crypto.py`：`/fh_tool/api` MAC-derived AES-CBC；配置文件 AES-ECB 解密。
- `client.py`：HTTP client、timeout、错误处理、endpoint 封装。
- `config_store.py`：本机 CLI 配置、设备 IP/MAC、profile。
- `risk.py`：`safe` / `write` / `danger` / `extreme` 风险分级与确认逻辑。
- `backends/`：
  - `fh_tool.py`：现有 `/fh_tool/api`。
  - `telnet.py`：Telnet/root shell backend。
  - `cfg_cmd.py`：在线配置层 `cfg_cmd get/set/attr`。
  - `web_ajax.py`：标准 Web AJAX/session backend。
- `commands/`：按功能拆命令组。

## 2. 离线配置解密

新增 read-only 子命令，用于 dump 后分析配置文件。

```bash
fh-tool config-decrypt --input usrconfig_conf --attr attrconfig_conf --output decrypted.json
fh-tool config-decrypt --input usrconfig_conf --redact
fh-tool config-decrypt --input usrconfig_conf --reveal-secrets
```

实现要点：

- 解析 UCI-like 配置结构，不用脆弱字符串拼接。
- 支持 `encrymode=2`：AES-128-ECB、static key、zero padding、uppercase hex。
- 结合 `attrconfig_conf` 判断敏感字段和加密属性。
- 默认脱敏 LOID、PPPoE、ACS、Wi-Fi、token、password。
- `--reveal-secrets` 才输出明文敏感值。
- 第一版只做解密和导出，不做离线重加密写回。

## 3. 在线配置层封装

通过 Telnet/root backend 包装设备自己的 `cfg_cmd`，避免直接手工编辑 encrypted `usrconfig_conf`。

```bash
fh-tool cfg get PATH
fh-tool cfg set PATH VALUE --yes
fh-tool cfg attr PATH
fh-tool cfg snapshot --output cfg.json
fh-tool cfg diff before.json after.json
```

要求：

- `cfg set` 前自动提示备份。
- 写入后读取同一 PATH 验证结果。
- 输出同时包含 path、value、risk、是否已验证落盘。
- 对 TR-069、WAN、PON、LOID、VLAN、preconfig 等路径默认标记 `danger`。

## 4. 备份与回滚准备

新增备份命令，作为所有写操作的前置基础。

```bash
fh-tool backup --output backup.tgz
fh-tool backup --manifest backup.json
fh-tool backup verify backup.tgz
```

备份范围：

- `/fhconf/usrconfig_conf`
- `/fhconf/usrconfig_conf_bak`
- `/fhconf/attrconfig_conf`
- `/fhconf/status_version_flag`
- `/fhconf/cfgmgr_restore_flag_conf`
- `/fhconf/factory_reset_conf`
- `/fhconf/process_start_list`
- `/fhconf/tr069_control_conf`
- `/fhconf/xpon_tr069cfg_conf`
- `/fhdata/factory_conf`
- `/fhdata/sysinfo_conf`
- `/fhdata/pre_usrconfig_conf`
- `/fhdata/pre_attrconfig_conf`
- runtime password files：`/var/tel_passwd`、`/var/telWan_passwd`、`/var/telsu`
- 只读状态：`/proc/mtd`、`mount`、`df -h`、`ubinfo -a`、boot state。

第一阶段只实现 backup/verify，不直接做自动 restore。restore 单独设计，默认高风险。

## 5. 密码管理

新增 account 命令组。

```bash
fh-tool account show
fh-tool account set-web-admin-password --password-stdin --yes
fh-tool account set-telnet-password --generate --yes
fh-tool account set-telnet-username --name telnetadmin --yes --danger
fh-tool account set-su-runtime-password --password-stdin --yes --danger
```

支持的 clean persistent path：

- Web superadmin password：
  - `InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password`
- Telnet login password：
  - `InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetPassword`
- Telnet username：
  - `InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetUserName`

`su root` password：

- 当前只做 runtime 覆写 `/var/telsu`。
- 明确标注 reboot/serviceMgr 重建后可能丢失。
- 不默认实现持久 patch `serviceMgr` 或 init hook。

密码输入规则：

- 支持 `--password-stdin`、`--password VALUE`、`--generate`。
- 不在工具代码里写死固定目标密码。
- 默认脱敏输出，日志不记录明文。

## 6. 自动更新 / 远程控制管理

新增 `autoupdate`、`tr069`、`cloud` 命令组。

```bash
fh-tool autoupdate status
fh-tool autoupdate audit --output report.md
fh-tool autoupdate plan
fh-tool tr069 status
fh-tool tr069 harden --periodic-inform off --yes --danger
fh-tool tr069 randomize-connection-request --yes --danger
fh-tool cloud status
fh-tool cloud endpoints
fh-tool cloud disable-cloudclt --yes --danger
```

TR-069 覆盖：

- ACS URL、Username、Password。
- PeriodicInformEnable、PeriodicInformInterval。
- ConnectionRequestURL、ConnectionRequestUsername、ConnectionRequestPassword。
- UpgradesManaged。
- 当前进程、监听端口、iptables rule、download/reboot 日志。

CloudPlat 覆盖：

- `gdecms`、`saf`、`appmgr`、`cloudclient`、`cloudclocal` 进程。
- ABI/BSS/file server endpoints。
- 当前 `netstat` 连接。
- `SmartSwitch` 状态。
- SAF/appframework DBus 暴露面只读枚举。

Harden 分层：

- L0：只生成上级 router/firewall/DNS 阻断建议，不改设备。
- L1：配置层削弱 TR-069，例如关闭 PeriodicInform、随机化 ConnectionRequest credentials。
- L2：停/禁 SAF container 内 `cloudclt`。
- L3：`SmartSwitch=0` 阻断 SAF/appframework，默认高风险。
- L4：启动层/二进制层不默认实现，只生成人工计划。

## 7. 标准 Web AJAX backend

新增 superadmin Web 登录、AJAX session、接口发现 catalog 和受安全门保护的任意 AJAX POST 支持。live discovery 是主路径，可以直接访问实机后台抓取同源 HTML/JS/CSS 并只读探测 read method；static discovery 作为 rootfs/备份目录扫描补充。

```bash
fh-tool web login-check
fh-tool web ajax get get_base_info
fh-tool web discover live --ip 192.168.1.1 --web-port 8080 --output web-ajax-catalog.json
fh-tool web discover static --root /mnt/dev-cold/HG5143F-ONU-vm/rootfs-vm --output static-web-ajax-catalog.json
fh-tool web discover merge --input web-ajax-catalog.json --input static-web-ajax-catalog.json --output merged-web-ajax-catalog.json
fh-tool web ajax post set_fake --param Enable=1
fh-tool web ajax replay --catalog web-ajax-catalog.json --method set_fake --param Enable=1
fh-tool web wan list
fh-tool web tr069 show
fh-tool web services show
fh-tool web firewall show
```

已覆盖 typed command：

- WAN/宽带信息。
- TR-069 页面状态。
- service switches。
- firewall。
- port mapping。
- vlanbind。

任意 `web ajax post/replay` 默认 dry-run；真实执行必须同时提供 `--execute --backup-confirmed --yes --danger`，默认拒绝空 payload，输出默认脱敏。

写接口必须走风险分级和备份，不做批量无确认写入。

## 8. PON / WAN / 网络画像

新增只读诊断命令。

```bash
fh-tool pon status
fh-tool wan list
fh-tool vlan list
fh-tool ip status
fh-tool firewall status
fh-tool ipv6 status
fh-tool ports
```

目标输出：

- PON 类型、注册状态、光功率。
- WANConnectionDevice 列表、ServiceList、ConnectionType、VLAN、IPMode、NAT、LAN binding。
- TR-069 management interface。
- IPv6 PD、LAN DHCP、UPnP、ALG、firewall/DoS 状态。
- 监听端口和关键进程。

默认不输出 LOID、PPPoE、ACS、STBMAC 明文。

## 9. 安全护栏

所有命令统一风险分级。

- `safe`：只读、无敏感明文。
- `sensitive`：只读但可能显示 secret，需要 `--reveal-secrets`。
- `write`：普通配置写入，需要 `--yes`。
- `danger`：可能影响远程管理、登录、业务、进程，需要 `--yes --danger`。
- `extreme`：reboot、restore、factory reset、firmware/preconfig upload，需要 `--yes --danger --i-know-this-can-break-my-device`。

通用规则：

- 默认只允许 RFC1918/LAN 目标。
- 默认脱敏。
- 写操作前提示 backup。
- 写操作后做 read-back verify。
- 不自动关闭 Telnet。
- 不默认修改 LOID、PON mode、WAN VLAN、ServiceList、TR-069 VLAN。
- 不 `killall fhomci/fhoam`。

## 10. 测试与发布

测试：

- `/fh_tool/api` crypto golden tests。
- 配置 AES decrypt golden tests。
- UCI-like parser tests。
- mock HTTP server 测 `/fh_tool/api` 错误响应。
- fake Telnet backend 测 `cfg_cmd` command parsing。
- report JSON/Markdown golden output。

发布前：

- 统一默认配置路径为 `~/.config/fh_tool-cli/config.json`。
- 清理 `dist/` 和 egg-info 生成物是否进入发布包的策略。
- README 按普通用户、诊断、密码管理、远程控制、危险操作分层。
- 明确授权和风险声明。

## 建议实施顺序

1. 架构拆分，不改变现有行为。
2. `config-decrypt` 离线解密。
3. `backup` 和 `audit` 只读报告。
4. Telnet/root backend + `cfg get/set/attr`。
5. `account` 密码管理。
6. `tr069 status/audit/plan` 和 `cloud status/endpoints`。
7. `tr069 harden`、`cloud disable-cloudclt`。
8. Web AJAX read-only backend。
9. PON/WAN/network typed diagnostics。
10. 更高风险 restore、SmartSwitch、upload 流程最后再做。
