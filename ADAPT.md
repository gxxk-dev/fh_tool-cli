# ADAPT.md — 适配新的 FiberHome 设备型号

本指南写给两类读者:**持有未支持设备的用户(和他们的 AI agent)**,以及维护者。
目标:把一台尚未收录的 FiberHome 光猫的凭据派生公式接入 fh_tool-cli,经实机验证后
通过 issue/PR 回流上游。

- 上游仓库:`https://github.com/gxxk-dev/fh_tool-cli`
- 跟踪 issue / PR 模板:`.github/ISSUE_TEMPLATE/device-adaptation.md`、`.github/PULL_REQUEST_TEMPLATE.md`
- 脚手架:`scripts/adapt_scaffold.py`(本指南阶段 2 的机械臂)
- 发版检查:`scripts/check_version.py`(维护者阶段 5 使用)

## 30 秒开始

在你的 clone/fork 里打开任意 AI coding agent(Claude Code、Codex、Cursor 等),说:

> 请按 ADAPT.md 的流程,为 fh_tool-cli 适配我的 <型号> 光猫,设备在 <IP>,MAC <MAC>。

agent 会读本文件并接管全流程。也可以先在设备可达时运行
`uv run fh-tool adapt-prompt --ip <IP>` 生成一段带设备上下文的 prompt,直接粘贴给 agent。

只想贡献调研结论、不想写代码?直接看[降级路径](#降级路径仅贡献调研结论)。

## 安全红线(对所有 agent 与贡献者,不可违反)

1. **只操作用户自己的设备**,不触碰局域网内任何其它主机;默认只访问 RFC1918 地址。
2. **严禁批量爆破密码**。Telnet 登录只允许有限次尝试已知默认组合(既有型号公式、
   常见出厂默认),失败即停止,向设备主人要凭据。
3. **公式未经至少 2 个独立证据不得标记 verified**(例如:实际登录成功 + `/var/telsu`
   hash 吻合;或多台同型号设备交叉验证)。无法验证时明确报错,绝不盲猜——这是
   `credential_sources.py` 的既有设计原则。
4. 写入设备配置前必须先备份(`fh-tool backup`)并获得设备主人确认;本项目所有写命令
   默认 dry-run。
5. 默认脱敏输出:密码、LOID、PPPoE 等敏感值仅在 `--reveal-secrets` 下显示,不得写入
   issue/PR 正文。

## 适配原理速览

fh_tool-cli **没有设备型号自动识别**:所有型号相关行为都是"固定顺序的候选公式逐一
尝试 + 失败换下一个"。因此适配一个新型号 = 在注册表里**追加**新候选,而不是实现探测
逻辑。

- 凭据公式惯例:`固定前缀 + MAC 后 6 位大写十六进制`
  (见 `credentials.py` 的 `mac_suffix()`;MAC 经 `normalize_mac()` 统一大写)。
- Telnet 登录候选顺序 = 登录尝试顺序(`telnet_login_candidates`,HG5143F 优先,历史兼容)。
- su root 密码候选 = `/var/telsu` hash 验证顺序(`su_password_candidates`,
  支持 `$1$` md5-crypt 与 `$5$` SHA256-crypt,见 `crypt_unix.py`)。

## 触点索引表

以下行号对应 v0.2.9 代码;若文件结构已变化,以锚点语义为准(脚手架对行号漂移有
防呆:锚点未命中即整体 abort)。

### 必改触点(脚手架自动完成)

| 位置 | 内容 |
| --- | --- |
| `src/fh_tool_cli/credentials.py:9-15` | `DERIVED_CREDENTIAL_KINDS` 元组追加新 kind |
| `src/fh_tool_cli/credentials.py:16-24` | 型号常量(用户名/前缀);新 Telnet 用户名须同时加入 `DERIVED_TELNET_USERNAMES`(24 行) |
| `src/fh_tool_cli/credentials.py:159-175` | `derive_credentials` 分发分支 + `"all"` 列表;新 derive 函数插在它前面 |
| `src/fh_tool_cli/credentials.py:178-188` | `telnet_login_candidates` 追加候选(仅当有 Telnet 公式) |
| `src/fh_tool_cli/credentials.py:191-201` | `su_password_candidates` 追加候选(仅当有 su 公式) |
| `tests/test_credentials.py:7-20` | import 按字母序追加 |
| `tests/test_credentials.py:60-63` | `"all"` 顺序断言追加 |
| `tests/test_credentials.py:78-84` / `101-103` | telnet/su 候选精确列表断言追加 |
| `tests/test_credentials.py:171` | fallback 计数断言 +1(仅当新增 telnet 候选) |
| `tests/test_credentials.py` 尾部 | 新 derive 函数的测试 |
| `tests/test_parser_registration.py` 尾部 | 新 kind 的 `--kind` 注册用例 |

**不要动** `tests/test_credentials.py:176-195`(显式用户名测试):`credential_sources.py`
的 `complete_derived_telnet_login` 对显式用户名只返回同名候选,天然兼容新型号。

### 条件触点(人工/agent 逐项决策,脚手架只打印清单不改写)

| 位置 | 何时需要改 |
| --- | --- |
| `src/fh_tool_cli/backends/telnet.py:179-181` | 新增 telnet 候选时,更新"候选均登录失败"错误文案里的型号列举 |
| `src/fh_tool_cli/fh_endpoints.py:8-9` | 该型号 fh_tool API 不在 80/8080 时,扩展 `FALLBACK_FH_TOOL_PORTS` |
| `src/fh_tool_cli/crypt_unix.py:17-19, 35-38` | su hash 非 `$1$`/`$5$` 时:新增 MAGIC、crypt 实现、`crypt_kind`/`crypt_verify` 分支、`_CRYPT_HASH_PATTERN` 正则与测试向量 |
| `src/fh_tool_cli/account.py:84-95` | 新型号 runtime su 写入格式非 md5-crypt 时,`set_su_runtime_password` 分型号分支 |
| `README.md` / `ROADMAP.md` | 补充新型号适配说明(公式、固件版本、验证结论) |
| `confidence` / `note` 字段 | 实机验证通过后,把脚手架默认的 pending-live-verify 文案回填为实测结论 |

## 阶段流程

### 阶段 0 — 前置与跟踪 issue

- [ ] `git status` 干净,工作在最新上游 main(或 fork 同步后的 main)
- [ ] 收集:型号 / 固件版本 / 运营商分支 / 测试机 IP 与 MAC
- [ ] 在上游开跟踪 issue(正文按 `.github/ISSUE_TEMPLATE/device-adaptation.md` 填):

```bash
gh issue create --repo gxxk-dev/fh_tool-cli \
  --title "适配 <MODEL>:凭据派生公式接入与实机验证" \
  --body-file issue-body.md \
  --label device-adaptation   # label 不存在时先: gh label create device-adaptation -R gxxk-dev/fh_tool-cli
```

### 阶段 1 — 实机调研(只读优先)

- [ ] `uv run fh-tool probe --ip <IP>`:确认 fh_tool 端口(`fh_port`)、MAC、GetDevInfo 可达
- [ ] Telnet 手动登录(遵守安全红线第 2 条):优先使用设备主人已知的凭据;
      登录后记录提示符形态(大小写 `login:`/`Login:` 已兼容)与 shell 类型
- [ ] 读 `/var/telsu`:`cat /var/telsu`,记录 hash 原文与类型(`$1$` md5-crypt /
      `$5$` SHA256-crypt / 其它 → 条件触点)
- [ ] 归纳公式假设:Telnet 用户名、Telnet 密码前缀、su 密码前缀
- [ ] **验证公式(≥2 个独立证据)**:用派生候选实际登录/su 一次;或把候选密码与
      `/var/telsu` hash 对照(同 `crypt_verify` 逻辑)
- [ ] 调研结论回填 issue(公式、hash 类型、端口、证据)

### 阶段 2 — 脚手架接入

- [ ] 开分支:`git checkout -b adapt/<slug>`(slug = 小写型号,如 `adapt/hg9999a`)
- [ ] dry-run 并逐行审 diff(重点:常量拼写、kind 命名、测试断言):

```bash
uv run python scripts/adapt_scaffold.py <MODEL> \
  --telnet-username <NAME> --telnet-prefix <PREFIX> \
  --su-prefix <PREFIX> [--su-kind-suffix su|root] \
  [--su-hash-oracle '/var/telsu 的 hash 原文']
```

- [ ] 确认后加 `--write` 落盘(自动全量 unittest;锚点未命中会整体 abort、零写入)
- [ ] 逐项处理"条件触点决策清单"(见上表),每项决策记录到 PR
- [ ] 手填实机结论:把默认 confidence/note 改为验证结论文案
      (对齐现有写法,如 `high-hg5143f-local-live-verified`)

### 阶段 3 — 测试与实机验证

- [ ] `uv run python -m unittest discover -s tests` 全绿
- [ ] 实机端到端:`uv run fh-tool credentials derive --kind <slug>-su --verify --ip <IP> --mac <MAC> --reveal-secrets`
      (走"读 `/var/telsu` → 本地 crypt 验证候选"全链路)
- [ ] `uv run fh-tool cfg get InternetGatewayDevice.DeviceInfo.Manufacturer --ip <IP>`
      (验证 Telnet fallback 自动登录链路)
- [ ] 在 issue 勾掉对应 checklist 项

### 阶段 4 — fork + 上游 PR

```bash
gh repo fork --clone=false          # 若还没有 fork(假设 fork 为 <user>/fh_tool-cli)
git remote add fork https://github.com/<user>/fh_tool-cli.git
git push fork adapt/<slug>

# PR 正文按 .github/PULL_REQUEST_TEMPLATE.md 组装(先写到临时文件再 --body-file)
gh pr create --repo gxxk-dev/fh_tool-cli --base main --head <user>:adapt/<slug> \
  --title "feat: 适配 <MODEL> 凭据派生" --body-file pr-body.md
```

- commit 约定(conventional commits,中文描述):
  - `feat: <MODEL> 凭据派生公式接入注册表与测试`(脚手架产物)
  - `fix: <MODEL> 适配的 Telnet 提示文案/端口/hash 格式调整`(条件触点,仅当有)
  - `docs: 补充 <MODEL> 适配说明`(README/ROADMAP)
- 提交前确认你自己的 git 身份(`git config user.name` / `git config user.email`)与签名设置
- PR 正文用 `Closes #N` 关联跟踪 issue,合并即自动关闭

### 阶段 5 — 发版(维护者)

合并 PR 后:

```bash
uv run python scripts/check_version.py          # 确认三处版本现状一致
# 修改 pyproject.toml version -> uv lock -> 同步 src/fh_tool_cli/__init__.py __version__
uv run python scripts/check_version.py          # 复核(不一致时 --fix 只修 __init__.py)
git commit -am "chore: 发布 X.Y.Z 版本" && git tag vX.Y.Z
git push origin main --tags                      # 推送前确认
```

## 降级路径:仅贡献调研结论

没有时间/条件写代码?把 `.github/ISSUE_TEMPLATE/device-adaptation.md` 的
"调研结论"段填好(公式、`/var/telsu` hash 类型、fh_tool 端口、证据),开成上游 issue
即可。维护者会用同一套脚手架完成接入,并在 PR 中署名致谢。

## 异常与回滚

- **脚手架锚点失败**:整体 abort、零写入。按"触点索引表"人工对照——文件结构可能
  已漂移,先 `git log` 看 `credentials.py` 最近变更。
- **公式验证失败**:停在阶段 1,把已确认与被否证的假设都记入 issue;**不要**提交
  半验证的代码。
- **实机不可用**:只允许以显式 `pending-live-verify` 的 confidence 落注册表,并在
  PR 中说明未实机验证;维护者会决定是否先合入。
- **脚手架写错**:工作区未提交前 `git checkout -- <文件>` 即可整体还原;因此
  务必在干净工作区上跑 `--write`。
