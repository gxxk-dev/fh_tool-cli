# AGENTS.md — AI coding agent 工作约定

fh_tool-cli 是本地管理 FiberHome `/fh_tool` 接口的 Python CLI(Click 入口,stdlib 为主,
`uv` 管理环境)。本文件是任何 AI agent(Claude Code、Codex、Cursor 等)在本仓库工作的
通用约束。

## 任务路由

- **用户要求适配/新增某个设备型号**(如"适配我的 HG9999A")→ 必读根目录
  [ADAPT.md](ADAPT.md),严格按其阶段流程与安全红线执行。
- 其它任务:直接进行,遵守下述硬约束。

## 硬约束

- 一律用 `uv run ...` 运行 Python/CLI(如 `uv run fh-tool --help`、
  `uv run python -m unittest discover -s tests`)。
- 代码注释与文档用中文;标识符与既有字符串约定保持一致(如 `DerivedCredential.note`
  沿用英文)。
- commit 信息用 conventional commits + 中文描述(`feat:` / `fix:` / `docs:` / `test:` /
  `chore:`)。
- 运行期依赖只允许 pyproject.toml 里已有的包;工具脚本(`scripts/`)仅用标准库。
- **安全红线(与 ADAPT.md 一致,适用于一切任务)**:只操作用户自己的设备;严禁批量
  爆破密码;派生公式未经 ≥2 个独立证据不得标 verified;无法验证时明确报错,不盲猜;
  默认脱敏输出,不在日志/issue/PR 中留下明文凭据。
- 写操作命令默认 dry-run,需 `--confirm` 才执行;不自动关闭 Telnet;不做未确认的
  批量写入。

## 发版

发版需同步三处版本:`pyproject.toml`、`src/fh_tool_cli/__init__.py` 的 `__version__`、
`uv.lock`(由 `uv lock` 刷新)。提交前跑 `uv run python scripts/check_version.py`
校验(不一致时 `--fix` 只修 `__init__.py`)。流程见 ADAPT.md 阶段 5。
