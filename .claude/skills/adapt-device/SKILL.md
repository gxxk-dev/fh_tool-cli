---
name: adapt-device
description: 为 fh_tool-cli 适配新的 FiberHome 设备型号(凭据派生公式接入)。当用户要求适配/新增某个型号(如"适配 HG9999A")或输入 /adapt-device <MODEL> 时使用。
---

# 设备适配(维护者入口)

本 skill 是 [ADAPT.md](../../../ADAPT.md) 的维护者薄入口,**不复制流程正文**——
单一事实源始终是仓库根目录的 ADAPT.md。

## 执行步骤

1. **完整阅读仓库根目录 `ADAPT.md`**,按其阶段 0-4 执行,严格遵守其"安全红线"与
   "触点索引表"。型号名从本 skill 的调用参数取(如 `/adapt-device HG9999A` 中的
   `HG9999A`);未给型号时先向用户询问型号与测试机 IP/MAC。
2. 脚手架机械部分一律走 `uv run python scripts/adapt_scaffold.py ...`(dry-run 先行,
   确认 diff 后 `--write`),不要手改注册表。

## 维护者差异层(相对外部贡献者)

- **身份确认硬门槛**:每次 `git commit`/`git push` 前,确认 `ghis context` 绑定为本
  仓库的 `gxxk-dev`(git 身份 `gxxk-dev <gxxk@duck.com>`,signed),并把"以该身份
  提交 <操作>"明确报给用户确认;**未经用户对本条确认,禁止执行任何 git commit**。
  若 ghis 绑定缺失或不一致,停下请用户处理,不得代改全局 git 配置。
- **分支策略**:基建设施(版本修复、工具脚本、文档)可走 main 直提;真实型号适配
  一律 `adapt/<slug>` 分支 + 上游 PR(ADAPT.md 阶段 4)。
- **阶段 5 发版是维护者职责**:合并 PR 后按 ADAPT.md 阶段 5 执行
  (`scripts/check_version.py` → 三处版本同步 → tag),推送前请用户确认。
- 外部用户走 AGENTS.md/ADAPT.md 的通用路径;本 skill 仅在维护者环境生效,不要把
  ghis 等维护者工具写进对外文档。
