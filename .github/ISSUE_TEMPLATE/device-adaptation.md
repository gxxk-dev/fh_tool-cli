---
name: 设备适配
about: 适配新 FiberHome 型号的凭据派生公式（调研结论 / 跟踪）
labels:
  - device-adaptation
---

<!-- 流程见仓库根 ADAPT.md；只提交调研结论的用户填好前两段即可，维护者会接入。 -->

## 型号信息

- 型号：
- 固件版本：
- 运营商分支（联通/电信/移动/其它）：
- 测试机 IP / MAC（可自行抹去部分字段）：

## 调研结论（阶段 1 产出）

- [ ] Telnet 登录公式：用户名 `___` + 密码前缀 `___` + MAC 后 6 位（验证方式：实际登录 / 其它：___）
- [ ] su root 公式：密码前缀 `___` + MAC 后 6 位；`/var/telsu` hash 类型：`$1$` / `$5$` / 其它：___
- [ ] fh_tool API 端口：`8080` / `80` / 其它：___
- [ ] 证据（≥2 个独立证据才标 verified；至少给一条，例如实机登录记录、`/var/telsu` hash 与候选密码的 crypt 对照）：

<!-- 注意：不要在此粘贴密码明文对应的敏感配置值；hash 摘要与公式可以提供。 -->

## 实施 checklist（阶段 2-3，代码接入时勾选）

- [ ] `scripts/adapt_scaffold.py` 接入注册表（dry-run diff 已人工/agent 确认）
- [ ] 条件触点核对：telnet.py 提示文案 / fh_endpoints 端口 / crypt_unix MAGIC / account.py 写入格式（不适用项写 N/A 及原因）
- [ ] 测试：注册表断言更新 + hash oracle 用例 + `uv run python -m unittest discover -s tests` 全绿
- [ ] 实机验证：`fh-tool credentials derive --kind <slug>-* --verify` + `cfg get`（Telnet fallback 全链路）
- [ ] confidence/note 回填实机验证结论；README/ROADMAP 更新
