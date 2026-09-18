<!-- 设备适配类 PR 请关联跟踪 issue：Closes #N；流程见仓库根 ADAPT.md。 -->

## 变更说明

<!-- 做了什么 / 为什么。适配类 PR 说明型号、固件、运营商分支与公式来源。 -->

## 关联 issue

Closes #

## 验证方式

- [ ] `uv run python -m unittest discover -s tests` 全绿（附输出摘要：Ran N tests, OK）
- [ ] 实机验证（命令与结果摘要）：`fh-tool credentials derive --kind <slug>-su --verify` / `fh-tool cfg get ...`

## 条件触点核对（不适用项写 N/A 及原因）

- [ ] `backends/telnet.py` 候选提示文案
- [ ] `fh_endpoints.py` 端口
- [ ] `crypt_unix.py` hash MAGIC/正则（新增非 `$1$`/`$5$` 格式时）
- [ ] `account.py` su 写入格式（非 md5-crypt 时）
- [ ] README/ROADMAP 文档

## 风险与回滚

<!-- 是否有写行为变化；回滚方式（git revert / 还原文件）。 -->
