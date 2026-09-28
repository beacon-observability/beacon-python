# Beacon Python 发行流程

`beacon-otel` 主包与 `beacon-profiling` 可选包按同一产品版本发行。继承的上游及历史上的 `gtrace` 包安装示例不是 Beacon 的发行证据；[产品入口](https://github.com/beacon-observability/beacon)以实际发布标签为准。

对外产品名称统一为 Beacon Python，命令入口使用 `beacon`，不恢复或发布 `gtrace` 命令。发行包名为 `beacon-otel` 与 `beacon-profiling`。旧 `gtrace` 名称只用于历史分支和来源追溯；公共 PyPI 上的 [`beacon`](https://pypi.org/project/beacon/) 和 [`beacon-python`](https://pypi.org/project/beacon-python/) 已属于其他项目，不能直接用作本项目发行包名。

## 版本入口

- [version.properties](version.properties) 是 Beacon Python 产品版本的唯一手工修改入口。开发版使用 `X.Y.Z.devN`，候选版使用 `X.Y.ZrcN`，正式版使用 `X.Y.Z`；正式发行标签使用 `beacon-vX.Y.Z`，候选版相应加 `rcN`，不复用上游 `v*` 标签。两个 Beacon 包均接入此版本，不把上游包版本批量替换为 Beacon 版本。
- 修改产品版本后运行 `python beacon/scripts/check-version.py --sync`，将版本复制到两个包内，并同步 `beacon-otel[profiling]` 的精确依赖版本；日常和发行前运行不带 `--sync` 的检查，防止副本偏离。包内版本文件是生成副本，不是第二个手工版本入口。
- [upstream.lock.json](upstream.lock.json) 记录 Contrib 与 Core 各自的 tag 和完整提交；根目录 [pyproject.toml](../pyproject.toml)、[uv.lock](../uv.lock) 和 Profiling 依赖是实际构建配置。`check-version.py` 校验这些配置与基线记录一致，产品版本与上游版本相互独立。基线升级仍按[同步流程](UPSTREAM.md)执行。
- 构建候选 wheel 后，对两个 wheel 分别传入 `--wheel`，检查名称、版本及四项固定的 OTel 依赖。检查候选或正式标签时加 `--tag beacon-vX.Y.Z[rcN]`；开发版不能通过发布标签检查。此检查不代替从同一源码提交构建 sdist、功能测试、运行环境和 DataKit 验收；也不表示当前开发版已获准发布。

## 发布操作

1. 在完成接收端及环境验收后，确认 `version.properties` 中的候选版号，运行 `python beacon/scripts/check-version.py --sync`，核对锁文件并提交。CI 的 [ci.yml](../.github/workflows/ci.yml) 在 Python 3.10–3.14 的干净环境安装两个构建制品、检查元数据并测试自有包；发布前还须确认该提交的 CI 全部通过。
2. 仓库管理员在 GitHub 创建 `pypi-profiling` 和 `pypi` 两个 Environment，均限制为 `beacon-v*` 标签并设置人工审核；在 PyPI 分别为 `beacon-profiling`、`beacon-otel` 配置待生效的 Trusted Publisher，均指向 `GuanceCloud/beacon-python` 和 `beacon-release.yml`，但环境分别填写 `pypi-profiling`、`pypi`。PyPI 会拒绝同一仓库、工作流和环境组合用于两个不同名称的待创建项目；首版采用不同环境，正式项目创建后再按需评估合并。确认这些保护生效后，才将仓库变量 `BEACON_PYPI_RELEASE_ENABLED` 设为 `true`。没有这些设置时[发布工作流](../.github/workflows/beacon-release.yml)只会跳过，不会尝试上传。不要把 PyPI 令牌写入仓库。
3. 仅在实际验收通过后给已验证提交打 `beacon-vX.Y.ZrcN`（或正式版）标签并推送。手动在该标签上运行 `Publish Beacon Python`；构建和测试通过后先发布 Profiling，再发布主包。发布任务分别在受保护的 `pypi-profiling`、`pypi` 环境等待批准。PyPI 不允许覆盖同一版本，失败后修复应递增版本，不能重传已发布文件。
4. 两个 PyPI 包发布成功后，工作流自动创建 GitHub Release，并附加两个包的 wheel 与 sdist；候选版本自动标记为 Pre-release，正式版按 GitHub 的版本规则参与 Latest 判定。任务重试时会复用已有 Release 并覆盖同名附件。核对自动生成的发布说明并补充对应的 Contrib/Core 基线、已验证能力和环境、限制及回退方法。
5. 在 PyPI 核对两个包的版本和制品，再用全新虚拟环境从公开索引安装 `beacon-otel[profiling,requests]`，验证 `beacon --version`、应用自动插桩和目标 DataKit 接收；最后更新产品仓库的 Python 入口。

GitHub 的 `pypi` 和 `pypi-profiling` Environment 均已创建，限定 `beacon-v*` 标签并要求 `lrwh` 人工审核；PyPI Trusted Publisher 已完成配置，`0.1.0rc1`、`0.1.0rc2` 和 `0.1.0` 已按本流程发布。`BEACON_PYPI_RELEASE_ENABLED` 日常保持关闭，仅在人工发布窗口临时启用；本仓库代码推送或开发制品构建均不会自动发布。

稳定版发行前需要在本仓库确定并验证：

1. 确认 `beacon-otel` 与 `beacon-profiling` 的功能边界、稳定版本号及旧 Guance 包的迁移说明。`0.1.0` 正式版基于已验收的 `0.1.0rc2` 功能基线；旧 `guance-sdk-extension-profiling` 与 Beacon Profiling 不能混装，不得以旧 Guance 包的名称和版本覆盖既有制品。
2. 固定的 Contrib、Python Core、第三方依赖与许可证来源；从固定提交构建候选制品并记录摘要。
3. 自有功能、上游影响范围、Python 运行环境、DataKit 接收端和升级回退的验证结果；将证据绑定同一提交和制品。
4. 发布权限、目标仓库或包索引、发行审批及回退流程；不得启用继承的 OpenTelemetry 发布工作流来发布 Beacon。
5. 每版发布说明、已知限制和版本化使用文档；发布后同步更新产品仓库的 Python 安装和 Release 入口。

各语言独立发行；不要求与 Beacon Java、Go 锁步，也不把本地测试通过视为发行验收。
