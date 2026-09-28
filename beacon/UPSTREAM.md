# 同步 OpenTelemetry Python Contrib

命令均从仓库根目录执行。`main` 是 Beacon 下游主线；官方主线只用于发现更新，不直接替换 Beacon 的自有提交。首次导入的旧仓库及已采用的官方 Contrib、Core 标签记录在[基线文件](upstream.lock.json)中，导入记录保持不变；只有完成新版本合并与验证后才更新 `upstream` 和 `core` 字段。

Beacon 下游的主 CI 入口是 [ci.yml](../.github/workflows/ci.yml)，只验证两个 Beacon 包；上游生成的可复用测试工作流保留作同步或专项验证，不直接成为 Beacon 日常发布门禁。上游同步时应保留此下游入口，不用生成脚本覆盖。

## Remote 配置

克隆 Beacon 仓库后，先确认 `origin` 指向 `https://github.com/beacon-observability/beacon-python.git`。不存在 `upstream` 时添加：

```bash
git remote add upstream https://github.com/open-telemetry/opentelemetry-python-contrib.git
git config remote.upstream.tagOpt --no-tags
git config --replace-all remote.upstream.fetch '+refs/heads/main:refs/remotes/upstream/main'
git config remote.pushDefault origin
```

若 remote 已存在，先核对 URL，不要覆盖。`legacy` 仅用于追溯旧 `gtrace` 分支，不是后续发布源：

```bash
git remote add legacy https://github.com/GuanceCloud/opentelemetry-python-contrib.git
git config remote.legacy.tagOpt --no-tags
git config --replace-all remote.legacy.fetch '+refs/heads/gtrace:refs/remotes/legacy/gtrace'
```

Remote、refspec 和远程跟踪引用是本地配置，不随 Git 提交。首次远程创建及推送须另行授权；不要向官方 `upstream` 或旧 `legacy` 推送。

## 固定并合入正式基线

1. 审查官方 Release，独立核对标签和其完整提交 SHA。Python Contrib 的发行标签可能位于 release 分支，不要求它成为官方 `main` 的祖先。
2. 用[单标签校验脚本](scripts/fetch-upstream-tag.sh)获取标签；已有同名上游引用时，脚本会拒绝标签对象改写。以已登记基线为例：

   ```bash
   bash beacon/scripts/fetch-upstream-tag.sh v0.65b0 a5470c666947acddc24fd4064ec7c1b169dfe8b6
   ```

3. 在干净的 `main` 上新建同步分支，合并已核对的提交（保留合并提交，不 squash 整次上游同步），解决冲突并适配自有包。不要用新的上游树覆盖整个下游工作树。
4. 同步核对根目录 [pyproject.toml](../pyproject.toml) 中的 Python Core 标签，重新生成并检查 [uv.lock](../uv.lock)。上游 Contrib 标签、Python Core 标签及依赖版本应作为一组兼容基线评审，不盲目改成 `main` 或最新版本。
5. 运行自有包回归与受影响的上游测试，并按拟发行范围验证运行环境和接收端。完成后更新[基线文件](upstream.lock.json)的 `upstream` 和 `core` 字段，再运行 `python beacon/scripts/check-version.py` 核对实际依赖与记录。确认目标提交已成为产品主线祖先：

   ```bash
   git merge-base --is-ancestor <已核对的上游提交SHA> HEAD
   ```

抓取、合并、测试和发行是不同状态。`uv.lock` 仅固定开发依赖，不替代包的发行验证。保留上游许可证、历史及包名；自有功能在对应包维护。继承的上游发行和维护机器人工作流不作为 Beacon 入口，已从本仓库移除；每次同步后仍需复核新增或变化的工作流，避免将这些流程重新引入。
