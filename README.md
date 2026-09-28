# Beacon Python

Beacon Python 是 GuanceCloud 基于完整 OpenTelemetry Python Contrib 源码维护的 Python 自动插桩与增强工程，保留上游历史，按语言独立开发和发行。

当前稳定版本为 `0.1.0`，通过 PyPI 发布：[`beacon-otel`](https://pypi.org/project/beacon-otel/) 与 [`beacon-profiling`](https://pypi.org/project/beacon-profiling/)。上游 OpenTelemetry 包及既有 Guance PyPI 包的下载地址和支持声明，不代表 Beacon Python 的发行结果。

## 开发入口

- [开发说明与工程布局](beacon/README.md)
- [源码来源与上游基线](beacon/upstream.lock.json)
- [同步 OpenTelemetry](beacon/UPSTREAM.md)
- [发行准备](beacon/RELEASING.md)
- [Beacon 主安装包](beacon-otel/)
- [上游自动插桩发行包](opentelemetry-distro/)
- [Profiling 扩展](sdk-extension/beacon-profiling/)
- [贡献指南](CONTRIBUTING.md)

开发主线为 `main`。从仓库根目录执行 `uvx --from uv==0.12.1 uv lock --check` 可检查开发依赖锁定状态；自有包测试及完整上游矩阵的入口见[开发说明](beacon/README.md)。依赖解析、构建或本地测试通过均不等于正式发行验收。

## Beacon Contributors

<p align="center">
  <a href="https://github.com/lrwh">
    <img src="https://avatars.githubusercontent.com/u/17264378?v=4" width="96" height="96" alt="Reid Liu">
    <br>
    Reid Liu
  </a>
</p>

## 产品与上游

- [Beacon 产品入口](https://github.com/beacon-observability/beacon)
- [OpenTelemetry Python Contrib](https://github.com/open-telemetry/opentelemetry-python-contrib)
- [导入时的 Guance 自有实现](https://github.com/GuanceCloud/opentelemetry-python-contrib/tree/40b90737969d7dfd48a732a93a3a3734f55bff27)

保留上游源码布局、包名和[许可证](LICENSE)。`beacon-otel` 与 `beacon-profiling` 作为独立包发布，不以现有 Guance 包版本覆盖已发布制品。
