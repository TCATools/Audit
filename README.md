## Audit

js/ts/css 依赖分析工具

### 工具

#### npm audit

检查package.json和package-lock.json，默认使用v9.8.1版本，可用环境变量NPM_VERSION=v6.14.16切换至v6.14.16版本

#### yarn audit

检查yarn.lock，默认版本为v1.22.19

### 规则

- 一般：VUL_INFO
- 警告：VUL_WARN
- 严重：VUL_ERROR
