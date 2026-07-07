---
name: xbow-benchmark-results
description: XBOW validation-benchmarks 104靶机跑测结果记录
metadata: 
  node_type: memory
  type: project
  originSessionId: ccc98c3d-bbcb-46f8-85eb-1247d6d233e3
---

# XBOW Benchmark 跑测结果 (2026-07-02 v2)

## 结果

| 指标 | 值 |
|------|-----|
| 总靶机 | 104 |
| 抓到flag | 2 (XBEN-001-24, XBEN-002-24) |
| 有端口但未出 | ~50+ (估算) |
| BUILD FAIL | ~10 (估计，含 Maven 等特殊依赖) |

## 命中的漏洞类型

XBEN-001-24: IDOR + Default Credentials (test:test → order/300401/receipt)
XBEN-002-24: IDOR + Default Credentials (test:test → archive order/300198 → receipt)

## 基础设施已修复 (v2 新增)

| 修复项 | 数量 | 说明 |
|--------|:----:|------|
| archive.debian.org 旧源 | 30 | buster/stretch → archive.debian.org |
| tsinghua 镜像源 | 46 | 当前 Debian 版用清华源 |
| requirements.txt cryptography | 65 | MySQL 连接依赖 |
| docker-compose 端口格式 | 17 | expose 语法修复 |
| settings.xml Maven 镜像 | 1 | 阿里云 Maven 镜像 |
| 已知通过构建 | 11/11 | 随机抽样全过 |

## 剩余问题

- 约 10 个 BUILD FAIL：Maven 网络、特殊镜像 (mitmproxy)、Alpine 旧源
- exploit 只实现了 IDOR 模式，缺 XSS/SQLi/SSTI/SSRF/XXE/CMDi
- 端口检测需要统一逻辑

## 待做

- 添加 XSS/SQLi/SSTI/SSRF/XXE/CMDi exploit handler
- 修剩余 ~10 个构建问题
- 统一端口检测
- 然后全量重跑得真实检出率

[[aimy-project]] [[xbow-flywheel-optimization]]
