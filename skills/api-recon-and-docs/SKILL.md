---
name: api-recon-and-docs
description: >-
  API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, and surface area for API testing.
---

# SKILL: API Recon and Docs — Endpoints, Schemas, and Version Surface

> **AI LOAD INSTRUCTION**: Use this skill first when the target is a REST, mobile, or GraphQL API and you need to enumerate endpoints, documentation, versions, and hidden surface area before exploitation.

## 1. PRIMARY GOALS

1. Discover all reachable API entrypoints.
2. Extract schemas, optional fields, and role differences.
3. Identify old versions, mobile paths, GraphQL endpoints, and undocumented parameters.

## 2. RECON CHECKLIST

### JavaScript and client mining

```bash
curl https://target/app.js | grep -oE '(/api|/rest|/graphql)[^"'\'' ]+' | sort -u
```

### Common documentation and schema paths

```text
/swagger.json
/openapi.json
/api-docs
/docs
/.well-known/
/graphql
/gql
```

### Version and product drift

```text
/api/v1/
/api/v2/
/api/mobile/v1/
/legacy/
```

## 3. WHAT TO EXTRACT FROM DOCS

- optional and undocumented fields
- admin-only request examples
- deprecated endpoints that may still be active
- schema hints like `additionalProperties: true`
- parameter names tied to filtering, sorting, IDs, roles, or tenancy

## 4. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| object IDs everywhere | [api authorization and bola](../api-authorization-and-bola/SKILL.md) |
| JWT, OAuth, role claims | [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) |
| GraphQL or hidden fields | [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md) |
| strong auth boundary but suspicious business flow | [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) |

<!-- FLYWHEEL_APPEND -->
<!-- 以下内容由 EVX 飞轮自动维护，手动编辑会被覆盖 -->

## 🔄 飞轮进化技法 (auto-updated 2026-07-01 00:17)

> 以下技法是该漏洞类型中**H1 真实 accept 记录里综合得分最高的一项**。
> 遇到此类漏洞时**优先尝试此技法**。

### 🏆 Recon: Favicon Hash — mmh3 hash → FOFA/Shodan 查同图标资产

| 指标 | 值 |
|------|----|
| 接受率 | **100%** (1/1) |
| 平均赏金 | ¥2 |
| 漏洞类型 | `recon` |

