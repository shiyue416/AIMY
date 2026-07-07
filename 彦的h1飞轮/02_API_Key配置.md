# 🔑 API Key 配置指南
> 不配 Key → 工具只用免费数据源 → 覆盖率损失 30-50%

---

## subfinder API Keys

配置文件位置: `~/.config/subfinder/provider-config.yaml`

```yaml
# 编辑此文件，填入对应 Key
virustotal:
  - YOUR_VT_KEY
shodan:
  - YOUR_SHODAN_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_SECRET
securitytrails:
  - YOUR_ST_KEY
binaryedge:
  - YOUR_BE_KEY
github:
  - YOUR_GITHUB_TOKEN
```

### 免费 Key 获取地址

| 数据源 | 注册地址 | 免费额度 |
|--------|---------|---------|
| VirusTotal | https://virustotal.com | 500次/天 |
| Shodan | https://shodan.io | 有限免费 |
| Censys | https://censys.io | 250次/月 |
| SecurityTrails | https://securitytrails.com | 50次/月 |
| GitHub Token | https://github.com/settings/tokens | 按速率限制 |
| chaos (PD) | https://chaos.projectdiscovery.io | 免费申请 |

> **优先配**: GitHub Token（免费+量大）+ VirusTotal（覆盖率提升最明显）

---

## uncover API Keys

配置文件: `~/.config/uncover/provider-config.yaml`

```yaml
shodan:
  - YOUR_SHODAN_KEY
fofa:
  - YOUR_FOFA_EMAIL:YOUR_FOFA_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
quake:
  - YOUR_QUAKE_KEY
hunter:
  - YOUR_HUNTER_KEY
```

### FOFA（国内最强测绘，必配）

```
注册: https://fofa.info
免费账户: 每天 100 条，够用
Key 位置: 个人中心 → API Key
```

---

## nuclei PDCP Key（可选，扩展模板）

```bash
# 登录 ProjectDiscovery Cloud Platform
nuclei -auth
# 或设置环境变量
export PDCP_API_KEY=your_key
```

---

## 配置后验证

```bash
# 验证 subfinder 数据源激活数量
subfinder -d test.com -ls

# 验证 uncover
uncover -q 'ssl:"target.com"' -e shodan,fofa -silent | head -5
```

---

## 快速配置（最小配置，先跑起来）

```bash
# 1. 创建配置目录
mkdir -p ~/.config/subfinder

# 2. 写入最小配置（只用 GitHub Token）
cat > ~/.config/subfinder/provider-config.yaml << EOF
github:
  - YOUR_GITHUB_TOKEN_HERE
EOF

# 3. 测试
subfinder -d hackerone.com -silent | head -10
```
