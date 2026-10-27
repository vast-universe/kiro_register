# Kiro 自动注册工具 (iCloud + LuckMail)

纯协议实现的 AWS Builder ID (Kiro) 自动注册工具。

## 支持的接码方式

| 模式 | 说明 | 配置 |
|------|------|------|
| `icloud` | iCloud 邮箱 + api798.com 接码 | accounts.txt + config.json |
| `luckmail` | LuckMail 平台临时邮箱 | config.json 中填入 api_key |

## 快速开始

```bash
pip install curl_cffi cbor2 jwcrypto requests

# 1. 配置 config.json（填入接码信息）
# 2. 准备 accounts.txt（iCloud 模式：每行一个邮箱）
# 3. 准备 proxies.txt（每行一个代理，格式: user:pass@host:port）

# 单次注册
python main.py

# 批量注册
python main.py --batch 5

# 指定接码模式
python main.py --mode luckmail

# 手动输入验证码
python main.py --manual

# 列出已注册账号
python main.py --list

# 切换账号到 Kiro IDE
python main.py --switch
```

## 文件说明

```
├── main.py              # 入口
├── core.py              # 注册核心逻辑
├── icloud_mailbox.py    # iCloud 接码（api798.com）
├── luckmail_mailbox.py  # LuckMail 接码
├── luckmail/            # LuckMail SDK
├── switch.py            # Kiro IDE 账号切换
├── file_lock.py         # 并发文件锁
├── config.json          # 配置文件
├── accounts.txt         # 邮箱列表（iCloud 模式）
├── proxies.txt          # 代理列表
└── kiro_accounts.txt    # 注册结果
```

## 配置说明

### iCloud 模式
- `accounts.txt`: 每行一个 iCloud 邮箱地址
- `config.json` → `icloud.api_url`: 接码 API 地址
- `config.json` → `icloud.auth_code`: API 认证码

### LuckMail 模式
- `config.json` → `luckmail.api_key`: LuckMail API Key
- 不需要 accounts.txt（平台自动分配邮箱）

### 代理
- `proxies.txt`: 每行一个代理，格式 `user:pass@host:port`
- 一号一IP 策略，用完自动删除
```
