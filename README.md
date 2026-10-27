# Kiro 自动注册工具 (iCloud + LuckMail)

纯协议实现的 AWS Builder ID (Kiro) 自动注册工具。

## 支持的接码方式

| 模式 | 说明 | 配置 |
|------|------|------|
| `icloud` | iCloud 邮箱接码（专属 API 或 api798.com） | `icloud.accounts_file` + config.json |
| `luckmail` | LuckMail 平台临时邮箱 | config.json 中填入 api_key |

iCloud 模式支持两种账号文件格式（每行一条）：

```text
# 格式 1：邮箱 + 专属接码 API（推荐，如 icloudemail.txt）
xxx@icloud.com----https://ima2.52dfd.top/api/v1/mailboxes/xxx@icloud.com/code?key=xxxxx

# 格式 2：仅邮箱（如 accounts.txt，走 api798.com 公共接口）
xxx@icloud.com
```

## 快速开始

```bash
pip install curl_cffi cbor2 jwcrypto requests

# 1. 配置 config.json（icloud.accounts_file 指向 icloudemail.txt）
# 2. 准备 proxies.txt（每行一个代理，格式: user:pass@host:port）

# 单次注册
python main.py

# 指定账号文件（覆盖 config.json）
python main.py --accounts-file icloudemail.txt

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
├── icloud_mailbox.py    # iCloud 接码（专属 API / api798.com）
├── luckmail_mailbox.py  # LuckMail 接码
├── luckmail/            # LuckMail SDK
├── switch.py            # Kiro IDE 账号切换
├── file_lock.py         # 并发文件锁
├── config.json          # 配置文件
├── icloudemail.txt      # 邮箱 + 专属接码 API（默认账号文件）
├── accounts.txt         # 仅邮箱（走 api798 公共接码）
├── proxies.txt          # 代理列表
└── kiro_accounts.txt    # 注册结果
```

## 配置说明

### iCloud 模式
- `config.json` → `icloud.accounts_file`: 账号文件名（默认 `icloudemail.txt`，也支持 `accounts.txt`）
- `config.json` → `icloud.wait_ms`: 专属 API 长轮询等待毫秒数（默认 10000）
- `config.json` → `icloud.api_url`: 公共接码 API 地址（账号行没有专属 API 时使用）
- `config.json` → `icloud.auth_code`: 公共接码 API 认证码
- 专属 API 返回 JSON（`success` / `code` / `received_at`），代码会忽略 `no_code` 和 `peek` 到的旧验证码

#### 专属取码 API 响应

成功（`peek=1` 会返回最近一次已缓存的验证码）：

```json
{
  "success": true,
  "code": "465456",
  "email": "jouster.maddest-27@icloud.com",
  "subject": "验证您的 AWS 构建者 ID 电子邮件地址",
  "message_id": "msg_942029",
  "received_at": "2026-10-27T23:45:35+08:00",
  "icloud_in_at": "2026-10-27T23:45:35+08:00",
  "icloud_out_at": "2026-10-27T23:45:40+08:00",
  "inbox_at": "2026-10-27T23:45:43+08:00",
  "written_at": "2026-10-27T23:45:47+08:00"
}
```

未收到码 / 错误（HTTP 200，`success=false`）：

```json
{"success": false, "code": "no_code", "message": "暂未收到验证码，智能事件接码V5正在后台同步", "retryable": true}
{"success": false, "code": "invalid_api_key", "message": "API Key 错误", "retryable": false}
```

- 不带 `peek` 时只等待新事件，已经取过的旧码会返回 `no_code`；带 `peek=1` 可读最近一次缓存码（本工具用它做旧码快照）
- 可选参数：`wait_ms`（长轮询毫秒）、`after`（RFC3339 时间，只取该时间之后的码）、`keyword`、`session_id`
- 本工具只依赖 `success` 和 `code`，同时兼容 `codes` 数组、`primary_code`、纯数字及旧 api798 的 HTML 响应

### LuckMail 模式
- `config.json` → `luckmail.api_key`: LuckMail API Key
- 不需要 accounts.txt（平台自动分配邮箱）

### 代理
- `proxies.txt`: 每行一个代理，格式 `user:pass@host:port`
- 一号一IP 策略，用完自动删除
```
# kiro_register
