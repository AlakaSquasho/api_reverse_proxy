# API Reverse Proxy

反向代理 API 接口地址，实现无需科学上网即可使用。另外为了安全已添加访问速率限制以及 HTTPS 支持。该脚本需部署在服务器端。

## 前置条件

使用该脚本需要：
- 一台服务器（支持 CentOS 7 或 Ubuntu）
- 一个域名（已解析到服务器）
- 一个邮箱（用于 Let's Encrypt 证书申请）

## 快速开始

### 方式一：一键部署（推荐）

```bash
# CentOS 7
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AlakaSquasho/api_reverse_proxy/main/nginx_proxy_deploy_script.sh)"

# Ubuntu
curl -fsSL https://raw.githubusercontent.com/AlakaSquasho/api_reverse_proxy/main/nginx_proxy_deploy_script.sh | bash
```

### 方式二：手动下载运行

1. 下载脚本
```bash
curl -O https://raw.githubusercontent.com/AlakaSquasho/api_reverse_proxy/main/nginx_proxy_deploy_script.sh
```

2. 添加执行权限
```bash
chmod +x nginx_proxy_deploy_script.sh
```

3. 运行脚本
```bash
./nginx_proxy_deploy_script.sh
```

## 配置过程

运行脚本后，您需要依次输入：

- 域名（例如：`mydomain.com`）
- 子域名前缀（默认：`api`）
- HTTPS 端口号（默认：`8443`）
- HTTP 端口号（默认：`8080`）
- 速率限制 [每分钟请求次数]（默认：`100`）
- 突发请求限制（默认：`20`）
- SSL 证书申请用邮箱

## 使用方法

部署完成后，您可以通过以下地址访问 API：

### Gemini API
- 原始地址：`https://generativelanguage.googleapis.com`
- 代理地址：`https://api.mydomain.com:8443/gemini`

### OpenAI API
- 原始地址：`https://api.openai.com`
- 代理地址：`https://api.mydomain.com:8443/openai`

## 安全说明

- 脚本会自动配置防火墙规则
- 保留现有防火墙规则（包括 SSH 等重要服务端口）
- 自动配置 HTTPS 证书
- 包含请求速率限制
- 自动配置证书续期

## 监控与维护

- 健康检查：`https://api.mydomain.com:8443/health`
- 状态监控：`https://api.mydomain.com:8443/status`
- 详细使用说明将在部署完成后生成

## 注意事项

1. 确保域名已正确解析到服务器
2. 确保服务器防火墙允许 HTTP(80) 和 HTTPS(443) 端口
3. 建议在生产环境部署前先在测试环境验证
4. 部署过程中如遇问题，请查看脚本生成的日志