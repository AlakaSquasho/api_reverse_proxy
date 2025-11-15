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

> 注意：脚本为幂等设计（会在第一次成功执行时记录状态），可安全重复执行。脚本会尽量跳过已完成的步骤（例如已安装的软件包、已申请的证书或已生成的配置），因此在出现中断后再次运行不会重复执行不必要的操作。

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

## 幂等性设计

脚本采用幂等设计，**可以安全地多次执行**。脚本会记录每个关键步骤的完成状态，在下次运行时自动跳过已完成的步骤，避免重复安装或重复配置。这对于以下场景特别有用：

- 部署过程中由于网络或其他原因中断，可直接重新运行脚本继续部署
- 需要修改某些配置后重新部署时，删除对应的状态标记文件即可

### 状态标记文件位置

所有状态标记文件存储在：`/var/lib/api_reverse_proxy/`

主要标记文件包括：

- `deps_installed` - 依赖包已安装
- `firewall_ports` - 防火墙已配置（内容为 HTTPS_PORT:HTTP_PORT）
- `ssl_obtained_<域名>` - SSL 证书已申请（例：ssl_obtained_api.mydomain.com）
- `nginx_configured` - Nginx 配置已生成
- `logrotate_configured` - 日志轮转已配置
- `ssl_renewal_configured` - SSL 自动续期已配置
- `services_started` - 服务已启动

## 监控与维护

- 健康检查：`https://api.mydomain.com:8443/health`
- 状态监控：`https://api.mydomain.com:8443/status`
- 详细使用说明将在部署完成后生成

## 强制重做步骤（操作指南）

### 查看当前状态

查看所有状态标记文件：

```bash
sudo ls -l /var/lib/api_reverse_proxy
```

查看特定标记文件内容：

```bash
# 查看依赖安装状态
sudo cat /var/lib/api_reverse_proxy/deps_installed

# 查看防火墙配置信息（格式为 HTTPS_PORT:HTTP_PORT）
sudo cat /var/lib/api_reverse_proxy/firewall_ports

# 查看 SSL 证书状态
sudo cat /var/lib/api_reverse_proxy/ssl_obtained_api.mydomain.com

# 查看最后启动时间
sudo cat /var/lib/api_reverse_proxy/services_started
```

### 强制重新执行某个步骤

如果需要重新执行某个步骤，删除对应的标记文件后重新运行脚本即可。

**重新安装依赖：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/deps_installed
./nginx_proxy_deploy_script.sh
```

**重新配置防火墙：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/firewall_ports
./nginx_proxy_deploy_script.sh
```

**重新申请 SSL 证书：**

```bash
# 注意：请确保域名已正确解析且 80/443 端口可达
sudo rm -f /var/lib/api_reverse_proxy/ssl_obtained_api.mydomain.com
./nginx_proxy_deploy_script.sh
```

**重新生成 Nginx 配置：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/nginx_configured
./nginx_proxy_deploy_script.sh
```

**重新配置日志轮转：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/logrotate_configured
./nginx_proxy_deploy_script.sh
```

**重新配置 SSL 自动续期：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/ssl_renewal_configured
./nginx_proxy_deploy_script.sh
```

**重新启动服务：**

```bash
sudo rm -f /var/lib/api_reverse_proxy/services_started
./nginx_proxy_deploy_script.sh
```

**完全重新部署（删除所有标记文件）：**

```bash
sudo rm -rf /var/lib/api_reverse_proxy
./nginx_proxy_deploy_script.sh
```

## 注意事项

1. 确保域名已正确解析到服务器
2. 确保服务器防火墙允许 HTTP(80) 和 HTTPS(443) 端口
3. 建议在生产环境部署前先在测试环境验证
4. 部署过程中如遇问题，请查看脚本生成的日志
5. 状态标记文件需要 sudo 权限查看和修改
6. 删除状态标记文件后重新运行脚本时，请确保环境满足相应操作的前置条件（如防火墙配置时请确保网络连接）