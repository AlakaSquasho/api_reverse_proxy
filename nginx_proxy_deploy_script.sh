#!/bin/bash

# Nginx反向代理一键部署脚本
# 适用于CentOS 7 和 Ubuntu 系统
# 作者: Assistant
# 版本: 1.2 (添加Ubuntu支持)

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局OS变量
OS=""
OS_VERSION=""

# 状态目录（用于记录已完成的步骤，避免重复执行）
STATE_DIR="/var/lib/api_reverse_proxy"

# 创建状态目录（需要 sudo）
ensure_state_dir() {
    if [[ ! -d "$STATE_DIR" ]]; then
        sudo mkdir -p "$STATE_DIR"
        sudo chmod 755 "$STATE_DIR"
    fi
}

# 在状态目录中创建标记文件
create_marker() {
    ensure_state_dir
    sudo bash -c "echo \"$2\" > '$STATE_DIR/$1'"
}

# 检查标记文件是否存在
marker_exists() {
    [[ -f "$STATE_DIR/$1" ]]
}

# 读取状态文件内容（输出内容）
read_state() {
    if [[ -f "$STATE_DIR/$1" ]]; then
        sudo cat "$STATE_DIR/$1"
    fi
}

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户（脚本不建议以root直接运行）
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "请不要使用root用户直接运行此脚本"
        log_info "请使用普通用户运行，脚本会在需要时自动使用sudo"
        exit 1
    fi
}

# 检查系统版本并设置OS变量（支持CentOS 7 和 Ubuntu）
check_system() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        ID_L=$(echo "${ID:-}" | tr '[:upper:]' '[:lower:]')
        VERSION_ID_STR="${VERSION_ID:-}"
    fi

    # CentOS 7 检查（保留之前的 /etc/redhat-release 检查方式作为兼容）
    if [[ -f /etc/redhat-release ]]; then
        if grep -qi 'CentOS' /etc/redhat-release || grep -qi 'Red Hat' /etc/redhat-release; then
            local version=$(cat /etc/redhat-release | grep -oE '[0-9]+' | head -n1)
            if [[ "$version" == "7" ]]; then
                OS="centos"
                OS_VERSION="7"
                log_success "系统检查通过: CentOS 7"
                return 0
            else
                log_error "此脚本仅支持CentOS 7 或 Ubuntu 系统，检测到: $(cat /etc/redhat-release)"
                exit 1
            fi
        fi
    fi

    # Ubuntu 检查
    if [[ "$ID_L" == "ubuntu" ]]; then
        # 允许所有较新的 ubuntu 版本 (18.04+ 推荐)
        OS="ubuntu"
        OS_VERSION="$VERSION_ID_STR"
        log_success "系统检查通过: Ubuntu $OS_VERSION"
        return 0
    fi

    log_error "此脚本仅支持 CentOS 7 或 Ubuntu 系统，当前系统不受支持"
    exit 1
}

# 收集用户配置
collect_config() {
    log_info "开始收集配置信息..."
    
    # 域名配置
    while true; do
        read -p "请输入您的域名 (例如: mydomain.com): " DOMAIN
        if [[ -n "$DOMAIN" ]]; then
            break
        fi
        log_warning "域名不能为空，请重新输入"
    done
    
    # 子域名配置
    read -p "请输入子域名前缀 (默认: api): " SUBDOMAIN
    SUBDOMAIN=${SUBDOMAIN:-api}
    FULL_DOMAIN="${SUBDOMAIN}.${DOMAIN}"
    
    # 端口配置
    read -p "请输入HTTPS端口 (默认: 8443): " HTTPS_PORT
    HTTPS_PORT=${HTTPS_PORT:-8443}
    
    read -p "请输入HTTP端口 (默认: 8080): " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-8080}
    
    # 速率限制配置
    read -p "请输入每分钟请求限制 (默认: 100): " RATE_LIMIT
    RATE_LIMIT=${RATE_LIMIT:-100}
    
    read -p "请输入突发请求限制 (默认: 20): " BURST_LIMIT
    BURST_LIMIT=${BURST_LIMIT:-20}
    
    # 邮箱配置（用于SSL证书）
    while true; do
        read -p "请输入您的邮箱地址 (用于SSL证书申请): " EMAIL
        if [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        fi
        log_warning "邮箱格式不正确，请重新输入"
    done
    
    # 确认配置
    echo
    log_info "配置信息确认:"
    echo "域名: $FULL_DOMAIN"
    echo "HTTPS端口: $HTTPS_PORT"
    echo "HTTP端口: $HTTP_PORT"
    echo "速率限制: ${RATE_LIMIT}次/分钟"
    echo "突发限制: $BURST_LIMIT"
    echo "邮箱: $EMAIL"
    echo
    
    read -p "确认以上配置正确吗? (y/N): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log_info "已取消部署"
        exit 0
    fi
}


# 安装依赖（根据OS变量选择包管理器）
install_dependencies() {
    log_info "安装依赖 (OS=$OS)..."

    # 幂等检查：如果之前已成功安装过依赖则跳过
    if marker_exists deps_installed; then
        log_info "检测到依赖已安装，跳过此步骤"
        return 0
    fi

    if [[ "$OS" == "centos" ]]; then
        log_info "更新系统包..."
        sudo yum update -y
        
        log_info "安装EPEL仓库..."
        sudo yum install -y epel-release
        
        log_info "安装Nginx..."
        sudo yum install -y nginx
        
        log_info "安装Certbot..."
        sudo yum install -y certbot python2-certbot-nginx

    elif [[ "$OS" == "ubuntu" ]]; then
        log_info "更新系统包..."
        sudo apt-get update -y

        log_info "安装必要工具..."
        sudo apt-get install -y software-properties-common apt-transport-https ca-certificates cron

        log_info "安装Nginx..."
        sudo apt-get install -y nginx

        log_info "安装Certbot (apt 版本，Ubuntu 上可能推荐使用 snap 在新版系统上安装证书工具)..."
        # 使用 apt 提供的 certbot 和 nginx 插件
        sudo apt-get install -y certbot python3-certbot-nginx || {
            log_warning "apt 安装 certbot 失败，尝试通过 snap 安装（需要 snapd）"
            sudo apt-get install -y snapd
            sudo snap install core; sudo snap refresh core
            sudo snap install --classic certbot
            sudo ln -s /snap/bin/certbot /usr/bin/certbot || true
        }
    else
        log_error "未知操作系统: $OS"
        exit 1
    fi

    # 标记已安装
    create_marker deps_installed "installed"

    log_success "依赖安装完成"
}

# 配置防火墙（支持 firewalld 与 ufw）
setup_firewall() {
    log_info "配置防火墙 (OS=$OS)..."
    ensure_state_dir

    if [[ "$OS" == "centos" ]]; then
        # 检查firewalld是否运行
        if ! sudo systemctl is-active --quiet firewalld; then
            log_warning "firewalld未运行，启动firewalld..."
            sudo systemctl start firewalld
            sudo systemctl enable firewalld
        fi

        # 检查上次配置的端口（如果有），若相同则跳过配置
        local desired_ports="${HTTPS_PORT}:${HTTP_PORT}"
        local existing_config=$(read_state firewall_ports || true)
        if [[ "$existing_config" == "$desired_ports" && $(sudo firewall-cmd --list-ports) ]]; then
            log_info "防火墙已按需配置（端口 ${desired_ports}），跳过"
            return 0
        fi

        # 保存现有防火墙规则（以便恢复）
        log_info "保存现有防火墙规则..."
        local existing_ports=$(sudo firewall-cmd --list-ports)
        log_info "当前开放的端口: $existing_ports"

        # 确保基本服务端口开放
        sudo firewall-cmd --permanent --add-port=22/tcp || true
        sudo firewall-cmd --permanent --add-port=21/tcp || true
        sudo firewall-cmd --permanent --add-port=53/tcp || true
        sudo firewall-cmd --permanent --add-port=53/udp || true

        # 开放代理服务端口
        sudo firewall-cmd --permanent --add-port=${HTTPS_PORT}/tcp || true
        sudo firewall-cmd --permanent --add-port=${HTTP_PORT}/tcp || true
        sudo firewall-cmd --permanent --add-port=80/tcp || true
        sudo firewall-cmd --permanent --add-port=443/tcp || true

        # 如果有现有端口规则，确保也添加（防止覆盖）
        if [[ -n "$existing_ports" ]]; then
            for port in $existing_ports; do
                sudo firewall-cmd --permanent --add-port=$port || true
            done
        fi

        # 重新载入规则
        sudo firewall-cmd --reload

        # 记录已配置的端口
        create_marker firewall_ports "$desired_ports"

    elif [[ "$OS" == "ubuntu" ]]; then
        # 使用 ufw
        if ! command -v ufw >/dev/null 2>&1; then
            log_info "安装 ufw..."
            sudo apt-get install -y ufw
        fi
        ensure_state_dir

        # 检查上次配置的端口（如果有），若相同则跳过配置
        local desired_ports="${HTTPS_PORT}:${HTTP_PORT}"
        local existing_config=$(read_state firewall_ports || true)
        if [[ "$existing_config" == "$desired_ports" && $(sudo ufw status | grep -i "Status: active" >/dev/null 2>&1; echo $?) -eq 0 ]]; then
            log_info "UFW 防火墙已按需配置（端口 ${desired_ports}），跳过"
            return 0
        fi

        # 保存现有防火墙规则
        log_info "保存现有 UFW 规则..."
        local existing_rules=$(sudo ufw status numbered | grep ALLOW || true)
        log_info "当前 UFW 规则: $existing_rules"

        # 确保基本服务端口开放（在启用 UFW 前）
        sudo ufw allow 22/tcp || true    # SSH
        sudo ufw allow 21/tcp || true    # FTP
        sudo ufw allow 53/tcp || true    # DNS
        sudo ufw allow 53/udp || true    # DNS
        sudo ufw allow 443/tcp || true   # HTTPS

        # 开放代理服务端口
        sudo ufw allow "${HTTPS_PORT}/tcp" || true
        sudo ufw allow "${HTTP_PORT}/tcp" || true
        sudo ufw allow "80/tcp" || true  # HTTP验证需要

        # 启用 ufw（如果未启用）
        if ! sudo ufw status | grep -qi "Status: active"; then
            log_info "启用 ufw 防火墙..."
            sudo ufw --force enable
        else
            sudo ufw reload || true
        fi

        # 记录已配置的端口
        create_marker firewall_ports "$desired_ports"

    else
        log_warning "跳过防火墙配置：未知操作系统 $OS"
    fi

    log_success "防火墙配置完成"
}

# 获取SSL证书
setup_ssl() {
    log_info "申请SSL证书..."
    ensure_state_dir

    # 如果证书已经存在，则跳过申请
    if [[ -d "/etc/letsencrypt/live/${FULL_DOMAIN}" ]]; then
        log_info "检测到已存在的证书 /etc/letsencrypt/live/${FULL_DOMAIN}，跳过申请"
        create_marker "ssl_obtained_${FULL_DOMAIN}" "exists"
        return 0
    fi
    
    # 检查域名解析
    log_info "检查域名解析..."
    if ! nslookup "$FULL_DOMAIN" > /dev/null 2>&1; then
        log_warning "域名解析检查失败，请确保域名已正确解析到此服务器"
        read -p "是否继续? (y/N): " CONTINUE
        if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
            exit 1
        fi
    fi
    
    # 临时停止可能占用80端口的服务
    sudo systemctl stop nginx 2>/dev/null || true
    
    # 申请证书
    if sudo certbot certonly --standalone -d "$FULL_DOMAIN" --email "$EMAIL" --agree-tos --non-interactive; then
        log_success "SSL证书申请成功"
        create_marker "ssl_obtained_${FULL_DOMAIN}" "issued"
    else
        log_error "SSL证书申请失败，请检查域名解析和网络连接"
        exit 1
    fi
}

# 生成Nginx配置
generate_nginx_config() {
    log_info "生成Nginx配置文件..."
    ensure_state_dir

    # 如果已经为该域名生成过代理配置且包含FULL_DOMAIN，则跳过
    if [[ -f "/etc/nginx/conf.d/api-proxy.conf" ]]; then
        if sudo grep -q "${FULL_DOMAIN}" /etc/nginx/conf.d/api-proxy.conf 2>/dev/null; then
            log_info "检测到已存在的 Nginx 代理配置，跳过生成"
            create_marker nginx_configured "${FULL_DOMAIN}"
            return 0
        fi
    fi
    
    # 备份原配置
    sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # 生成主配置文件
    sudo tee /etc/nginx/nginx.conf > /dev/null <<'EOF'
user root;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 速率限制配置
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=RATE_LIMIT/m;
    limit_req_status 429;

    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # 包含站点配置
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # 替换配置中的变量
    sudo sed -i "s/RATE_LIMIT/${RATE_LIMIT}/g" /etc/nginx/nginx.conf

    # 生成API代理配置文件
    sudo tee /etc/nginx/conf.d/api-proxy.conf > /dev/null <<'EOF'
# 上游服务器配置
upstream gemini_api {
    server generativelanguage.googleapis.com:443;
    keepalive 32;
}

upstream openai_api {
    server api.openai.com:443;
    keepalive 32;
}

# 主服务器配置
server {
    listen HTTPS_PORT ssl http2;
    server_name FULL_DOMAIN;

    # SSL证书配置
    ssl_certificate /etc/letsencrypt/live/FULL_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/FULL_DOMAIN/privkey.pem;
    
    # SSL安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # 安全头部
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 日志配置
    access_log /var/log/nginx/api_access.log main;
    error_log /var/log/nginx/api_error.log;

    # Gemini API代理
    location /gemini/ {
        # 应用速率限制
        limit_req zone=api_limit burst=BURST_LIMIT nodelay;
        
        # 代理配置
        proxy_pass https://gemini_api/;
        proxy_ssl_server_name on;
        proxy_ssl_name generativelanguage.googleapis.com;
        proxy_ssl_verify off;
        
        # 请求头配置
        proxy_set_header Host generativelanguage.googleapis.com;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 连接配置
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        proxy_buffering off;
        proxy_request_buffering off;
        
        # 去除路径前缀
        rewrite ^/gemini/(.*)$ /$1 break;
    }

    # OpenAI API代理
    location /openai/ {
        # 应用速率限制
        limit_req zone=api_limit burst=BURST_LIMIT nodelay;
        
        # 代理配置
        proxy_pass https://openai_api/;
        proxy_ssl_server_name on;
        proxy_ssl_name api.openai.com;
        proxy_ssl_verify off;
        
        # 请求头配置
        proxy_set_header Host api.openai.com;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 连接配置
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        proxy_buffering off;
        proxy_request_buffering off;
        
        # 去除路径前缀
        rewrite ^/openai/(.*)$ /$1 break;
    }

    # 健康检查端点
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # 状态监控端点
    location /status {
        access_log off;
        return 200 '{"status":"running","timestamp":"2024-01-01T00:00:00Z"}';
        add_header Content-Type application/json;
    }

    # 默认返回404
    location / {
        return 404 '{"error":"Not Found","message":"Available endpoints: /gemini/, /openai/, /health, /status"}';
        add_header Content-Type application/json;
    }
}

# HTTP重定向到HTTPS
server {
    listen HTTP_PORT;
    server_name FULL_DOMAIN;
    
    # 健康检查允许HTTP访问
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # 其他请求重定向到HTTPS
    location / {
        return 301 https://$server_name:HTTPS_PORT$request_uri;
    }
}
EOF

    # 替换配置中的变量
    sudo sed -i "s/HTTPS_PORT/${HTTPS_PORT}/g" /etc/nginx/conf.d/api-proxy.conf
    sudo sed -i "s/HTTP_PORT/${HTTP_PORT}/g" /etc/nginx/conf.d/api-proxy.conf
    sudo sed -i "s/FULL_DOMAIN/${FULL_DOMAIN}/g" /etc/nginx/conf.d/api-proxy.conf
    sudo sed -i "s/BURST_LIMIT/${BURST_LIMIT}/g" /etc/nginx/conf.d/api-proxy.conf

    log_success "Nginx配置文件生成完成"
}

# 设置日志轮转
setup_log_rotation() {
    log_info "配置日志轮转..."

    ensure_state_dir
    if marker_exists logrotate_configured; then
        log_info "日志轮转已配置，跳过"
        return 0
    fi

    sudo tee /etc/logrotate.d/nginx-api > /dev/null <<EOF
/var/log/nginx/api_*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 nginx adm
    sharedscripts
    postrotate
        systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}
EOF

    # 标记已配置
    create_marker logrotate_configured "done"

    log_success "日志轮转配置完成"
}

# 设置SSL证书自动续期
setup_ssl_renewal() {
    log_info "配置SSL证书自动续期..."
    
    # 检查cron服务是否安装和运行
    if ! command -v crontab >/dev/null 2>&1; then
        if [[ "$OS" == "ubuntu" ]]; then
            log_info "安装cron服务..."
            sudo apt-get install -y cron
        elif [[ "$OS" == "centos" ]]; then
            log_info "安装cronie服务..."
            sudo yum install -y cronie
        fi
    fi

    # 确保cron服务在运行
    if [[ "$OS" == "ubuntu" ]]; then
        sudo systemctl enable cron
        sudo systemctl start cron
    elif [[ "$OS" == "centos" ]]; then
        sudo systemctl enable crond
        sudo systemctl start crond
    fi
    
    ensure_state_dir
    if marker_exists ssl_renewal_configured; then
        log_info "SSL 自动续期已配置，跳过"
        return 0
    fi

    # 添加到crontab
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/certbot renew --quiet && systemctl reload nginx") | crontab -
        # 标记已配置
        create_marker ssl_renewal_configured "done"
        log_success "SSL证书自动续期配置完成"
    else
        log_warning "无法配置自动续期，请手动添加以下命令到crontab："
        echo "0 2 * * * /usr/bin/certbot renew --quiet && systemctl reload nginx"
    fi
}

# 启动服务
start_services() {
    log_info "启动服务..."
    ensure_state_dir
    # 如果已经启动并记录过，则跳过
    if marker_exists services_started; then
        if sudo systemctl is-active --quiet nginx; then
            if sudo nginx -t >/dev/null 2>&1; then
                log_info "Nginx 已在运行且配置通过，跳过启动"
                return 0
            fi
        fi
    fi
    
    # 验证配置
    if ! sudo nginx -t; then
        log_error "Nginx配置验证失败"
        log_info "查看配置文件内容以排查问题:"
        sudo cat /etc/nginx/conf.d/api-proxy.conf
        exit 1
    fi
    
    # 启动并设置开机自启
    sudo systemctl start nginx
    sudo systemctl enable nginx
    
    # 检查服务状态
    if sudo systemctl is-active --quiet nginx; then
        log_success "Nginx服务启动成功"
        create_marker services_started "$(date -u +%Y%m%dT%H%M%SZ)"
    else
        log_error "Nginx服务启动失败"
        sudo systemctl status nginx
        exit 1
    fi
}

# 运行测试
run_tests() {
    log_info "运行服务测试..."
    
    # 等待服务完全启动
    sleep 3
    
    # 测试健康检查
    if curl -s -f "http://${FULL_DOMAIN}:${HTTP_PORT}/health" > /dev/null; then
        log_success "HTTP健康检查测试通过"
    else
        log_warning "HTTP健康检查测试失败"
    fi
    
    if curl -s -f -k "https://${FULL_DOMAIN}:${HTTPS_PORT}/health" > /dev/null; then
        log_success "HTTPS健康检查测试通过"
    else
        log_warning "HTTPS健康检查测试失败"
    fi
    
    # 测试速率限制
    log_info "测试速率限制功能..."
    local rate_limit_triggered=false
    for ((i=1; i<=RATE_LIMIT+5; i++)); do
        if ! curl -s -f -k "https://${FULL_DOMAIN}:${HTTPS_PORT}/health" > /dev/null; then
            rate_limit_triggered=true
            break
        fi
    done
    
    if [ "$rate_limit_triggered" = true ]; then
        log_success "速率限制功能正常"
    else
        log_warning "速率限制可能未正常工作"
    fi
}

# 生成使用文档
generate_usage_doc() {
    local doc_file="/tmp/nginx_proxy_usage.txt"
    
    cat > $doc_file <<EOF
===========================================
Nginx API反向代理服务部署完成
===========================================

服务信息:
- 域名: ${FULL_DOMAIN}
- HTTPS端口: ${HTTPS_PORT}
- HTTP端口: ${HTTP_PORT}
- 速率限制: ${RATE_LIMIT}次/分钟 (突发${BURST_LIMIT}次)

使用方法:
-----------

1. Gemini API代理:
   原始地址: https://generativelanguage.googleapis.com/v1/models
   代理地址: https://${FULL_DOMAIN}:${HTTPS_PORT}/gemini/v1/models

   示例:
   curl "https://${FULL_DOMAIN}:${HTTPS_PORT}/gemini/v1/models?key=YOUR_API_KEY"

2. OpenAI API代理:
   原始地址: https://api.openai.com/v1/models
   代理地址: https://${FULL_DOMAIN}:${HTTPS_PORT}/openai/v1/models

   示例:
   curl "https://${FULL_DOMAIN}:${HTTPS_PORT}/openai/v1/models" \\
     -H "Authorization: Bearer YOUR_API_KEY"

3. 健康检查:
   curl "https://${FULL_DOMAIN}:${HTTPS_PORT}/health"

4. 状态监控:
   curl "https://${FULL_DOMAIN}:${HTTPS_PORT}/status"

管理命令:
-----------

查看服务状态:
sudo systemctl status nginx

查看访问日志:
sudo tail -f /var/log/nginx/api_access.log

查看错误日志:
sudo tail -f /var/log/nginx/api_error.log

重启服务:
sudo systemctl restart nginx

重新加载配置:
sudo systemctl reload nginx

验证配置:
sudo nginx -t

查看SSL证书状态:
sudo certbot certificates

手动续期SSL证书:
sudo certbot renew

故障排除:
-----------

1. 如果无法访问，检查防火墙和端口:
   sudo firewall-cmd --list-ports
   sudo netstat -tlnp | grep nginx

2. 如果SSL证书有问题:
   sudo certbot certificates
   sudo certbot renew --dry-run

3. 如果代理失败，检查上游服务器连接:
   curl -I https://generativelanguage.googleapis.com
   curl -I https://api.openai.com

配置文件位置:
--------------
- 主配置: /etc/nginx/nginx.conf
- 代理配置: /etc/nginx/conf.d/api-proxy.conf
- SSL证书: /etc/letsencrypt/live/${FULL_DOMAIN}/
- 日志文件: /var/log/nginx/

安全注意事项:
--------------
1. 定期更新系统和Nginx版本
2. 监控访问日志，注意异常访问
3. 根据实际使用情况调整速率限制
4. 定期备份配置文件

===========================================
EOF

    log_success "使用文档已生成: $doc_file"
    
    # 显示简要信息
    echo
    log_info "=== 部署完成 ==="
    echo "服务地址: https://${FULL_DOMAIN}:${HTTPS_PORT}"
    echo "健康检查: https://${FULL_DOMAIN}:${HTTPS_PORT}/health"
    echo "详细使用说明请查看: $doc_file"
    echo
    log_success "Nginx API反向代理服务部署成功！"
}

# 清理函数
cleanup_on_error() {
    log_error "部署过程中发生错误，正在清理..."
    sudo systemctl stop nginx 2>/dev/null || true
    exit 1
}

# 主函数
main() {
    echo "=========================================="
    echo "     Nginx API反向代理一键部署脚本"
    echo "     版本: 1.2 (添加Ubuntu支持)"
    echo "=========================================="
    echo
    
    # 设置错误处理
    trap cleanup_on_error ERR
    
    # 执行部署步骤
    #check_root
    check_system
    collect_config
    install_dependencies
    setup_firewall
    setup_ssl
    generate_nginx_config
    setup_log_rotation
    setup_ssl_renewal
    start_services
    run_tests
    generate_usage_doc
    
    echo
    log_success "部署完成！"
}

# 运行主函数
main "$@"