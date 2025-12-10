#!/bin/bash

# 解析命令行参数
# 默认使用 https://gh-proxy.com
GITHUB_PROXY="${GITHUB_PROXY:-https://gh-proxy.com}"
while [[ $# -gt 0 ]]; do
  case $1 in
    --github-proxy)
      if [ -z "$2" ]; then
        echo "错误：请指定 GitHub 代理地址"
        exit 1
      fi
      GITHUB_PROXY="$2"
      shift 2
      ;;
    *)
      echo "未知参数: $1"
      echo "用法: $0 [--github-proxy <代理地址>]"
      echo "      如果不指定 --github-proxy，默认使用 https://gh-proxy.com"
      exit 1
      ;;
  esac
done

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
  echo "错误：请以root用户运行此脚本！"
  exit 1
fi

# 获取公网IP（15秒超时）
echo "正在获取服务器公网IP..."
IP=$(timeout 15 curl -s ifconfig.me)
if [ -z "$IP" ]; then
  echo "⚠️  无法自动获取公网IP（可能网络超时或服务器在内网）"
  echo "请手动输入您的服务器公网IP地址："
  read -p "服务器IP: " IP
  if [ -z "$IP" ]; then
    echo "❌ 未输入IP地址，使用默认值 '你的服务器IP'"
    IP="你的服务器IP"
  else
    echo "✅ 已设置服务器IP: $IP"
  fi
else
  echo "✅ 自动获取到服务器IP: $IP"
fi

# 检查Xray服务是否已存在
if systemctl is-active --quiet xray || command -v xray &>/dev/null; then
  echo "警告：Xray服务或二进制文件已存在！"
  read -p "是否继续安装并覆盖现有配置？(y/n): " confirm
  if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "安装已取消，保留现有Xray配置。"
    # 检查xray服务状态
    if systemctl is-active --quiet xray; then
      echo "检测到Xray服务正在运行，尝试读取现有配置并输出节点链接："
      CONFIG_PATH="/usr/local/etc/xray/config.json"
      if [ -f "$CONFIG_PATH" ]; then
        # 提取参数（从vless inbound中提取）
        UUID=$(grep -A 20 '"protocol": "vless"' "$CONFIG_PATH" | grep -oP '"id"\s*:\s*"\K[^"]+' | head -n1)
        PRIVKEY=$(grep -A 20 '"security": "reality"' "$CONFIG_PATH" | grep -oP '"privateKey"\s*:\s*"\K[^"]+' | head -n1)
        # 计算公钥
        if command -v xray &>/dev/null && [ -n "$PRIVKEY" ]; then
          PUBKEY=$(xray x25519 -i "$PRIVKEY" | grep "Public key" | awk '{print $3}')
        else
          PUBKEY=""
        fi
        
        # 提取mmm端口
        MMM_PORT_EXISTING=$(grep -B 5 -A 10 '"tag":\s*"mmm-in' "$CONFIG_PATH" | grep -oP '"port":\s*\K[0-9]+' | head -n1)
        
        # 提取vless配置的SNI和ShortID (端口4431)
        SNI_EXISTING=$(grep -B 30 '"port":\s*4431' "$CONFIG_PATH" | grep -A 5 '"serverNames"' | grep -oP '"\K[^"]+' | head -n1)
        SHORTID_EXISTING=$(grep -B 30 '"port":\s*4431' "$CONFIG_PATH" | grep -A 3 '"shortIds"' | grep -oP '"\K[^"]+' | grep -v "^$" | head -n1)
        
        [ -z "$SNI_EXISTING" ] && SNI_EXISTING="www.microsoft.com"
        
        # 输出配置信息和节点链接
        echo
        if [ -n "$PUBKEY" ] && [ -n "$SHORTID_EXISTING" ]; then
          VLESS_LINK_EXISTING="vless://$UUID@$IP:$MMM_PORT_EXISTING?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI_EXISTING&fp=chrome&pbk=$PUBKEY&sid=$SHORTID_EXISTING&type=tcp#$IP-$MMM_PORT_EXISTING"
          echo "节点链接："
          echo "$VLESS_LINK_EXISTING"
          echo "$VLESS_LINK_EXISTING" > vless_link.txt
          echo "(节点链接已写入 vless_link.txt)"
          echo
        fi
        
        echo "配置详情："
        echo "  地址: $IP"
        echo "  外部端口: $MMM_PORT_EXISTING (mmm-door)"
        echo "  内部端口: 4431 (vless)"
        echo "  UUID: $UUID"
        echo "  加密: none"
        echo "  流控: xtls-rprx-vision"
        echo "  安全: reality"
        echo "  SNI: $SNI_EXISTING"
        echo "  ShortID: $SHORTID_EXISTING"
        echo "  公钥: $PUBKEY"
        echo
      else
        echo "未找到配置文件 $CONFIG_PATH，无法输出节点链接。"
      fi
    else
      echo "Xray服务未启动，将重新生成配置并重启Xray。"
    fi
    exit 0
  fi
fi

# 安装Xray
echo "正在安装Xray..."

# 使用传入的代理地址或默认值构建下载 URL
# 直接硬编码原始 URL，避免环境变量影响
readonly RAW_SCRIPT_URL="https://raw.githubusercontent.com/Poiig/Xray-install/refs/heads/1.0/install-release.sh"
# 确保代理地址以 / 结尾，避免拼接错误
GITHUB_PROXY_NORMALIZED="${GITHUB_PROXY%/}"
DOWNLOAD_URL="${GITHUB_PROXY_NORMALIZED}/${RAW_SCRIPT_URL}"
TEMP_SCRIPT="/tmp/install-release.sh"

echo "使用 GitHub 代理: $GITHUB_PROXY"
echo "下载地址: $DOWNLOAD_URL"

# 下载安装脚本到本地
echo "正在下载安装脚本..."
SCRIPT_CONTENT=$(curl -sL --max-time 30 "$DOWNLOAD_URL" 2>/dev/null)

if [ -z "$SCRIPT_CONTENT" ]; then
  echo "⚠️  使用代理下载失败，尝试直接下载..."
  SCRIPT_CONTENT=$(curl -sL --max-time 30 "$RAW_SCRIPT_URL" 2>/dev/null)
fi

if [ -z "$SCRIPT_CONTENT" ]; then
  echo "❌ 错误：无法下载安装脚本！"
  echo "请检查网络连接或手动安装Xray。"
  exit 1
fi

# 检查是否是HTML错误页面（包含常见的HTML标签）
if echo "$SCRIPT_CONTENT" | grep -qiE "<html|<head|<title|<!DOCTYPE"; then
  echo "⚠️  返回HTML错误页面，尝试直接下载..."
  SCRIPT_CONTENT=$(curl -sL --max-time 30 "$RAW_SCRIPT_URL" 2>/dev/null)
  if echo "$SCRIPT_CONTENT" | grep -qiE "<html|<head|<title|<!DOCTYPE"; then
    echo "❌ 错误：无法下载有效的安装脚本！"
    exit 1
  fi
fi

# 检查是否是有效的bash脚本
if ! echo "$SCRIPT_CONTENT" | head -n 1 | grep -qE "#!/usr/bin/env bash|#!/bin/bash"; then
  echo "❌ 错误：下载的内容不是有效的bash脚本！"
  exit 1
fi

# 保存脚本到临时文件
rm -f "$TEMP_SCRIPT"
echo "$SCRIPT_CONTENT" > "$TEMP_SCRIPT"
chmod +x "$TEMP_SCRIPT"
echo "✅ 脚本下载成功！保存到: $TEMP_SCRIPT"

# 使用本地脚本执行安装（使用bash -c保持与官方命令一致的行为）
echo "正在执行本地安装脚本..."
INSTALL_ARGS="install"
if [ -n "$GITHUB_PROXY" ]; then
  INSTALL_ARGS="$INSTALL_ARGS --github-proxy $GITHUB_PROXY"
  echo "使用 GitHub 代理: $GITHUB_PROXY"
fi
if bash -c "$(cat "$TEMP_SCRIPT")" @ $INSTALL_ARGS; then
  echo "✅ Xray安装成功！"
  rm -f "$TEMP_SCRIPT"
else
  echo "❌ 错误：Xray安装失败！"
  rm -f "$TEMP_SCRIPT"
  exit 1
fi

# 确保xray命令可用
if ! command -v xray &>/dev/null; then
  echo "错误：Xray未正确安装！"
  exit 1
fi

# 生成UUID和REALITY密钥
echo "正在生成UUID和REALITY密钥..."
UUID=$(xray uuid)
if [ -z "$UUID" ]; then
  echo "❌ 错误：UUID生成失败！"
  exit 1
fi

KEY_INFO=$(xray x25519)
if [ -z "$KEY_INFO" ]; then
  echo "❌ 错误：REALITY密钥生成失败！"
  exit 1
fi

# 兼容新旧版本的输出格式
# 新版本格式: "PrivateKey: xxxxx" (无空格，首字母大写)
# 旧版本格式: "Private key: xxxxx" (有空格)
PRIVKEY=$(echo "$KEY_INFO" | grep -iE "PrivateKey|Private key" | sed -E 's/.*[:][[:space:]]*([A-Za-z0-9+/=_-]{43,44}).*/\1/' | head -n1 | tr -d ' ')

# 新版本不直接输出 PublicKey，需要从 PrivateKey 生成
# 使用 xray x25519 -i <privateKey> 来生成公钥
PUBKEY=""
if [ -n "$PRIVKEY" ]; then
  echo "正在从私钥生成公钥..."
  PUBKEY_INFO=$(xray x25519 -i "$PRIVKEY" 2>/dev/null)
  
  if [ -n "$PUBKEY_INFO" ]; then
    # 方式1: 查找 PublicKey 或 Public key
    PUBKEY=$(echo "$PUBKEY_INFO" | grep -iE "PublicKey|Public key" | sed -E 's/.*[:][[:space:]]*([A-Za-z0-9+/=_-]{43,44}).*/\1/' | head -n1 | tr -d ' ')
    
    # 方式2: 如果方式1失败，尝试提取第一个base64字符串（可能是PublicKey）
    if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "" ]; then
      # 排除 PrivateKey、Password、Hash32 等已知字段
      PUBKEY=$(echo "$PUBKEY_INFO" | grep -vE "PrivateKey|Password|Hash32" | grep -oE '[A-Za-z0-9+/=_-]{43,44}' | head -n1)
    fi
    
    # 方式3: 如果还是找不到，尝试提取所有base64字符串，取第一个（排除私钥）
    if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "" ] || [ "$PUBKEY" = "$PRIVKEY" ]; then
      ALL_KEYS=($(echo "$PUBKEY_INFO" | grep -oE '[A-Za-z0-9+/=_-]{43,44}'))
      for key in "${ALL_KEYS[@]}"; do
        if [ "$key" != "$PRIVKEY" ]; then
          PUBKEY="$key"
          break
        fi
      done
    fi
  fi
fi

# 如果从 -i 参数无法获取，尝试从原始输出中查找（旧版本可能有 Public key）
if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "" ]; then
  PUBKEY=$(echo "$KEY_INFO" | grep -iE "PublicKey|Public key" | sed -E 's/.*[:][[:space:]]*([A-Za-z0-9+/=_-]{43,44}).*/\1/' | head -n1 | tr -d ' ')
fi

# 验证密钥是否生成成功
if [ -z "$PRIVKEY" ] || [ -z "$PUBKEY" ] || [ "$PRIVKEY" = "" ] || [ "$PUBKEY" = "" ]; then
  echo "❌ 错误：REALITY密钥解析失败！"
  echo ""
  echo "Xray版本信息:"
  xray version 2>/dev/null || echo "无法获取版本信息"
  echo ""
  echo "xray x25519 原始输出:"
  echo "----------------------------------------"
  echo "$KEY_INFO"
  echo "----------------------------------------"
  if [ -n "$PUBKEY_INFO" ]; then
    echo ""
    echo "xray x25519 -i '$PRIVKEY' 输出:"
    echo "----------------------------------------"
    echo "$PUBKEY_INFO"
    echo "----------------------------------------"
  else
    echo ""
    echo "尝试运行: xray x25519 -i '$PRIVKEY'"
    echo "查看实际输出格式"
  fi
  echo ""
  echo "解析结果："
  echo "PRIVKEY: '$PRIVKEY' (长度: ${#PRIVKEY})"
  echo "PUBKEY: '$PUBKEY' (长度: ${#PUBKEY})"
  echo ""
  echo "提示：如果新版本 xray x25519 的输出格式已改变，"
  echo "请手动运行 'xray x25519' 和 'xray x25519 -i <privateKey>' 查看实际输出格式。"
  exit 1
fi

# 验证密钥格式（x25519密钥应该是base64编码，长度约43-44字符）
if [ ${#PRIVKEY} -lt 40 ] || [ ${#PRIVKEY} -gt 50 ]; then
  echo "❌ 错误：PRIVKEY 长度异常: ${#PRIVKEY} 字符"
  echo "PRIVKEY: '$PRIVKEY'"
  exit 1
fi
if [ ${#PUBKEY} -lt 40 ] || [ ${#PUBKEY} -gt 50 ]; then
  echo "❌ 错误：PUBKEY 长度异常: ${#PUBKEY} 字符"
  echo "PUBKEY: '$PUBKEY'"
  exit 1
fi

SHORTID=$(openssl rand -hex 8)
SNI="www.microsoft.com"

echo "✅ UUID和REALITY密钥生成成功"

# 生成随机外部端口（1025-65535，排除常见端口）
EXCLUDE_PORTS=(21 22 80 443 8080 8443 8000 8888 9000 4431)
# 生成外部端口
while :; do
  MMM_PORT=$((RANDOM%64511+1025))
  if [[ ! " ${EXCLUDE_PORTS[*]} " =~ " ${MMM_PORT} " ]]; then
    if ! ss -tuln | grep -q ":${MMM_PORT} "; then
      break
    fi
  fi
done

# 检查内部端口4431是否被占用
if ss -tuln | grep -q ":4431 "; then
  echo "⚠️  警告：端口4431已被占用，可能会影响vless服务！"
  read -p "是否继续？(y/n): " continue_4431
  if [ "$continue_4431" != "y" ] && [ "$continue_4431" != "Y" ]; then
    echo "安装已取消。"
    exit 1
  fi
fi

echo "✅ 已生成随机外部端口: $MMM_PORT (对应 $SNI)"

# 写入Xray配置文件（包含mmm-door和vless，带路由规则）
CONFIG_PATH="/usr/local/etc/xray/config.json"

# 创建日志目录并设置权限（配置文件使用 /var/log/xray/）
if [ ! -d "/var/log/xray" ]; then
  mkdir -p /var/log/xray
  chown root:root /var/log/xray
  chmod 755 /var/log/xray
fi

# 创建日志文件并设置权限（如果不存在）
if [ ! -f "/var/log/xray/access.log" ]; then
  touch /var/log/xray/access.log
  chown root:root /var/log/xray/access.log
  chmod 644 /var/log/xray/access.log
fi

if [ ! -f "/var/log/xray/error.log" ]; then
  touch /var/log/xray/error.log
  chown root:root /var/log/xray/error.log
  chmod 644 /var/log/xray/error.log
fi

# 检查并修改 systemd 服务文件为 root 启动
SERVICE_FILE="/etc/systemd/system/xray.service"
if [ -f "$SERVICE_FILE" ]; then
  # 修改服务文件中的 User 配置为 root（处理可能存在的注释和空格）
  if grep -qE "^[[:space:]]*User=" "$SERVICE_FILE"; then
    # 替换任何 User= 行（包括前面可能有空格的情况）
    sed -i 's/^[[:space:]]*User=.*/User=root/' "$SERVICE_FILE"
    # 如果 User 行被注释了，取消注释并设置为 root
    sed -i 's/^[[:space:]]*#.*User=.*/User=root/' "$SERVICE_FILE"
  else
    # 如果不存在 User 行，在 [Service] 部分添加
    sed -i '/\[Service\]/a User=root' "$SERVICE_FILE"
  fi
  systemctl daemon-reload
  # 验证修改是否成功
  if grep -q "^User=root" "$SERVICE_FILE"; then
    echo "✅ 已修改 systemd 服务文件为 root 用户启动"
  else
    echo "⚠️  警告：systemd 服务文件修改可能未成功，请手动检查 $SERVICE_FILE"
  fi
fi

cat > $CONFIG_PATH <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "tag": "mmm-in",
      "port": $MMM_PORT,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 4431,
        "network": "tcp"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["tls"],
        "routeOnly": true
      }
    },
    {
      "listen": "127.0.0.1",
      "port": 4431,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$SNI:443",
          "serverNames": ["$SNI"],
          "privateKey": "$PRIVKEY",
          "shortIds": ["$SHORTID"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "rules": [
      {
        "inboundTag": ["mmm-in"],
        "domain": ["$SNI"],
        "outboundTag": "direct"
      },
      {
        "inboundTag": ["mmm-in"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

# 设置配置文件权限
chmod 600 $CONFIG_PATH
chown root:root $CONFIG_PATH 2>/dev/null || chown xray:xray $CONFIG_PATH 2>/dev/null

# 验证配置文件中的 privateKey 是否正确写入
if ! grep -q "\"privateKey\": \"$PRIVKEY\"" "$CONFIG_PATH"; then
  echo "❌ 错误：配置文件中的 privateKey 验证失败！"
  echo "期望的 privateKey: $PRIVKEY"
  echo "配置文件内容："
  grep -A 5 "privateKey" "$CONFIG_PATH" || echo "未找到 privateKey"
  exit 1
fi

echo "✅ 配置文件验证通过"

# 确保日志文件权限正确（服务以 root 运行）
echo "正在设置日志文件权限..."
chown root:root /var/log/xray/ 2>/dev/null
chmod 755 /var/log/xray/ 2>/dev/null
chown root:root /var/log/xray/*.log 2>/dev/null
chmod 644 /var/log/xray/*.log 2>/dev/null

# 重启Xray服务
echo "正在重启Xray服务..."
systemctl restart xray
sleep 2
if systemctl is-active --quiet xray; then
  systemctl enable xray
  echo "✅ Xray服务启动成功！"
else
  echo "❌ 错误：Xray服务启动失败，请检查配置！"
  echo "查看错误日志："
  journalctl -u xray -n 20 --no-pager
  exit 1
fi

# 生成节点链接
VLESS_LINK="vless://$UUID@$IP:$MMM_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBKEY&sid=$SHORTID&type=tcp#$IP-$MMM_PORT"

# 输出配置信息
echo
echo "✅ VLESS+REALITY+MMM-Door 节点配置完成！"
echo "以下信息可用于Passwall客户端（也支持Shadowrocket等）："
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  节点链接（$SNI）："
echo "$VLESS_LINK"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
# 保存节点链接到文件
echo "$VLESS_LINK" > vless_link.txt
echo "(节点链接已写入 vless_link.txt)"
echo
echo "配置详情："
echo "  公网IP: $IP"
echo "  UUID: $UUID"
echo "  公钥: $PUBKEY"
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  入口："
    echo "    外部端口: $MMM_PORT (mmm-door)"
echo "    内部端口: 4431 (vless，监听127.0.0.1)"
echo "    目标域名: $SNI"
echo "    ShortID: $SHORTID"
echo "    加密: none"
echo "    流控: xtls-rprx-vision"
echo "    安全: reality"
echo "    指纹: chrome"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "配置详情（Passwall手动配置用）："
echo "  地址: $IP"
  echo "  端口: $MMM_PORT"
echo "  UUID: $UUID"
echo "  加密: none"
echo "  流控: xtls-rprx-vision"
echo "  安全: reality"
echo "  SNI: $SNI"
echo "  指纹: chrome"
echo "  公钥: $PUBKEY"
echo "  ShortID: $SHORTID"
echo
echo "路由规则："
echo "  - 访问 $SNI 的流量将直接放行，其他流量将被阻止"
echo
echo "日志级别: debug"
echo "日志文件: /var/log/xray/access.log 和 error.log"
echo
echo "⚠️  注意：此配置使用mmm-door端口接收流量，"
echo "   转发到内部vless服务。请确保防火墙允许端口 $MMM_PORT。"
echo
echo "保存以上信息到Passwall，建议定期更换UUID和ShortID以提升安全性！"

