#!/bin/bash

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
        # 提取参数
        UUID=$(grep -oP '"id"\s*:\s*"\K[^"]+' "$CONFIG_PATH" | head -n1)
        PORT=$(grep -oP '"port"\s*:\s*\K[0-9]+' "$CONFIG_PATH" | head -n1)
        PRIVKEY=$(grep -oP '"privateKey"\s*:\s*"\K[^"]+' "$CONFIG_PATH" | head -n1)
        SHORTID=$(grep -oP '"shortIds"\s*:\s*\[\s*"\K[^"]+' "$CONFIG_PATH" | head -n1)
        SNI=$(grep -oP '"serverNames"\s*:\s*\[\s*"\K[^"]+' "$CONFIG_PATH" | head -n1)
        [ -z "$SNI" ] && SNI="www.microsoft.com"
        # 计算公钥
        if command -v xray &>/dev/null && [ -n "$PRIVKEY" ]; then
          PUBKEY=$(xray x25519 -i "$PRIVKEY" | grep "Public key" | awk '{print $3}')
        else
          PUBKEY=""
        fi
        VLESS_LINK="vless://$UUID@$IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBKEY&sid=$SHORTID&type=tcp#cn-$IP"
        echo
        echo "节点链接："
        echo "$VLESS_LINK"
        echo "$VLESS_LINK" > vless_link.txt
        echo "(节点链接已写入 vless_link.txt)"
        echo
        echo "配置详情（Passwall手动配置用）："
        echo "  地址: $IP"
        echo "  端口: $PORT"
        echo "  UUID: $UUID"
        echo "  加密: none"
        echo "  流控: xtls-rprx-vision"
        echo "  安全: reality"
        echo "  SNI: $SNI"
        echo "  指纹: chrome"
        echo "  公钥: $PUBKEY"
        echo "  ShortID: $SHORTID"
        echo
        echo "保存以上信息到Passwall，建议定期更换UUID和ShortID以提升安全性！"
      else
        echo "未找到配置文件 $CONFIG_PATH，无法输出节点链接。"
      fi
    else
      echo "Xray服务未启动，将重新生成配置并重启Xray。"
      # 重新生成配置和重启流程（跳转到生成配置部分）
      # 由于脚本结构，直接继续后续生成配置部分即可
    fi
    exit 0
  fi
fi

# 安装Xray
echo "正在安装Xray..."
if ! bash -c "$(curl -L https://ghfast.top/https://raw.githubusercontent.com/Poiig/Xray-install/refs/heads/1.0/install-release.sh)" @ install; then
  echo "错误：Xray安装失败，请检查网络或脚本源！"
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
SNI="www.microsoft.com" # 使用国际网站，降低GFW检测风险

# 解析参数，支持指定端口
PORT_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--port)
      PORT_ARG="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# 生成随机端口（1025-65535，排除常见端口）或使用用户指定端口
EXCLUDE_PORTS=(21 22 80 443 8080 8443 8000 8888 9000)
if [ -n "$PORT_ARG" ]; then
  # 检查端口是否为数字且在合法范围
  if ! [[ "$PORT_ARG" =~ ^[0-9]+$ ]] || [ "$PORT_ARG" -lt 1025 ] || [ "$PORT_ARG" -gt 65535 ]; then
    echo "错误：指定端口无效，必须为1025-65535之间的数字！"
    exit 1
  fi
  # 检查端口是否在排除列表
  if [[ " ${EXCLUDE_PORTS[*]} " =~ " ${PORT_ARG} " ]]; then
    echo "错误：指定端口为常见端口，出于安全考虑请更换其他端口！"
    exit 1
  fi
  # 检查端口是否被占用
  if ss -tuln | grep -q ":$PORT_ARG "; then
    echo "错误：指定端口已被占用，请更换其他端口！"
    exit 1
  fi
  PORT=$PORT_ARG
else
  while :; do
    PORT=$((RANDOM%64511+1025))
    if [[ ! " ${EXCLUDE_PORTS[*]} " =~ " ${PORT} " ]]; then
      # 检查端口是否被占用
      if ! ss -tuln | grep -q ":$PORT "; then
        break
      fi
    fi
  done
fi

# 写入Xray配置文件（无分流规则，适配Passwall）
CONFIG_PATH="/usr/local/etc/xray/config.json"
mkdir -p /usr/local/var/log/xray

# 检查并修改 systemd 服务文件为 root 启动
SERVICE_FILE="/etc/systemd/system/xray.service"
if [ -f "$SERVICE_FILE" ]; then
  sed -i 's/^User=nobody/User=root/' "$SERVICE_FILE"
  systemctl daemon-reload
fi

cat > $CONFIG_PATH <<EOF
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": $PORT,
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
          "show": false,
          "dest": "$SNI:443",
          "xver": 0,
          "serverNames": ["$SNI"],
          "privateKey": "$PRIVKEY",
          "shortIds": ["$SHORTID"],
          "fingerprint": "chrome"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

# 设置配置文件权限
chmod 600 $CONFIG_PATH
chown xray:xray $CONFIG_PATH

# 确保日志目录存在
mkdir -p /var/log/xray
chown xray:xray /var/log/xray 2>/dev/null || chown root:root /var/log/xray 2>/dev/null

# 重启Xray服务
echo "正在启动Xray服务..."
systemctl restart xray
sleep 2

# 如果启动失败，清理日志并重试
if ! systemctl is-active --quiet xray; then
  echo "⚠️  Xray服务启动失败，正在清理日志并重试..."
  rm -rf /var/log/xray/*
  systemctl restart xray
  sleep 2
  
  # 再次检查状态
  if systemctl is-active --quiet xray; then
    echo "✅ 清理日志后Xray服务启动成功！"
    systemctl enable xray
  else
    echo "❌ 错误：Xray服务启动失败，请检查配置！"
    echo "查看服务状态："
    systemctl status xray --no-pager -l
    exit 1
  fi
else
  systemctl enable xray
  echo "✅ Xray服务启动成功！"
fi
# 输出节点信息
echo
echo "✅ VLESS+REALITY 节点配置完成！"
echo "以下信息可用于Passwall客户端（也支持Shadowrocket等）："
echo
echo "节点链接："
VLESS_LINK="vless://$UUID@$IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBKEY&sid=$SHORTID&type=tcp#cn-$IP"
echo "$VLESS_LINK"
echo "$VLESS_LINK" > vless_link.txt
echo "(节点链接已写入 vless_link.txt)"
echo
echo "配置详情（Passwall手动配置用）："
echo "  地址: $IP"
echo "  端口: $PORT"
echo "  UUID: $UUID"
echo "  加密: none"
echo "  流控: xtls-rprx-vision"
echo "  安全: reality"
echo "  SNI: $SNI"
echo "  指纹: chrome"
echo "  公钥: $PUBKEY"
echo "  ShortID: $SHORTID"
echo
echo "保存以上信息到Passwall，建议定期更换UUID和ShortID以提升安全性！"
echo

# 配置日志归档
echo "正在配置日志归档..."
LOGROTATE_FILE="/etc/logrotate.d/xray"
cat > "$LOGROTATE_FILE" <<'LOGROTATE_EOF'
/var/log/xray/*.log {
    daily
    rotate 7
    dateext
    dateformat -%Y%m%d
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGROTATE_EOF

chmod 644 "$LOGROTATE_FILE"
echo "✅ 日志归档配置完成！日志将每天轮转，保留7天。"

# 询问是否开启加速
echo
read -p "是否要开启网络加速（BBR/BBR Plus）？(y/n): " enable_accel
if [ "$enable_accel" = "y" ] || [ "$enable_accel" = "Y" ]; then
  echo "正在下载加速脚本..."
  ACCEL_SCRIPT="./tcp.sh"
  if wget -N --no-check-certificate "https://ghfast.top/https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh" -O "$ACCEL_SCRIPT" 2>/dev/null; then
    chmod +x "$ACCEL_SCRIPT"
    echo "✅ 加速脚本下载成功！"
    echo "⚠️  注意：执行加速脚本可能需要重启服务器，请确认后再继续。"
    echo "正在执行加速脚本，请根据提示输入选项..."
    "$ACCEL_SCRIPT"
  else
    echo "⚠️  加速脚本下载失败，您可以稍后手动下载并执行："
    echo "  wget -N --no-check-certificate \"https://ghfast.top/https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh\""
    echo "  chmod +x tcp.sh"
    echo "  ./tcp.sh"
  fi
else
  echo "已跳过网络加速配置。"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 所有配置已完成！"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"