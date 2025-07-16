#!/bin/bash

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
  echo "错误：请以root用户运行此脚本！"
  exit 1
fi

# 检查Xray服务是否已存在
if systemctl is-active --quiet xray || command -v xray &>/dev/null; then
  echo "警告：Xray服务或二进制文件已存在！"
  read -p "是否继续安装并覆盖现有配置？(y/n): " confirm
  if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "安装已取消，保留现有Xray配置。"
    exit 0
  fi
fi

# 安装Xray
echo "正在安装Xray..."
if ! bash <(curl -L https://gh-proxy.com/https://raw.githubusercontent.com/Poiig/Xray-install/refs/heads/main/install-release.sh); then
  echo "错误：Xray安装失败，请检查网络或脚本源！"
  exit 1
fi

# 确保xray命令可用
if ! command -v xray &>/dev/null; then
  echo "错误：Xray未正确安装！"
  exit 1
fi

# 生成UUID和REALITY密钥
UUID=$(xray uuid)
KEY_INFO=$(xray x25519)
PRIVKEY=$(echo "$KEY_INFO" | grep "Private key" | awk '{print $3}')
PUBKEY=$(echo "$KEY_INFO" | grep "Public key" | awk '{print $3}')
SHORTID=$(openssl rand -hex 4)
SNI="www.microsoft.com" # 使用国际网站，降低GFW检测风险

# 生成随机端口（1025-65535，排除常见端口）
EXCLUDE_PORTS=(21 22 80 443 8080 8443 8000 8888 9000)
while :; do
  PORT=$((RANDOM%64511+1025))
  if [[ ! " ${EXCLUDE_PORTS[*]} " =~ " ${PORT} " ]]; then
    # 检查端口是否被占用
    if ! ss -tuln | grep -q ":$PORT "; then
      break
    fi
  fi
done

# 写入Xray配置文件（无分流规则，适配Passwall）
CONFIG_PATH="/usr/local/etc/xray/config.json"
cat > $CONFIG_PATH <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/usr/local/var/log/xray/access.log",
    "error": "/usr/local/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision",
            "email": "passwall@example.com"
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

# 重启Xray服务
systemctl restart xray
if systemctl is-active --quiet xray; then
  systemctl enable xray
else
  echo "错误：Xray服务启动失败，请检查配置！"
  exit 1
fi

# 获取公网IP
IP=$(curl -s ifconfig.me)
if [ -z "$IP" ]; then
  echo "警告：无法获取公网IP，请手动确认服务器IP！"
  IP="你的服务器IP"
fi

# 输出节点信息（适配Passwall）
echo
echo "✅ VLESS+REALITY 节点配置完成！"
echo "以下信息可用于Passwall客户端（也支持Shadowrocket等）："
echo
echo "节点链接："
echo "vless://$UUID@$IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBKEY&sid=$SHORTID&type=tcp#Reality回国节点"
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