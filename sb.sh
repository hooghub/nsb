#!/bin/bash
# Sing-box 一键部署脚本 (最终双栈版 - 修复 set -e + IPv6 兼容)
# 支持域名模式 / 自签固定域名 www.epple.com
# Author: Chis (优化 by ChatGPT)

set -e

echo "=================== Sing-box 部署前环境检查 ==================="

# --------- 检查 root ---------
if [[ $EUID -ne 0 ]]; then
  echo "[✖] 请用 root 权限运行"
  exit 1
else
  echo "[✔] Root 权限 OK"
fi

# --------- 检测公网 IP（修复：IPv6 不存在也不退出）---------
SERVER_IPV4="$(curl -4 -s --max-time 3 ipv4.icanhazip.com 2>/dev/null || curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || true)"

SERVER_IPV6=""
if curl -6 -s --max-time 3 ipv6.icanhazip.com >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
elif curl -6 -s --max-time 3 ifconfig.me >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
fi
rm -f /tmp/ipv6 2>/dev/null || true

[[ -n "$SERVER_IPV4" ]] && echo "[✔] 检测到公网 IPv4: $SERVER_IPV4" || echo "[✖] 未检测到公网 IPv4"
[[ -n "$SERVER_IPV6" ]] && echo "[✔] 检测到公网 IPv6: $SERVER_IPV6" || echo "[!] 未检测到公网 IPv6（可忽略）"

# --------- 自动安装依赖 ---------
REQUIRED_CMDS=(curl ss openssl qrencode dig systemctl bash socat cron ufw)
MISSING_CMDS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
done

if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then
  echo "[!] 检测到缺失命令: ${MISSING_CMDS[*]}"
  echo "[!] 自动安装依赖中..."
  apt update -y
  INSTALL_PACKAGES=()
  for cmd in "${MISSING_CMDS[@]}"; do
    case "$cmd" in
      dig) INSTALL_PACKAGES+=("dnsutils") ;;
      qrencode|socat|ufw) INSTALL_PACKAGES+=("$cmd") ;;
      ss) INSTALL_PACKAGES+=("iproute2") ;;
      cron) INSTALL_PACKAGES+=("cron") ;;
      *) INSTALL_PACKAGES+=("$cmd") ;;
    esac
  done
  apt install -y "${INSTALL_PACKAGES[@]}"
fi

# --------- 检查常用端口 ---------
for port in 80 443; do
  if ss -tuln | grep -q ":$port"; then
    echo "[✖] 端口 $port 已被占用"
  else
    echo "[✔] 端口 $port 空闲"
  fi
done

read -rp "环境检查完成 ✅  确认继续执行部署吗？(y/N): " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || exit 0

# --------- 模式选择 ---------
while true; do
  echo -e "\n请选择部署模式：\n1) 使用域名 + Let's Encrypt 证书\n2) 使用公网 IP + 自签固定域名 www.epple.com"
  read -rp "请输入选项 (1 或 2): " MODE
  [[ "$MODE" =~ ^[12]$ ]] && break
  echo "[!] 输入错误，请重新输入 1 或 2"
done

# --------- 安装 sing-box ---------
if ! command -v sing-box &>/dev/null; then
  echo ">>> 安装 sing-box ..."
  bash <(curl -fsSL https://sing-box.app/deb-install.sh)
fi

CERT_DIR="/etc/ssl/sing-box"
mkdir -p "$CERT_DIR"

# --------- 随机端口函数 ---------
get_random_port() {
  while :; do
    PORT=$((RANDOM%50000+10000))
    ss -tuln | grep -q ":$PORT" || break
  done
  echo "$PORT"
}

# --------- 域名模式 ---------
if [[ "$MODE" == "1" ]]; then
  while true; do
    read -rp "请输入你的域名 (例如: example.com): " DOMAIN
    [[ -z "$DOMAIN" ]] && { echo "[!] 域名不能为空"; continue; }

    DOMAIN_IPV4="$(dig +short A "$DOMAIN" | tail -n1 || true)"
    DOMAIN_IPV6="$(dig +short AAAA "$DOMAIN" | tail -n1 || true)"

    echo "[✔] 域名解析检查完成 (IPv4: ${DOMAIN_IPV4:-无}, IPv6: ${DOMAIN_IPV6:-无})"
    break
  done

  # 安装 acme.sh
  if ! command -v acme.sh &>/dev/null; then
    echo ">>> 安装 acme.sh ..."
    curl https://get.acme.sh | sh
    source ~/.bashrc || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  # --------- 检查是否已有证书 ---------
  LE_CERT_PATH="$HOME/.acme.sh/${DOMAIN}_ecc/fullchain.cer"
  LE_KEY_PATH="$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key"

  if [[ -f "$LE_CERT_PATH" && -f "$LE_KEY_PATH" ]]; then
    echo "[✔] 已检测到现有 Let's Encrypt 证书，直接导入"
    cp "$LE_CERT_PATH" "$CERT_DIR/fullchain.pem"
    cp "$LE_KEY_PATH" "$CERT_DIR/privkey.pem"
    chmod 644 "$CERT_DIR"/*.pem
  else
    echo ">>> 申请新的 Let's Encrypt TLS 证书"

    # 自动选择可用 IP 协议
    if [[ -n "$SERVER_IPV4" ]]; then
      USE_LISTEN="--listen-v4"
    elif [[ -n "$SERVER_IPV6" ]]; then
      USE_LISTEN="--listen-v6"
    else
      echo "[✖] 未检测到可用 IPv4 或 IPv6，无法申请证书"
      exit 1
    fi

    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone $USE_LISTEN --keylength ec-256 --force
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --ecc \
      --key-file "$CERT_DIR/privkey.pem" \
      --fullchain-file "$CERT_DIR/fullchain.pem" \
      --force
    chmod 644 "$CERT_DIR"/*.pem
    echo "[✔] TLS 证书申请完成"
  fi

else
  # --------- 自签固定域名模式（修复：SAN 不包含空 IPv6）---------
  DOMAIN="www.epple.com"
  echo "[!] 自签模式，将生成固定域名 $DOMAIN 的自签证书 (URI 使用 VPS 公网 IP)"

  if [[ -z "$SERVER_IPV4" ]]; then
    echo "[✖] 未检测到公网 IPv4，自签模式需要 IPv4"
    exit 1
  fi

  SAN="DNS:$DOMAIN,IP:$SERVER_IPV4"
  [[ -n "$SERVER_IPV6" ]] && SAN="$SAN,IP:$SERVER_IPV6"

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName = $SAN"

  chmod 644 "$CERT_DIR"/*.pem
  echo "[✔] 自签证书生成完成"
fi

# --------- 输入端口 ---------
read -rp "请输入 VLESS TCP 端口 (默认 443, 输入0随机): " VLESS_PORT
[[ -z "$VLESS_PORT" || "$VLESS_PORT" == "0" ]] && VLESS_PORT=$(get_random_port)

read -rp "请输入 Hysteria2 UDP 端口 (默认 8443, 输入0随机): " HY2_PORT
[[ -z "$HY2_PORT" || "$HY2_PORT" == "0" ]] && HY2_PORT=$(get_random_port)

# IPv6 端口（即使机器没公网 IPv6 也无妨：监听 :: 只是本地能力）
VLESS6_PORT=$(get_random_port)
HY2_6_PORT=$(get_random_port)

# 自动生成 UUID / Hysteria2 密码
UUID=$(cat /proc/sys/kernel/random/uuid)
HY2_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)

# --------- 生成 sing-box 配置 ---------
mkdir -p /etc/sing-box

cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "listen": "0.0.0.0",
      "listen_port": $VLESS_PORT,
      "users": [{ "uuid": "$UUID"}],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": $VLESS6_PORT,
      "users": [{ "uuid": "$UUID"}],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "hysteria2",
      "listen": "0.0.0.0",
      "listen_port": $HY2_PORT,
      "users": [{ "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": $HY2_6_PORT,
      "users": [{ "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "[✔] sing-box 配置生成完成：IPv4 + IPv6 双栈"

# --------- 防火墙端口开放 ---------
if command -v ufw &>/dev/null; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow "$VLESS_PORT"/tcp || true
  ufw allow "$VLESS6_PORT"/tcp || true
  ufw allow "$HY2_PORT"/udp || true
  ufw allow "$HY2_6_PORT"/udp || true
  ufw reload || true
fi

# --------- 启动 sing-box ---------
systemctl enable sing-box
systemctl restart sing-box
sleep 3

# --------- 检查端口监听并显示信息 ---------
ss -tulnp | grep -q ":$VLESS_PORT" && echo "[✔] VLESS TCP IPv4（$VLESS_PORT） 已监听" || echo "[✖] VLESS TCP IPv4（$VLESS_PORT） 未监听"
ss -tulnp | grep -q ":$VLESS6_PORT" && echo "[✔] VLESS TCP IPv6（$VLESS6_PORT） 已监听" || echo "[✖] VLESS TCP IPv6（$VLESS6_PORT） 未监听"
ss -ulnp  | grep -q ":$HY2_PORT"   && echo "[✔] Hysteria2 UDP IPv4（$HY2_PORT） 已监听" || echo "[✖] Hysteria2 UDP IPv4（$HY2_PORT） 未监听"
ss -ulnp  | grep -q ":$HY2_6_PORT" && echo "[✔] Hysteria2 UDP IPv6（$HY2_6_PORT） 已监听" || echo "[✖] Hysteria2 UDP IPv6（$HY2_6_PORT） 未监听"

# --------- 生成节点 URI 和二维码 ---------
if [[ "$MODE" == "1" ]]; then
  NODE_HOST="$DOMAIN"
  INSECURE="0"
else
  NODE_HOST="$SERVER_IPV4"
  INSECURE="1"
fi

VLESS_URI="vless://$UUID@$NODE_HOST:$VLESS_PORT?encryption=none&security=tls&sni=$DOMAIN&type=tcp#VLESS-$NODE_HOST"
HY2_URI="hysteria2://$HY2_PASS@$NODE_HOST:$HY2_PORT?insecure=$INSECURE&sni=$DOMAIN#HY2-$NODE_HOST"

echo -e "\n=================== VLESS 节点 ==================="
echo "$VLESS_URI"
command -v qrencode &>/dev/null && echo "$VLESS_URI" | qrencode -t ansiutf8 || true

echo -e "\n=================== Hysteria2 节点 ==================="
echo "$HY2_URI"
command -v qrencode &>/dev/null && echo "$HY2_URI" | qrencode -t ansiutf8 || true

# --------- 保存节点到文件（注意：这里不是 JSON，只是文本清单）---------
SUB_FILE="/root/singbox_nodes.txt"
cat > "$SUB_FILE" <<EOF
$VLESS_URI
$HY2_URI
EOF

echo -e "\n=================== 节点文件内容 ==================="
cat "$SUB_FILE"
echo -e "\n节点文件已保存到：$SUB_FILE"

echo -e "\n=================== 部署完成 ==================="
