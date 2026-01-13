#!/bin/bash
# Sing-box 完全双栈 + HTTP/DNS 交互验证终极版
# Author: Chis | Enhanced by ChatGPT

set -e

echo "=================== Sing-box 部署前环境检查 ==================="

# ---------- Root ----------
[[ $EUID -ne 0 ]] && { echo "[✖] 请使用 root 运行"; exit 1; }
echo "[✔] Root 权限 OK"

# ---------- 公网 IP ----------
SERVER_IPV4=$(curl -4 -s ipv4.icanhazip.com || true)
SERVER_IPV6=$(curl -6 -s ipv6.icanhazip.com || true)

[[ -n "$SERVER_IPV4" ]] && echo "[✔] IPv4: $SERVER_IPV4" || echo "[!] 未检测到 IPv4"
[[ -n "$SERVER_IPV6" ]] && echo "[✔] IPv6: $SERVER_IPV6" || echo "[!] 未检测到 IPv6"

# ---------- 依赖 ----------
REQ=(curl ss openssl qrencode dig systemctl socat ufw)
MISS=()
for i in "${REQ[@]}"; do command -v $i &>/dev/null || MISS+=("$i"); done
if [[ ${#MISS[@]} -gt 0 ]]; then
  echo "[!] 安装依赖: ${MISS[*]}"
  apt update -y
  apt install -y dnsutils "${MISS[@]}"
fi

# ---------- 端口 ----------
for p in 80 443; do
  ss -tuln | grep -q ":$p " && echo "[✖] 端口 $p 被占用" || echo "[✔] 端口 $p 空闲"
done

read -rp "环境检查完成，是否继续？(y/N): " GO
[[ "$GO" =~ ^[Yy]$ ]] || exit 0

# ---------- 模式 ----------
while true; do
  echo -e "\n1) 域名 + TLS\n2) 公网 IP + 自签证书"
  read -rp "选择模式 (1/2): " MODE
  [[ "$MODE" =~ ^[12]$ ]] && break
done

# ---------- 安装 sing-box ----------
command -v sing-box &>/dev/null || bash <(curl -fsSL https://sing-box.app/deb-install.sh)

CERT_DIR="/etc/ssl/sing-box"
mkdir -p "$CERT_DIR"

# ===================================================================
# 域名模式
# ===================================================================
if [[ "$MODE" == "1" ]]; then
  while true; do
    read -rp "请输入域名: " DOMAIN
    [[ -z "$DOMAIN" ]] && continue

    A=$(dig +short A "$DOMAIN" | tail -n1)
    AAAA=$(dig +short AAAA "$DOMAIN" | tail -n1)

    echo "[解析] A=$A AAAA=$AAAA"

    MATCH=0
    [[ -n "$A" && "$A" == "$SERVER_IPV4" ]] && MATCH=1
    [[ -n "$AAAA" && "$AAAA" == "$SERVER_IPV6" ]] && MATCH=1

    [[ "$MATCH" != "1" ]] && { echo "[✖] 域名未指向本机"; continue; }

    # 判断 Cloudflare
    IS_CF=0
    dig +short NS "$DOMAIN" | grep -qi cloudflare && IS_CF=1

    # 推荐验证方式
    RECOMMEND="HTTP"
    [[ -z "$SERVER_IPV4" || $(ss -tuln | grep -c ":80 ") -gt 0 ]] && RECOMMEND="DNS"
    echo "[建议] 推荐使用 $RECOMMEND 验证"

    while true; do
      echo -e "\n1) HTTP 验证\n2) DNS 验证 (Cloudflare)"
      read -rp "选择验证方式: " VAL

      # ---------------- HTTP ----------------
      if [[ "$VAL" == "1" ]]; then
        ss -tuln | grep -q ":80 " && { echo "[✖] 80 被占用"; continue; }
        ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 && break
        echo "[✖] HTTP 验证失败"

      # ---------------- DNS ----------------
      elif [[ "$VAL" == "2" ]]; then
        [[ "$IS_CF" != "1" ]] && { echo "[✖] 非 Cloudflare 域名"; continue; }

        if [[ -f /root/.cf_token ]]; then
          export CF_Token=$(cat /root/.cf_token)
        else
          while true; do
            read -rp "输入 Cloudflare API Token: " T
            export CF_Token="$T"
            curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
              -H "Authorization: Bearer $CF_Token" | grep -q '"active"' && break
            echo "[✖] Token 无效"
          done
          read -rp "保存 Token？(y/N): " S
          [[ "$S" =~ ^[Yy]$ ]] && echo "$CF_Token" > /root/.cf_token && chmod 600 /root/.cf_token
        fi

        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 && break
        echo "[✖] DNS 验证失败"

      fi
    done
    break
  done

  ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
    --key-file "$CERT_DIR/privkey.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "systemctl restart sing-box"

else
# ===================================================================
# 自签模式
# ===================================================================
  DOMAIN="www.epple.com"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,IP:$SERVER_IPV4,IP:$SERVER_IPV6"
fi

# ---------- 随机端口 ----------
rand_port(){ while :; do p=$((RANDOM%40000+20000)); ss -tuln | grep -q ":$p " || break; done; echo $p; }

read -rp "VLESS 端口 (0随机): " VLESS
[[ -z "$VLESS" || "$VLESS" == "0" ]] && VLESS=$(rand_port)

read -rp "Hysteria2 端口 (0随机): " HY2
[[ -z "$HY2" || "$HY2" == "0" ]] && HY2=$(rand_port)

UUID=$(cat /proc/sys/kernel/random/uuid)
HY2_PASS=$(openssl rand -hex 8)

# ---------- sing-box 配置 ----------
cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "listen": "0.0.0.0",
      "listen_port": $VLESS,
      "users": [{ "uuid": "$UUID" }],
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
      "listen_port": $HY2,
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

systemctl enable sing-box
systemctl restart sing-box

# ---------- 节点 ----------
HOST="$DOMAIN"
VLESS_URI="vless://$UUID@$HOST:$VLESS?encryption=none&security=tls&sni=$DOMAIN#VLESS"
HY2_URI="hysteria2://$HY2_PASS@$HOST:$HY2?sni=$DOMAIN#HY2"

echo -e "\n===== VLESS =====\n$VLESS_URI"
qrencode -t ansiutf8 <<< "$VLESS_URI"

echo -e "\n===== Hysteria2 =====\n$HY2_URI"
qrencode -t ansiutf8 <<< "$HY2_URI"

echo -e "\n部署完成 ✅"
