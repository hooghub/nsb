#!/bin/bash
set -e

echo "=================== Sing-box 双栈部署（最终增强版） ==================="

# ---------- Root ----------
[[ $EUID -ne 0 ]] && echo "[✖] 请使用 root 运行" && exit 1
echo "[✔] Root 权限 OK"

# ---------- 公网 IP ----------
SERVER_IPV4=$(curl -4 -s ipv4.icanhazip.com || true)
SERVER_IPV6=$(curl -6 -s ipv6.icanhazip.com || true)

[[ -n "$SERVER_IPV4" ]] && echo "[✔] 公网 IPv4: $SERVER_IPV4" || echo "[!] 未检测到 IPv4"
[[ -n "$SERVER_IPV6" ]] && echo "[✔] 公网 IPv6: $SERVER_IPV6" || echo "[!] 未检测到 IPv6"

# ---------- 依赖 ----------
REQ=(curl ss openssl qrencode dig systemctl socat ufw)
MISS=()
for c in "${REQ[@]}"; do command -v "$c" >/dev/null 2>&1 || MISS+=("$c"); done
if [[ ${#MISS[@]} -gt 0 ]]; then
  echo "[!] 安装依赖: ${MISS[*]}"
  apt update -y
  apt install -y "${MISS[@]/dig/dnsutils}"
fi

# ---------- 端口 ----------
for p in 80 443; do
  ss -tuln | grep -q ":$p" && echo "[!] 端口 $p 被占用" || echo "[✔] 端口 $p 空闲"
done

read -rp "继续部署？(y/N): " GO
[[ "$GO" =~ ^[Yy]$ ]] || exit 0

# ---------- 安装 sing-box ----------
command -v sing-box >/dev/null 2>&1 || bash <(curl -fsSL https://sing-box.app/deb-install.sh)

CERT_DIR="/etc/ssl/sing-box"
mkdir -p "$CERT_DIR"

# ---------- 域名 ----------
while true; do
  read -rp "请输入域名: " DOMAIN
  [[ -z "$DOMAIN" ]] && echo "域名不能为空" && continue

  A=$(dig +short A "$DOMAIN" | tail -n1)
  AAAA=$(dig +short AAAA "$DOMAIN" | tail -n1)

  [[ -z "$A" && -z "$AAAA" ]] && echo "域名未解析" && continue

  MATCH=0
  [[ -n "$A" && "$A" == "$SERVER_IPV4" ]] && MATCH=1
  [[ -n "$AAAA" && "$AAAA" == "$SERVER_IPV6" ]] && MATCH=1

  echo "[解析] A=$A AAAA=$AAAA"
  [[ "$MATCH" == "1" ]] && break

  echo "[✖] 域名未指向本机 IPv4 或 IPv6，重试"
done

# ---------- Cloudflare 判断 ----------
IS_CF=0
dig +short NS "$DOMAIN" | grep -qi cloudflare && IS_CF=1

# ---------- 推荐验证 ----------
RECOMMEND="HTTP"
ss -tuln | grep -q ":80" && RECOMMEND="DNS"
[[ -z "$SERVER_IPV4" && -n "$SERVER_IPV6" ]] && RECOMMEND="DNS"
echo "[建议] 推荐验证方式: $RECOMMEND"

# ---------- 安装 acme.sh ----------
command -v acme.sh >/dev/null 2>&1 || curl https://get.acme.sh | sh
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

# ---------- 证书申请 ----------
while true; do
  echo "1) HTTP 验证"
  echo "2) DNS 验证"
  read -rp "选择 (1/2): " VM

  # ----- HTTP -----
  if [[ "$VM" == "1" ]]; then
    ss -tuln | grep -q ":80" && echo "80 被占用，不能 HTTP" && continue
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 && break
    echo "HTTP 验证失败"

  # ----- DNS -----
  elif [[ "$VM" == "2" ]]; then
    [[ "$IS_CF" != "1" ]] && echo "非 Cloudflare 域名，暂不支持" && continue

    if [[ -f /root/.cf_token ]]; then
      export CF_Token=$(cat /root/.cf_token)
    else
      while true; do
        read -rp "请输入 Cloudflare API Token: " T
        export CF_Token="$T"
        curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
          -H "Authorization: Bearer $CF_Token" | grep -q '"status":"active"' && break
        echo "Token 无效"
      done
      read -rp "保存 Token? (y/N): " S
      [[ "$S" =~ ^[Yy]$ ]] && echo "$CF_Token" > /root/.cf_token && chmod 600 /root/.cf_token
    fi

    /root/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 && break
    echo "DNS 验证失败"

  else
    echo "输入错误"
  fi
done

# ---------- 安装证书 ----------
/root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
  --key-file "$CERT_DIR/privkey.pem" \
  --fullchain-file "$CERT_DIR/fullchain.pem" \
  --reloadcmd "systemctl restart sing-box"

# ---------- 端口 ----------
rand_port(){ while :; do p=$((RANDOM%50000+10000)); ss -tuln | grep -q ":$p" || break; done; echo $p; }
read -rp "VLESS 端口(0随机): " VLESS
[[ -z "$VLESS" || "$VLESS" == "0" ]] && VLESS=$(rand_port)
read -rp "HY2 端口(0随机): " HY2
[[ -z "$HY2" || "$HY2" == "0" ]] && HY2=$(rand_port)

UUID=$(cat /proc/sys/kernel/random/uuid)
PASS=$(openssl rand -base64 16 | tr -dc a-zA-Z0-9)

# ---------- 配置 ----------
cat > /etc/sing-box/config.json <<EOF
{
 "inbounds":[
  {"type":"vless","listen":"::","listen_port":$VLESS,"users":[{"uuid":"$UUID"}],
   "tls":{"enabled":true,"server_name":"$DOMAIN","certificate_path":"$CERT_DIR/fullchain.pem","key_path":"$CERT_DIR/privkey.pem"}},
  {"type":"hysteria2","listen":"::","listen_port":$HY2,"users":[{"password":"$PASS"}],
   "tls":{"enabled":true,"server_name":"$DOMAIN","certificate_path":"$CERT_DIR/fullchain.pem","key_path":"$CERT_DIR/privkey.pem"}}
 ],
 "outbounds":[{"type":"direct"}]
}
EOF

systemctl enable sing-box
systemctl restart sing-box

HOST="$DOMAIN"
VLESS_URI="vless://$UUID@$HOST:$VLESS?security=tls&sni=$DOMAIN&type=tcp#VLESS-$HOST"
HY2_URI="hysteria2://$PASS@$HOST:$HY2?sni=$DOMAIN#HY2-$HOST"

echo "==== VLESS ===="
echo "$VLESS_URI"
qrencode -t ansiutf8 <<< "$VLESS_URI"

echo "==== HY2 ===="
echo "$HY2_URI"
qrencode -t ansiutf8 <<< "$HY2_URI"

echo '{"vless":"'"$VLESS_URI"'","hysteria2":"'"$HY2_URI"'"}' > /root/singbox_nodes.json
echo "订阅文件: /root/singbox_nodes.json"
echo "=================== 部署完成 ==================="
