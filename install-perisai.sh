#!/bin/bash
# Installer Perisai WAF (Go) ala aaPanel — tetap memakai Docker.
#
# Cara pakai (one-liner):
#   URL=https://raw.githubusercontent.com/willy911/perisai-waf-go/main/install-perisai.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install-perisai.sh "$URL";fi;bash install-perisai.sh
#
# Di akhir instalasi, terminal menampilkan: URL dashboard, username, password, dan port.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

IMAGE="willy911/perisai-waf:latest"
REPO_URL="https://github.com/willy911/perisai-waf-go.git"
CONTAINER="perisai-waf"
INSTALL_DIR="/opt/perisai-waf"
DATA_DIR="$INSTALL_DIR/data"

Green='\033[32m'; Yellow='\033[33m'; Red='\033[31m'; NC='\033[0m'
startTime=$(date +%s)

echo -e "${Green}============================ Perisai WAF Installer ============================${NC}"

# ---- 1. root & arsitektur ----
if [ "$(whoami)" != "root" ]; then
  echo -e "${Red}Harus dijalankan sebagai root. Coba: sudo bash $0${NC}"
  exit 1
fi
if [ "$(getconf LONG_BIT)" != "64" ]; then
  echo -e "${Red}Maaf, hanya mendukung sistem 64-bit.${NC}"
  exit 1
fi
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
  echo -e "${Red}Arsitektur $ARCH belum didukung (hanya x86_64 / aarch64).${NC}"
  exit 1
fi

# ---- 2. Docker ----
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker belum ada, menginstall..."
  if [ -f /usr/bin/curl ]; then
    curl -fsSL https://get.docker.com | bash
  else
    wget -qO- https://get.docker.com | bash
  fi
fi
if ! docker info >/dev/null 2>&1; then
  echo -e "${Red}Docker tidak jalan. Jalankan: systemctl start docker${NC}"
  exit 1
fi
echo -e "Docker: ${Green}$(docker --version)${NC}"

# ---- 3. Image ----
echo "Mengambil image $IMAGE ..."
if ! docker pull "$IMAGE" 2>/dev/null; then
  echo -e "${Yellow}Pull gagal, build dari source...${NC}"
  command -v git >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq git; }
  rm -rf /tmp/perisai-waf-go && git clone --depth 1 "$REPO_URL" /tmp/perisai-waf-go
  docker build -t "$IMAGE" /tmp/perisai-waf-go
  rm -rf /tmp/perisai-waf-go
fi

# ---- 4. Input user ----
read -p "Username dashboard [admin]: " INPUT_USER
DASH_USER="${INPUT_USER:-admin}"
DASH_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)"
read -p "Port WAF/proxy [8080]: " INPUT_WAF_PORT
WAF_PORT="${INPUT_WAF_PORT:-8080}"
read -p "Port dashboard [8899]: " INPUT_DASH_PORT
DASH_PORT="${INPUT_DASH_PORT:-8899}"

mkdir -p "$DATA_DIR"

# Bersihkan container lama bila ada
docker rm -f "$CONTAINER" >/dev/null 2>&1

# ---- 5. Jalankan container ----
echo "Menjalankan container..."
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "$WAF_PORT:8080" \
  -p "$DASH_PORT:8899" \
  -v "$DATA_DIR:/app/data" \
  -e DATA_DIR=/app/data \
  -e PORT=8080 \
  -e DASHBOARD_PORT=8899 \
  -e HOSTNAME=0.0.0.0 \
  -e INITIAL_USER="$DASH_USER" \
  -e INITIAL_PASSWORD="$DASH_PASS" \
  "$IMAGE" >/dev/null

# ---- 6. Tunggu dashboard siap ----
echo -n "Menunggu dashboard siap"
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$DASH_PORT/api/login" | grep -q "405\|200\|404"; then
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

# ---- 7. Ringkasan ----
PUB_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "<IP-server>")
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
endTime=$(date +%s)
((elapsed = (endTime - startTime) / 60))

echo -e "=================================================================="
echo -e "${Green}Perisai WAF install completed!${NC}"
echo -e "=================================================================="
echo "  Dashboard (luar) : http://${PUB_IP}:${DASH_PORT}"
echo "  Dashboard (lokal): http://${LOCAL_IP:-127.0.0.1}:${DASH_PORT}"
echo "  Port WAF/proxy   : ${WAF_PORT}  (arahkan domain ke sini)"
echo -e "  username         : ${Yellow}${DASH_USER}${NC}"
echo -e "  password         : ${Yellow}${DASH_PASS}${NC}"
echo ""
echo -e "  ${Yellow}Buka port ${WAF_PORT} & ${DASH_PORT} di security group/firewall bila tidak bisa diakses.${NC}"
echo ""
echo -e "  Data tersimpan di: ${DATA_DIR} (tetap aman walau container dihapus)"
echo -e "=================================================================="
echo -e "Time consumed: ${Green}${elapsed}${NC} Minute(s)!"
rm -f ./install-perisai.sh
