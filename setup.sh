#!/usr/bin/env bash
set -euo pipefail

CURRENT_DIR=$(pwd)

apt install python3-pip nginx libnginx-mod-http-echo libtool net-tools libssl-dev \
    apache2-utils nghttp2-client libnghttp2-dev autoconf unzip libtemplate-perl \
    tcpdump lxc util-linux -y

# stop and disable installed nginx
systemctl stop nginx
systemctl disable nginx

python3 -m pip install -r requirements.txt

# pre-commit
pre-commit install
pre-commit autoupdate

# ignore formatter commit in git blame
git config blame.ignoreRevsFile .git-blame-ignore-revs

# tls-perf
git clone https://github.com/tempesta-tech/tls-perf.git /tmp/tls-perf
cd /tmp/tls-perf
make
cp /tmp/tls-perf/tls-perf /bin/tls-perf

# wrk
git clone https://github.com/wg/wrk.git /tmp/wrk
cd /tmp/wrk
make
cp /tmp/wrk/wrk /bin/wrk

# h2spec
apt install golang-go -y
git clone https://github.com/tempesta-tech/h2spec.git /tmp/h2spec
cd /tmp/h2spec
make build
cp ./h2spec /usr/bin/h2spec

#gflood - CONTINUATION frame flooder
mkdir /tmp/gflood
cd "${CURRENT_DIR}"
cp tools/gflood/main.go /tmp/gflood/
cd /tmp/gflood
go mod init gflood
go mod tidy
go build
cp ./gflood /usr/bin/gflood

#ctrl_frames_flood - ctrl frame flooder
mkdir /tmp/ctrl_frames_flood
cd "${CURRENT_DIR}"
cp tools/ctrl_frames_flood/main.go /tmp/ctrl_frames_flood/
cd /tmp/ctrl_frames_flood
go mod init ctrl_frames_flood
go mod tidy
go build
cp ./ctrl_frames_flood /usr/bin/ctrl_frames_flood

#gutils - Common golang utils
cd "${CURRENT_DIR}"
go build -o /usr/bin/ratecheck ./gutils/cmd/ratecheck/main.go

# curl
git clone --depth=1 --branch curl-7_85_0 https://github.com/curl/curl.git /tmp/curl
cd /tmp/curl
autoreconf -fi
./configure --with-openssl --with-nghttp2 --prefix /usr/local
make
make install
ldconfig

# install lxc
snap install lxd
lxd init --auto

# update submodules
cd "${CURRENT_DIR}"
git submodule update --init --recursive

# create tempesta-site-stage container
python3 tempesta-tech.com/container/lxc/create.py --type=stage
lxc stop tempesta-site-stage

# docker
cd "${CURRENT_DIR}"
./tools/docker/install-docker.sh

# ClickHouse
mkdir /tmp/clickhouse-install & cd  /tmp/clickhouse-install
apt install apt-transport-https ca-certificates gnupg -y
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
apt update
apt install clickhouse-server clickhouse-client -y
rm -f /etc/clickhouse-server/users.d/default-password.xml
systemctl enable clickhouse-server.service
systemctl start clickhouse-server.service
