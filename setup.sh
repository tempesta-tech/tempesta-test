#! /bin/sh

apt install python3-pip nginx libnginx-mod-http-echo libtool net-tools libssl-dev apache2-utils libnghttp2-dev autoconf unzip docker.io -y

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
apt  install golang-go -y
git clone https://github.com/tempesta-tech/h2spec.git /tmp/h2spec
cd /tmp/h2spec
make build
cp ./h2spec /usr/bin/h2spec

# curl
git clone --depth=1 --branch curl-7_85_0 https://github.com/curl/curl.git /tmp/curl
cd /tmp/curl
autoreconf -fi
./configure --with-openssl --with-nghttp2 --prefix /usr/local
make
make install
ldconfig
