#! /bin/sh

apt install python3-pip nginx net-tools libssl-dev unzip -y

python3 -m pip install -r requirements.txt

# pre-commit
cp pre-commit.sample pre-commit
mv pre-commit .git/hooks
chmod +x .git/hooks/pre-commit

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
