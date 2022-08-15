#!/bin/bash

SUBJ="/C=US/ST=Washington/L=Seattle/O=Tempesta Technologies Inc./OU=Testing/CN=tempesta-tech.com/emailAddress=info@tempesta-tech.com"
KEY_NAME="tfw-root.key"
CERT_NAME="tfw-root.crt"

echo Generating RSA key...

mkdir -p RSA
cd RSA
openssl req -new -days 365 -nodes -x509					\
	-newkey rsa:2048						\
	-subj "${SUBJ}" -keyout ${KEY_NAME} -out ${CERT_NAME}
cd ..

echo Generating ECDSA key...

mkdir -p ECDSA
cd ECDSA
openssl req -new -days 365 -nodes -x509					\
	-newkey ec -pkeyopt ec_paramgen_curve:prime256v1		\
	-subj "${SUBJ}" -keyout ${KEY_NAME} -out ${CERT_NAME}
cd ..

echo Done.
