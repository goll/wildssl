#!/bin/bash -
#===============================================================================
#
#          FILE: wildssl.sh
# 
#         USAGE: ./wildssl.sh 
# 
#   DESCRIPTION: Generates root and wildcard certificates
# 
#       OPTIONS: ---
#  REQUIREMENTS: openssl
#         NOTES: - Subject needs to be set in the SUBJECT variable
#                - Generated keys are 2048 bit
#                - Message digest alghoritm is sha256
#                - Validity of the certificates is 10 years
#                - Private keys are not encrypted by default
#                - Wildcard certificate uses SAN extensions and works on root domain
#                - Optionally uncomment triple commented lines and delete lines below them
#                  to password protect key files
#        AUTHOR: Adrian Goll (goll[at]kset.org)
#===============================================================================

set -o nounset
set +o history

KEYSIZE="2048"
DAYS="3650"
MD="-sha256"
SUBJECT="C=XX/ST=State/L=Locality/O=Organization/OU=Organizational Unit"

###read -e -p "Enter the key password: " PASSWORD
read -e -p "Enter the domain for the cert: " CA_CN
CLIENT_CN="wildcard.${CA_CN}"

##
# Check if input is empty
##

###if [[ -z $PASSWORD || -z $CA_CN ]]; then
if [[ -z $CA_CN ]]; then
echo "
Input can not be empty.
" && exit 1
fi

##
# Generate extension configuration
##

cat << EOF > wildcard.cnf
[req]
req_extensions = v3_req

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
basicConstraints = CA:false
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = ${CA_CN}
DNS.2 = *.${CA_CN}
EOF

##
# Generate root CA private key
##

if [[ ! -f ${CA_CN}_CA.key ]]; then
###openssl genrsa -aes128 -passout fd:3 -out "${CA_CN}"_CA.key ${KEYSIZE} 3<<<${PASSWORD} > /dev/null 2>&1
openssl genrsa -out "${CA_CN}"_CA.key ${KEYSIZE} > /dev/null 2>&1
fi

##
# Generate root CA certificate
##

if [[ ! -f ${CA_CN}_CA.crt ]]; then
###openssl req -x509 -new ${MD} -subj "/${SUBJECT/CN=${CA_CN} Root CA" -key "${CA_CN}"_CA.key -passin fd:3 -days ${DAYS} -out "${CA_CN}"_CA.crt 3<<<${PASSWORD} > /dev/null 2>&1
openssl req -x509 -new ${MD} -subj "/${SUBJECT}/CN=${CA_CN} Root CA" -key "${CA_CN}"_CA.key -days ${DAYS} -out "${CA_CN}"_CA.crt > /dev/null 2>&1
fi

##
# Generate client certificate private key
##

openssl genrsa -out "${CLIENT_CN}".key ${KEYSIZE} > /dev/null 2>&1

##
# Generate client CSR
##

###openssl req -new ${MD} -subj "/${SUBJECT}/CN=*.${CA_CN}" -key "${CLIENT_CN}".key -passin fd:3 -out "${CLIENT_CN}".csr 3<<<${PASSWORD} > /dev/null 2>&1
openssl req -new ${MD} -subj "/${SUBJECT}/CN=*.${CA_CN}" -key "${CLIENT_CN}".key -out "${CLIENT_CN}".csr > /dev/null 2>&1

##
# Generate and sign the client certificate
##

###openssl x509 -req ${MD} -in "${CLIENT_CN}".csr -passin fd:3 -extensions v3_req -extfile wildcard.cnf -CA "${CA_CN}"_CA.crt -CAkey "${CA_CN}"_CA.key -CAcreateserial -CAserial index.srl -days ${DAYS} -out "${CLIENT_CN}".crt 3<<<${PASSWORD} > /dev/null 2>&1
openssl x509 -req ${MD} -in "${CLIENT_CN}".csr -extensions v3_req -extfile wildcard.cnf -CA "${CA_CN}"_CA.crt -CAkey "${CA_CN}"_CA.key -CAcreateserial -CAserial index.srl -days ${DAYS} -out "${CLIENT_CN}".crt > /dev/null 2>&1

rm -f {"${CLIENT_CN}".csr,wildcard.cnf}

exit 0
