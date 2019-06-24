#!/usr/bin/env bash
#
# Tested On:
#	OS: Mac OS X [10.10.5 (14F27), 10.13.1]
#           Red Hat Enterprise Linux 7
#
# Requires:
#	openssl [OpenSSL 0.9.8zg 14 July 2015 / LibreSSL 2.2.x]
#       sed
#       mktemp
#       tar

my_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


#################################################################
## DEFINE SOME ENVIRONMENT VARIABLES
#################################################################
# CA_PATH - The path in which to build the CA structure.
# ROOT_CA_PASS - The password for the root CA's private key.

CA_NAME="MongoDB-demo-CA" # Directory name where all OpenSSL-related data will be located
CA_SETTINGS="${my_dir}/${CA_NAME}/.ca_settings.sh" # ROOT CA password location

function die() {
  echo "$@"
  exit 1
}

function log2stderr() {
  echo "${*}" 1>&2
}

function log_info() {
  log2stderr "[INFO] $*"
}

function log_debug() {
  if [[ -n $DEBUG ]]; then
    log2stderr "[DEBUG] $*"
  fi
}

function _openssl_cmd() {
  local ret=$($mktemp_bin 'openssl-out.XXXXXX')
  if [[ -n DEBUG ]]; then
    if ! "$openssl_bin" "$@" | tee "$ret" 2>&1; then
      log2stderr "OpenSSL command [$openssl_bin $@] failed".
      rm -f "$ret"
      exit 1
    fi
    rm -f "$ret"
  else
    if ! "$openssl_bin" "$@" > "$ret" 2>&1; then
      log2stderr "OpenSSL command [$openssl_bin $@] failed".
      rm -f "$ret"
      exit 1
    fi
    rm -f "$ret"
  fi
}

function openssl_wrapper() {
  log_debug "Running the command: $openssl_bin $*"
  _openssl_cmd "$@"
#  if [[ -n $DEBUG ]]; then
#    "$openssl_bin" "$@" 
#  else
#    local ret=$($mktemp_bin 'openssl-out.XXXXXX')
#    if ! "$openssl_bin" "$@" > "$ret" 2>&1; then
#      log2stderr "OpenSSL invocation failed:"
#      log2stderr "$(<"$ret")"
#      rm -f "$ret"
#      exit 1
#    fi
#    rm -f "$ret"
#  fi
}

function openssl_wrapper_verbose() {
  local DEBUG='yes'
  _openssl_cmd "$@"
}

function check_prereqs() {
  local p=''
  for util in openssl sed mktemp tar; do
    if ! p=$(which $util); then
      die "Can't find $util in PATH!"
    else
      export ${util}_bin="$p"
    fi
  done
}

function get_random_string() {
  printf `cat /dev/urandom | env LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w "$1" | head -n 1`
}

[[ -z $CA_PATH ]] && CA_PATH="$my_dir/${CA_NAME}"
if [[ ! -f $CA_SETTINGS ]]; then
  log_info "Generating initial settings file $CA_SETTINGS"
  [[ -d "${my_dir}/${CA_NAME}" ]] || mkdir -p "${my_dir}/${CA_NAME}"
  cat > "$CA_SETTINGS" <<SETTINGS_CONF
ROOT_CA_PASS='$(get_random_string 32)'
COUNTRY='US'
STATE='NY'
LOCALITY='New York'
ORG='ACME'
CLUSTER_ORG_UNIT='Development MongoDB Cluster'
CLIENT_ORG_UNIT='Development MongoDB Clients'
SETTINGS_CONF
  log_info "Please modify the default values for the COUNTRY, STATE, LOCALITY, CLUSTER_ORG_UNIT and CLIENT_ORG_UNIT in the $CA_SETTINGS file."
  log_info "Make sure that CLUSTER_ORG_UNIT and CLIENT_ORG_UNIT have different values if you're going to generate and use client certificates!"
  log_info "Once you finish editing the $CA_SETTINGS file, perform the initialization by running this script with the following parameter: initial_ca_init. For example:"
  log_info "$0 initial_ca_init"
  exit 0
fi

source "$CA_SETTINGS"

SUBJ_PREFIX="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG"
CLUSTER_SUBJ_PREFIX="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/OU=$CLUSTER_ORG_UNIT"
CLIENT_SUBJ_PREFIX="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/OU=$CLIENT_ORG_UNIT"

log_info "CA path is: $CA_PATH"

set -e
WD=$CA_PATH
CERT_CHAINS="$WD/cert-chains"
[[ -d $WD ]] || mkdir -p -- "$WD"
[[ -d $CERT_CHAINS ]] || mkdir -p -- "$CERT_CHAINS"

ROOT_CA_NAME="CA_root"
ROOT_CA_CN="$ORG ROOT CA"
ROOT_CA_HOME="$WD/root"
ROOT_CA_CSR="$ROOT_CA_HOME/csr"
ROOT_CA_PRIVATE="$ROOT_CA_HOME/private"
ROOT_CA_CERTS="$ROOT_CA_HOME/certs"
ROOT_CA_CRL_DIR="$ROOT_CA_HOME/crl"
ROOT_CA_NEWCERTS="$ROOT_CA_HOME/newcerts"
ROOT_CA_DATABASE="$ROOT_CA_HOME/index.txt"
ROOT_CA_SERIAL="$ROOT_CA_HOME/serial"
ROOT_CA_RANDFILE="$ROOT_CA_PRIVATE/.rand"
ROOT_CA_KEY="$ROOT_CA_PRIVATE/root.ca.key.pem"
ROOT_CA_CRT="$ROOT_CA_CERTS/root.ca.crt.pem"
ROOT_CA_CRT_DER="$ROOT_CA_CERTS/root.ca.crt.der"
ROOT_CA_CRL="$ROOT_CA_CRL_DIR/ca.crl.pem"
ROOT_CA_CRL_NUMBER="$ROOT_CA_HOME/crlnumber"
ROOT_CA_CRL_DAYS="3650"
ROOT_CA_CERT_DAYS="824" # https://support.apple.com/en-us/HT210176

function create_and_sign_cert() {
  local type="$1"
  local key_id="$2"
  local common_name="$3"
  shift 2
  local CA='ROOT'

  local key_var="${CA}_CA_PRIVATE"
  local key="${!key_var}/${key_id}.key.pem"

  [[ -f $key ]] && die "Key file $key is already exist, please choose another name!"

  local csr_var="${CA}_CA_CSR"
  local csr="${!csr_var}/${key_id}.csr.pem"

  [[ -f $csr ]] && die "CSR file $csr is already exist, please choose another name!"

  local crt_var="${CA}_CA_CERTS"
  local crt="${!crt_var}/${key_id}.crt.pem"

  local ca_name_var="${CA}_CA_NAME"
  local ca_key_var="${CA}_CA_KEY"
  local ca_crt_var="${CA}_CA_CRT"
  local ca_crt_pass_var="${CA}_CA_PASS"

  [[ -n "${!ca_name_var}" ]] || die "Certificate authority $CA isn't configured in the script!"
  [[ -f "${!ca_key_var}" ]]  || die "You have to initialize Certificate Authority $CA first!"

  if [[ $type == 'CLUSTER' ]]; then
    local subj="$CLUSTER_SUBJ_PREFIX"
  else
    local subj="$CLIENT_SUBJ_PREFIX"
  fi

  log_debug "Generating $key"
  openssl_wrapper genrsa -out "$key" 2048
  chmod 400 "$key" || die "Can't chmod key: $key"

  log_info "Creating CSR for ${common_name}"
  openssl_wrapper req \
    -config "$OPENSSL_CONF" \
    -subj "${subj}/CN=${common_name}" \
    -key "$key" \
    -new \
    -sha256 \
    -out "$csr"

  log_info "Signing certificate $key_id using $CA CA"

  if [[ $type == 'CLIENT' ]]; then
    local exts="mongoclient"
    local ext_option="-extensions"
  else
    local ext_option="-extfile"
    local ext_file=$($mktemp_bin 'openssl-ext.XXXXXXXX')
    cat << EOF > "$ext_file"
basicConstraints = CA:FALSE
nsCertType = client, server
nsComment = "MongoDB Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @alt_names

[alt_names]

EOF
    local ip_regex='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
    local ip_counter=1
    local dns_counter=1
    local arg=''
    for arg in "$@"; do
      if [[ $arg =~ $ip_regex ]]; then
        # IP
        echo "IP."$((ip_counter++))" = $arg" >> "$ext_file"
      fi

      # Currently required both for hostnames and IP addresses
      # https://jira.mongodb.org/browse/SERVER-24591
      echo "DNS."$((dns_counter++))" = $arg" >> "$ext_file"
    done
    local exts="$ext_file"
  fi

  log_debug "Using the following CA key password: ${!ca_crt_pass_var}"
  echo -n "${!ca_crt_pass_var}" | openssl_wrapper ca \
    -config "$OPENSSL_CONF" \
    -name "${!ca_name_var}" \
    $ext_option "$exts" \
    -notext \
    -md sha256 \
    -keyfile "${!ca_key_var}" \
    -cert "${!ca_crt_var}" \
    -in "$csr" \
    -out "$crt" \
    -batch \
    -passin stdin
  [[ $type == 'CLUSTER' ]] && rm -f "$ext_file"

  local combined="${!key_var}/${key_id}.pem"
  cat "$key" "$crt" > "$combined"

  if [[ $type == 'CLUSTER' ]]; then
    log_info "Server certificate created: $combined"
    log_info "Use it for the net.ssl.PEMKeyFile MongoDB Server configuration option"
  else
    log_info "Client certificate created: $combined"
    log_info "Here's an example how to add to MongoDB Server by using MongoDB Shell:"
    log_info "> db.getSiblingDB('\$external').createUser({ user: '$($openssl_bin x509 -in "$crt" -subject -nameopt RFC2253 -noout | $sed_bin 's/subject= //; s,\\,\\\\,')', roles: [ { role: 'root', db: 'admin' } ] });"
  fi
}

for cca in ROOT; do
  for sd in CERTS CRL_DIR NEWCERTS PRIVATE CSR; do
    d="${cca}_CA_${sd}"
    [[ -d "${!d}" ]] || mkdir -p -- "${!d}" || die "Failed to create ${!d} directory"
  done
  pvt="${cca}_CA_PRIVATE"
  chmod 700 ${!pvt} || die "Can't chmod 700 ${!pvt}"
  idx="${cca}_CA_DATABASE"
  [[ -f "${!idx}" ]] || touch "${!idx}"
  ser="${cca}_CA_SERIAL"
  [[ -f "${!ser}" ]] || echo 1000 > "${!ser}"
  crlnum="${cca}_CA_CRL_NUMBER"
  [[ -f "${!crlnum}" ]] || echo 1000 > "${!crlnum}"
done

OPENSSL_CONF="$WD/openssl.cnf"

cat > "$OPENSSL_CONF" <<OPENSSL_CONF
# OpenSSL CA configuration file.

[ ca ]
default_ca = $ROOT_CA_NAME

[ $ROOT_CA_NAME ]
# Directory and file locations.
dir               = $ROOT_CA_HOME
certs             = $ROOT_CA_CERTS
crl_dir           = $ROOT_CA_CRL_DIR
new_certs_dir     = $ROOT_CA_NEWCERTS
database          = $ROOT_CA_DATABASE
serial            = $ROOT_CA_SERIAL
RANDFILE          = $ROOT_CA_RANDFILE

# The root key and root certificate.
private_key       = $ROOT_CA_KEY
certificate       = $ROOT_CA_CRT

# For certificate revocation lists.
crlnumber         = $ROOT_CA_CRL_NUMBER
crl               = $ROOT_CA_CRL
crl_extensions    = crl_ext
default_crl_days  = $ROOT_CA_CRL_DAYS

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = $ROOT_CA_CERT_DAYS
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of \`man ca\`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the \`ca\` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the \`req\` tool (\`man req\`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = $COUNTRY
stateOrProvinceName_default     = $STATE
localityName_default            = $LOCALITY
0.organizationName_default      = $ORG
organizationalUnitName_default  = $ORG_UNIT
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (\`man x509v3_config\`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (\`man x509v3_config\`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (\`man x509v3_config\`).
basicConstraints = CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = digitalSignature
extendedKeyUsage = clientAuth

[ server_cert ]
# Extensions for server certificates (\`man x509v3_config\`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ mongoclient ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "MongoDB Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = digitalSignature
extendedKeyUsage = clientAuth

[ crl_ext ]
# Extension for CRLs (\`man x509v3_config\`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (\`man ocsp\`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
OPENSSL_CONF

function initial_ca_init() {
  [[ -f $ROOT_CA_KEY ]] && die "Initial initialization was already done: $ROOT_CA_KEY is present!"
  log_info "Creating private key for root CA..."
  openssl_wrapper genrsa -aes256 -passout "pass:${ROOT_CA_PASS}" -out "$ROOT_CA_KEY" 4096
  chmod 400 "$ROOT_CA_KEY" || die "Can't secure the Root CA key"

  log_info "Creating self-signed root CA certificate"
  openssl_wrapper req -config "$OPENSSL_CONF" \
        -key "$ROOT_CA_KEY" \
        -new -x509 -days 7300 -sha256 -extensions v3_ca \
        -subj "${SUBJ_PREFIX}/CN=$ROOT_CA_CN" \
        -passin "pass:${ROOT_CA_PASS}" \
        -out "$ROOT_CA_CRT"

  chmod 444 "$ROOT_CA_CRT"

  log_info "Root CA certificate created:"
  openssl_wrapper_verbose x509 -noout -subject -in "$ROOT_CA_CRT"
  openssl_wrapper x509 -outform der -in "$ROOT_CA_CRT" -out "$ROOT_CA_CRT_DER"

  log_info "Root CA file (PEM format - use this for UNIX/Linux): $ROOT_CA_CRT"
  log_info "Root CA file (DER format - use this for MS Windows): $ROOT_CA_CRT_DER"
  log_info "Use it for the net.ssl.CAFile configuration option in a mongod.conf (PEM format)."
  log_info "How to import this into MS Windows Trusted Root Certification Authorities store:"
  log_info 'https://technet.microsoft.com/en-us/library/cc754841(v=ws.11).aspx'

  generate_crl
}

function backup_ca() {
  local fn="${CA_PATH}-backup-$(date '+%Y.%m.%d-%H_%M_%S_%Z').tar.bz2"
  [[ -f $fn ]] && die "Backup file $fn is already present, stopping"
  "$tar_bin" jcf "$fn"  -C "$(dirname "${CA_PATH?}")" "${CA_NAME?}"
  [[ -f $fn ]] || die "Can't create backup into $fn file"
  "$tar_bin" jtf "$fn" > /dev/null || die "Can't verify integrity of just created backup file $fn"
  log_info "Successfully created backup into $fn"
}

function restore_ca() {
  local fn="$1"

  [[ -n $fn ]] || die "Usage: restore_ca backup.tar.bz2"
  [[ -r $fn ]] || die "File $fn isn't readable by shell"

  local re="^${CA_NAME}-backup-"
  [[ $fn =~ $re ]] || die "Safe precaution: can't restore backup $fn as $CA_NAME"

  "$tar_bin" jtf "$fn" > /dev/null || die "Can't verify archive's $fn integrity using tar"

  log_debug "Removing old data in $CA_PATH"
  [[ -d $CA_PATH ]] && rm -fr -- "$CA_PATH"

  log_info "Restoring backup from $fn to $CA_PATH"
  "$tar_bin" jxf "$fn" -C "$(dirname "$CA_PATH")"

  log_info "Backup successfully restored"
}

function generate_crl() {
  log_info "Generating CRL"
  echo -n "${ROOT_CA_PASS?}" | openssl_wrapper ca \
    -gencrl \
    -config "$OPENSSL_CONF" \
    -name "${ROOT_CA_NAME?}" \
    -passin stdin \
    -out "${ROOT_CA_CRL?}"
  log_info "Successfully generated CRL file: ${ROOT_CA_CRL?} which will expire in $ROOT_CA_CRL_DAYS days. If you're using CRLs in your MongoDB deployment (net.ssl.CRLFile configuration option is defined in mongod.conf), new CRL file needs to be transferred to all hosts in the MongoDB deployment. Those mongod and mongos instances need to be restarted in a rolling manner to make this change effective. When the CRL file expires, MongoDB will stop accepting all new SSL connections until a new CRL file is generated and MongoDB services are restarted."
}

function revoke_certificate() {
  local name=$1

  local crt="${ROOT_CA_CERTS?}/${name}.crt.pem"
  [[ -f $crt ]] || die "Certificate file $crt not found"

  log_info "Revoking $name cerificate using $CA CA"
  echo -n "${ROOT_CA_PASS?}" | openssl_wrapper ca \
    -revoke "$crt" \
    -config "$OPENSSL_CONF" \
    -name "${ROOT_CA_NAME?}" \
    -passin stdin \
    -batch
  generate_crl "$CA"
}

check_prereqs

if [[ -n $1 ]]; then
  func=$1
  if declare -f "$1" > /dev/null; then
    shift # removes the first array element from $@ (which is already in $func)
    $func "$@"
  else
    echo "There is no function $func declared!"
  fi
else
  log_info "Simple MongoDB Certification Authority demo app welcomes you!"
  echo "Usage: ${BASH_SOURCE[0]} function parameter(s)"
  echo "Functions:"
  echo "  initial_ca_init"
  echo "  backup_ca"
  echo "  restore_ca backup.tar.bz2"
  echo "  create_and_sign_cert CLUSTER rs0 rs0.host.name rs0.alternate.name 127.0.0.1 192.168.0.1"
  echo "  create_and_sign_cert CLIENT devclient 'Development Client Common Name'"
  echo "  revoke_certificate rs0"
  echo "  generate_crl"
fi

log_info "Oki dockie!"
