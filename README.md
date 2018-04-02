# Simple Certificate Authority for MongoDB Server

## DISCLAIMER

This software is specifically designed to work with MongoDB Server to quickly create a **test** SSL environment. Official MongoDB Support is **not** provided for this, **use at your own RISK**.

## Introduction

This shell-script creates and maintains the simple private Certificate Authority which you can use to issue the SSL client and server certificates for `mongod`.

Requirements: Bash 3.x or later, OpenSSL, `sed`, `mktemp`, `tar`, `/dev/urandom`.

Tested on: macOS High Sierra + LibreSSL, Red Hat Enterprise Linux 7.

## Quick start guide

### 1. Initial configuration

#### 1.1. Run the script to generate the `MongoDB-demo-CA` directory and the default configuration file `.ca_settings.sh`:
```
$ ls
ca_mongodb.sh

$ ./ca_mongodb.sh
[INFO] Generating initial settings file /home/abr/tmp/MongoDB-demo-CA/.ca_settings.sh
[INFO] Please modify the default values for the COUNTRY, STATE, LOCALITY, CLUSTER_ORG_UNIT and CLIENT_ORG_UNIT in the /home/abr/tmp/MongoDB-demo-CA/.ca_settings.sh file.
[INFO] Make sure that CLUSTER_ORG_UNIT and CLIENT_ORG_UNIT have different values if you're going to generate and use client certificates!
[INFO] Once you finish editing the /home/abr/tmp/MongoDB-demo-CA/.ca_settings.sh file, perform the initialization by running this script with the following parameter: initial_ca_init. For example:
[INFO] ./ca_mongodb.sh initial_ca_init
```

#### 1.2. Edit the configuration file

```
$ nano ./MongoDB-demo-CA/.ca_settings.sh
```

Feel free to change the following variables:

- `COUNTRY`: Country abbreviation;
- `STATE`: State abbreviation;
- `LOCALITY`: City;
- `ORG`: Organization name;
- `CLUSTER_ORG_UNIT`: Organizational unit name for `mongod` hosts;
- `CLIENT_ORG_UNIT`: Organizational unit name for `mongod` client certificates.

#### 1.3. Generate the Certificate Authority certificate

```
$ ./ca_mongodb.sh initial_ca_init
[INFO] CA path is: /home/abr/tmp/MongoDB-demo-CA
[INFO] Creating private key for root CA...
Generating RSA private key, 4096 bit long modulus
................................................................................................................................................................................................++
...........................................................................................................................................................................................................++
e is 65537 (0x10001)
[INFO] Creating self-signed root CA certificate
[INFO] Root CA certificate created:
subject= /C=US/ST=NY/L=New York/O=ACME/CN=ACME ROOT CA
[INFO] Root CA file (PEM format - use this for UNIX/Linux): /home/abr/tmp/MongoDB-demo-CA/root/certs/root.ca.crt.pem
[INFO] Root CA file (DER format - use this for MS Windows): /home/abr/tmp/MongoDB-demo-CA/root/certs/root.ca.crt.der
[INFO] Use it for the net.ssl.CAFile configuration option in a mongod.conf (PEM format).
[INFO] How to import this into MS Windows Trusted Root Certification Authorities store:
[INFO] https://technet.microsoft.com/en-us/library/cc754841(v=ws.11).aspx
[INFO] Generating CRL
Using configuration from /home/abr/tmp/MongoDB-demo-CA/openssl.cnf
[INFO] Successfully generated CRL file: /home/abr/tmp/MongoDB-demo-CA/root/crl/ca.crl.pem which will expire in 3650 days. If you're using CRLs in your MongoDB deployment (net.ssl.CRLFile configuration option is defined in mongod.conf), new CRL file needs to be transferred to all hosts in the MongoDB deployment. Those mongod and mongos instances need to be restarted in a rolling manner to make this change effective. When the CRL file expires, MongoDB will stop accepting all new SSL connections until a new CRL file is generated and MongoDB services are restarted.
[INFO] Oki dockie!
```

### 2. Generate the server certificate

```
$ ./ca_mongodb.sh create_and_sign_cert CLUSTER rhel73 rhel-73.acme.qa 10.211.55.20

(OpenSSL output skipped)

[INFO] Server certificate created: /home/abr/tmp/MongoDB-demo-CA/root/private/rhel73.pem
[INFO] Use it for the net.ssl.PEMKeyFile MongoDB Server configuration option
[INFO] Oki dockie!
```

Parameters:

- `create_and_sign_cert`: Certificate request creation & signing mode.
-  `CLUSTER`: A constant, indicating that the **server** certificate will be created.
-  `rhel73`: The name for this particular certificate inside Certificate Authority. Certificate's filenames will be derived from this parameter.
-  `rhel-73.acme.qa 10.211.55.20`: The space-separated list of hostnames and IP addresses for the certificate. The first value in the list goes to the *Common Name* field in the certificate, and the whole list will be represented in the *X509v3 Subject Alternative Name* field.

### 3. Run `mongod` with SSL, no authentication

#### 3.1 Create the following MongoDB Server configuration file (`mongod.conf`):

```
systemLog:
  destination: file
  logAppend: false
  path: /home/abr/tmp/mongod.log
storage:
  dbPath: /home/abr/tmp/data
  journal:
    enabled: true
processManagement:
  fork: true
  pidFilePath: /home/abr/tmp/mongod.pid
net:
  port: 28000
  bindIp: 0.0.0.0
  ssl:
    mode: requireSSL
    PEMKeyFile: /home/abr/tmp/MongoDB-demo-CA/root/private/rhel73.pem
    CAFile: /home/abr/tmp/MongoDB-demo-CA/root/certs/root.ca.crt.pem
```

#### 3.2. Run `mongod` process:

```
$ mkdir -p /home/abr/tmp/data
$ mongod -f /home/abr/tmp/mongod.conf
```

### 4. Generate the client certificate for MongoDB Shell

```
$ ./ca_mongodb.sh create_and_sign_cert CLIENT shell 'MongoDB Shell'

(OpenSSL output skipped)

[INFO] Client certificate created: /home/abr/tmp/MongoDB-demo-CA/root/private/shell.pem
[INFO] Here's an example how to add to MongoDB Server by using MongoDB Shell:
[INFO] > db.getSiblingDB('$external').createUser({ user: 'CN=MongoDB Shell,OU=Development MongoDB Clients,O=ACME,ST=NY,C=US', roles: [ { role: 'root', db: 'admin' } ] });
[INFO] Oki dockie!
```

Parameters:

- `create_and_sign_cert`: Certificate request creation & signing mode.
- `CLIENT`: A constant, indicating that the **client** certificate will be created.
- `shell`: The name for this particular certificate inside Certificate Authority. Certificate's filenames will be derived from this parameter.
- `'MongoDB Shell'`: Client certificate's *Common Name*

### 5. Connect to MongoDB Server using the generated client certificate

```
$ mongo --ssl --host 10.211.55.20 --port 28000 --sslCAFile /home/abr/tmp/MongoDB-demo-CA/root/certs/root.ca.crt.pem --sslPEMKeyFile /home/abr/tmp/MongoDB-demo-CA/root/private/shell.pem
MongoDB shell version v3.6.3
connecting to: mongodb://10.211.55.20:28000/
MongoDB server version: 3.6.3
MongoDB Enterprise >
```

### 6. Create the user for X.509 authentication

```
MongoDB Enterprise > db.getSiblingDB('$external').createUser({ user: 'CN=MongoDB Shell,OU=Development MongoDB Clients,O=ACME,ST=NY,C=US', roles: [ { role: 'root', db: 'admin' } ] });
Successfully added user: {
	"user" : "CN=MongoDB Shell,OU=Development MongoDB Clients,O=ACME,ST=NY,C=US",
	"roles" : [
		{
			"role" : "root",
			"db" : "admin"
		}
	]
}
```

### 7. Reconfigure MongoDB Server to support X.509 authentication

#### 7.1. Append the following content to the end of the `mongod.conf` file

```
security:
  authorization: enabled
setParameter:
  authenticationMechanisms: "MONGODB-X509"
```

#### 7.2. Restart `mongod` process

```
$ killall mongod
$ mongod -f ./mongod.conf
```

### 8. Authenticate using X.509 authentication mechanism

```
$ mongo --ssl --host 10.211.55.20 --port 28000 --sslCAFile /home/abr/tmp/MongoDB-demo-CA/root/certs/root.ca.crt.pem --sslPEMKeyFile /home/abr/tmp/MongoDB-demo-CA/root/private/shell.pem -u 'CN=MongoDB Shell,OU=Development MongoDB Clients,O=ACME,ST=NY,C=US' --authenticationMechanism MONGODB-X509 --authenticationDatabase '$external'
MongoDB shell version v3.6.3
connecting to: mongodb://10.211.55.20:28000/
MongoDB server version: 3.6.3
MongoDB Enterprise >
```

## Miscellaneous

```
$ ./ca_mongodb.sh
[INFO] CA path is: /home/abr/tmp/MongoDB-demo-CA
[INFO] Simple MongoDB Certification Authority demo app welcomes you!
Usage: ./ca_mongodb.sh function parameter(s)
Functions:
  initial_ca_init
  backup_ca
  restore_ca backup.tar.bz2
  create_and_sign_cert CLUSTER rs0 rs0.host.name rs0.alternate.name 127.0.0.1 192.168.0.1
  create_and_sign_cert CLIENT devclient 'Development Client Common Name'
  revoke_certificate rs0
  generate_crl
[INFO] Oki dockie!
```
