
import os

import subprocess

token           = " @ oqsprovider"
oqs_sig_algs    = subprocess.getoutput(f"openssl list -signature-algorithms | grep '{token}'")

# List up the signature algorithms supported by oqs-provider
oqs_sig_algs    = oqs_sig_algs.split(f"\n")
for i in range(len(oqs_sig_algs)):
    oqs_sig_algs[i] = oqs_sig_algs[i].replace(token, "").strip()
print(oqs_sig_algs)
exit()

# Make test directory
path_certs_dir  = "./certs"
if not os.path.isdir(path_certs_dir):
    os.mkdir(path_certs_dir)
    print(f"Test directory is created: {path_certs_dir}")
else:
    print(f"Test directory already exists.")
# Move to the current path to the cert directory
os.chdir(path_certs_dir)

# Create certificates for all supported signature algorithms
PATH_CONFIG_FILE    = "/usr/local/ssl/openssl.cnf"
for x in oqs_sig_algs:
    algorithm       = x
    CA_key          = f"{x}_CA.key"
    CA_cert         = f"{x}_CA.crt"
    CA_subject      = f"'/CN=test CA'"
    cert_days       = 365
    os.system(f"openssl req -x509 -new \
                    -newkey {algorithm} \
                        -keyout {CA_key} \
                            -out {CA_cert} \
                                -nodes \
                                    -subj {CA_subject} \
                                        -days {cert_days} \
                                            -config {PATH_CONFIG_FILE}")
    
    server_key      = f"{x}_srv.key"
    os.system(f"openssl genpkey \
                    -algorithm {algorithm} \
                        -out {server_key}")
    
    server_cert_req = f"{x}_srv.csr"
    server_subject  = f"'/CN=test server'"
    os.system(f"openssl req -new \
                    -newkey {algorithm} \
                        -keyout {server_key} \
                            -out {server_cert_req} \
                                -nodes \
                                    -subj {server_subject} \
                                        -config {PATH_CONFIG_FILE}")
    
    server_cert     = f"{x}_srv.crt"
    os.system(f"openssl x509 -req \
                    -in {server_cert_req} \
                        -out {server_cert} \
                            -CA {CA_cert} \
                                -CAkey {CA_key} \
                                    -CAcreateserial \
                                        -days {cert_days}")

input("Waiting any input with enter key")
os.chdir("..")
os.system(f"rm -rf {path_certs_dir}")
    

    







