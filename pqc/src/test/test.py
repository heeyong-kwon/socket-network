
import os

def move_to_target_dir(path: str):
    os.chdir(path)
def build_oqs_provider():
    os.system("liboqs_DIR=../liboqs cmake -DOPENSSL_ROOT_DIR=$OPENSSL_PATH -S . -B _build && cmake --build _build && cmake --install _build")
    os.system("cd ..")
    os.system("cp rp5_openssl.cnf $OPENSSL_PATH/openssl.cnf")
    os.system("STRING='export OPENSSL_CONF=$OPENSSL_PATH/openssl.cnf'")
    os.system("grep -qxF '$STRING' ~/.bashrc || echo '$STRING' >> ~/.bashrc")
    os.system("STRING='alias python=python3'")
    os.system("grep -qxF '$STRING' ~/.bashrc || echo '$STRING' >> ~/.bashrc")
def test_cert(test_alg: str):
    os.system(f"openssl req -x509 -new -newkey {test_alg} -keyout {test_alg}_CA.key -out {test_alg}_CA.crt -nodes -subj '/CN=test CA' -days 365 -config /usr/local/ssl/openssl.cnf")
    os.system(f"openssl genpkey -algorithm {test_alg} -out {test_alg}_srv.key")
    os.system(f"openssl req -new -newkey {test_alg} -keyout {test_alg}_srv.key -out {test_alg}_srv.csr -nodes -subj '/CN=test server' -config /usr/local/ssl/openssl.cnf")
    os.system(f"openssl x509 -req -in {test_alg}_srv.csr -out {test_alg}_srv.crt -CA {test_alg}_CA.crt -CAkey {test_alg}_CA.key -CAcreateserial -days 365")
    os.system(f"rm {test_alg}*")

if __name__ == "__main__":
    os.system('pwd')
    move_to_target_dir("../../../oqs-provider")
    build_oqs_provider()
    
    test_alg    = "hyalg"
    test_cert(test_alg=test_alg)



    
    
    
    os.system('pwd')

