


## Installation

1. Move to the pqc project directory ($(ROOT_DIR)/pqc/)
```bash
cd pqc
```

2. Run server and client dockers by docker compose
```bash
(path: $(ROOT_DIR)/pqc/)
docker compose up -d
```

3. Set the docker environment
```bash
(path: $(ROOT_DIR)/pqc/)
docker exec -it pqc_server bash
    (pqc_server container)
    apt update && apt upgrade -y
    apt install openssl astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind build-essential git -y
```












## How to add submodule
```bash
git submodule add <repositoy.git>
(example)
git submodule add https://github.com/open-quantum-safe/oqs-provider.git
git submodule update --init --recursive
```