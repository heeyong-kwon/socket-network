
## Installation

#### Install oqs-provider

1. Move to the pqc project directory ($(ROOT_DIR)/pqc/)
```bash
cd pqc
# git submodule update --init --recursive
```
2. Run server and client dockers by docker compose
```bash
(path: $(ROOT_DIR)/pqc/)
docker compose up -d
```

3. Set the docker environment -> install oqs-provider
```bash
(path: $(ROOT_DIR)/pqc/)
docker exec -it pqc_server bash
    (pqc_server container)
    (path: /)
    cd socket/pqc/
    (path: /socket/pqc/)
    bash setup.sh
    source ~/.bashrc
    (path: /socket/pqc/)
    (optional: If you want to test the installation)
    cd oqs-provider
    cd _build && ctest --parallel 5 --rerun-failed --output-on-failure -V
    (path: /socket/pqc/_build/)
```




<!-- ## How to add submodule
```bash
git submodule add <repositoy.git>
(example)
git submodule add https://github.com/open-quantum-safe/oqs-provider.git
git submodule update --init --recursive
``` -->