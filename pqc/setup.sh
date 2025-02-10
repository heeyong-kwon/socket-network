apt update && apt upgrade -y
apt install openssl astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind build-essential git -y

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build
cd build
cmake -GNinja ..
ninja
cd ..
cmake -S . -B _build && cmake --build _build && cmake --install _build
cd ../..

git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -S . -B _build && cmake --build _build && cmake --install _build