apt update && apt upgrade -y
apt install openssl astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind build-essential git -y
apt install vim -y

if [ ! -d "liboqs" ]; then
    git clone https://github.com/open-quantum-safe/liboqs.git
else
    echo "The liboqs already exists. Skip Git clone."
fi

cd liboqs
mkdir build
cd build
cmake -GNinja ..
ninja
cd ..
cmake -S . -B _build && cmake --build _build && cmake --install _build
cd ..

if [ ! -d "oqs-provider" ]; then
    git clone https://github.com/open-quantum-safe/oqs-provider.git
else
    echo "The oqs-provider already exists. Skip Git clone."
fi
cd oqs-provider
cmake -S . -B _build && cmake --build _build && cmake --install _build