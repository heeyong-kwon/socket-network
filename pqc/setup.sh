apt update && apt upgrade -y
apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind build-essential git -y
apt install vim screen -y
apt install python3 python3-pip python3-dev python3-venv build-essential checkinstall wget zlib1g-dev -y
alias python=python3

# Install OpenSSL >= version 3.2
OPENSSL_VERSION=3.2.0
OPENSSL_FILE="openssl-$OPENSSL_VERSION.tar.gz"
if [ ! -f $OPENSSL_FILE]; then
    wget https://www.openssl.org/source/$OPENSSL_FILE
else
    echo "The $OPENSSL_FILE already exists. Skip download."
fi
# rm -rf openssl-3.2.0
tar -xvzf $OPENSSL_FILE
cd openssl-$OPENSSL_VERSION
./Configure linux-aarch64 --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
make -j$(nproc)
make install

STRING='export PATH=/usr/local/openssl/bin:$PATH'
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
STRING='export LD_LIBRARY_PATH=/usr/local/openssl/lib:$LD_LIBRARY_PATH'
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc

# Install liboqs
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

# Install oqs-provider
if [ ! -d "oqs-provider" ]; then
    git clone https://github.com/open-quantum-safe/oqs-provider.git
else
    echo "The oqs-provider already exists. Skip Git clone."
fi

cd oqs-provider
cmake -S . -B _build && cmake --build _build && cmake --install _build