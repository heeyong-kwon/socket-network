#!/bin/bash

apt update && apt upgrade -y
apt install vim screen -y
apt install git wget build-essential checkinstall zlib1g-dev -y
# For liboqs
apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind -y
apt install python3 python3-pip python3-dev python3-venv -y

# Install OpenSSL >= version 3.3
OPENSSL_VERSION=3.3.0
OPENSSL_FILE="openssl-$OPENSSL_VERSION.tar.gz"
OPENSSL_PATH=/usr/local/ssl

if [ ! -f $OPENSSL_FILE ]; then
    wget https://www.openssl.org/source/$OPENSSL_FILE --no-check-certificate
else
    echo "The $OPENSSL_FILE already exists. Skip download."
fi
tar -xvzf $OPENSSL_FILE
# rm -rf $OPENSSL_FILE
cd openssl-$OPENSSL_VERSION
./Configure --prefix=$OPENSSL_PATH --openssldir=$OPENSSL_PATH
make -j$(nproc)
make install
STRING="export PATH=$OPENSSL_PATH/bin:$PATH"
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
STRING="export LD_LIBRARY_PATH=$OPENSSL_PATH/lib:$LD_LIBRARY_PATH"
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
source ~/.bashrc
cd ..

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
# cmake -S . -B _build && cmake --build _build && cmake --install _build
liboqs_DIR=../liboqs cmake -DOPENSSL_ROOT_DIR=$OPENSSL_PATH -S . -B _build && cmake --build _build && cmake --install _build
cd ..
cp rp5_openssl.cnf $OPENSSL_PATH/openssl.cnf
STRING="export OPENSSL_CONF=$OPENSSL_PATH/openssl.cnf"
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
STRING="alias python=python3"
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
STRING='export OPENSSL_MODULES=/usr/lib/aarch64-linux-gnu/ossl-modules'
grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
