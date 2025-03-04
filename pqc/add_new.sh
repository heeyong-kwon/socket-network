#!/bin/bash

# Copy new files to each liboqs and oqs-provider directories
cp -r ./add_new/* ../../

# Move to the liboqs directory
cd ../../liboqs/

# Build liboqs
mkdir build
cd build
cmake -GNinja ..
ninja
cd ..
cmake -S . -B _build && cmake --build _build && cmake --install _build
cd ..

# Move to the oqs-provider directory
cd ./oqs-provider/

# Build oqs-provider
liboqs_DIR=../liboqs cmake -DOPENSSL_ROOT_DIR=$OPENSSL_PATH -S . -B _build && cmake --build _build && cmake --install _build
cd ..

