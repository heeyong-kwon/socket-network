
# Base image
FROM arm64v8/ubuntu:latest

# Install apt packages
RUN apt update && apt upgrade -y
RUN apt install vim screen -y
RUN apt install git wget build-essential checkinstall zlib1g-dev -y
# For liboqs
RUN apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind -y
RUN apt install python3 python3-pip python3-dev python3-venv -y
# Clean cache
RUN rm -rf /var/lib/apt/lists/*


# OpenSSL installation
ENV OPENSSL_VERSION=3.3.0
ENV OPENSSL_FILE="openssl-${OPENSSL_VERSION}.tar.gz"
ENV OPENSSL_PATH=/usr/local/ssl

WORKDIR /home
RUN if [ ! -f ${OPENSSL_FILE} ]; then \
    wget https://www.openssl.org/source/${OPENSSL_FILE} --no-check-certificate; \
    else \
        echo "The $OPENSSL_FILE already exists. Skip download."; \
    fi \
    && tar -xvzf ${OPENSSL_FILE} \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=$OPENSSL_PATH --openssldir=$OPENSSL_PATH \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf ${OPENSSL_FILE}

# RUN STRING="export PATH=$OPENSSL_PATH/bin:$PATH"
# RUN grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
# RUN STRING="export LD_LIBRARY_PATH=$OPENSSL_PATH/lib:$LD_LIBRARY_PATH"
# RUN grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc
# RUN source ~/.bashrc

ENV PATH=${OPENSSL_PATH}/bin:${PATH}
ENV LD_LIBRARY_PATH=${OPENSSL_PATH}/lib:${LD_LIBRARY_PATH}

# liboqs installation
RUN if [ ! -d "liboqs" ]; then \
        git clone https://github.com/open-quantum-safe/liboqs.git; \
    else \
        echo "The liboqs already exists. Skip Git clone."; \
    fi \
    && cd liboqs \
    && mkdir build \
    && cd build \
    && cmake -GNinja .. \
    && ninja \
    && cd .. \
    && cmake -S . -B _build && cmake --build _build && cmake --install _build \
    && cd ..


# Install oqs-provider
RUN if [ ! -d "oqs-provider" ]; then \
        git clone https://github.com/open-quantum-safe/oqs-provider.git; \
    else \
        echo "The oqs-provider already exists. Skip Git clone."; \
    fi \
    && cd oqs-provider \
    && liboqs_DIR=../liboqs cmake -DOPENSSL_ROOT_DIR=${OPENSSL_PATH} -S . -B _build && cmake --build _build && cmake --install _build \
    && cd ..

COPY rp5_openssl.cnf ${OPENSSL_PATH}/openssl.cnf
# RUN STRING="export OPENSSL_CONF=${OPENSSL_PATH}/openssl.cnf" \
#     && grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc \
#     && STRING="alias python=python3" \
#     && grep -qxF "$STRING" ~/.bashrc || echo "$STRING" >> ~/.bashrc

ENV OPENSSL_CONF=${OPENSSL_PATH}/openssl.cnf
ENV alias python=python3

# Set default command
CMD ["/bin/bash"]