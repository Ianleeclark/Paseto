#!/usr/bin/env bash

if [ ! -f /usr/local/lib/libsodium.so ]; then
    mkdir libsodium
    tar -xf ./libsodium/libsodium.tar.gz -C ./libsodium/ --strip-components=1
    cd libsodium; ./autogen.sh; ./configure; make; sudo make install
else
    echo "Libsodium cache hit"
fi
