#!/usr/bin/env bash

if [ ! -f /usr/local/lib/libsodium.so ]; then
    tar -xf libsodium.tar.gz -C ./libsodium/
    cd libsodium; ./autogen.sh; ./configure; make; sudo make install
else
    echo "Libsodium cache hit"
fi
