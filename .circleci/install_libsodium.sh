#!/usr/bin/env bash

if [ ! -f /usr/local/lib/libsodium.so ]; then
    if [ ! -f ./libsodium*.tar.gz ]; then
        wget https://download.libsodium.org/libsodium/releases/old/libsodium-1.0.13.tar.gz
    fi

    tar xf libsodium-1.0.13.tar.gz
    cd libsodium-1.0.13; ./configure; make; sudo make install
else
    echo "Libsodium cache hit"
fi
