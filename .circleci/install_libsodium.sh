#!/usr/bin/env bash

if [ ! -f /usr/local/lib/libsodium.so ]; then
    tar xf libsodium-1.0.13.tar.gz
    cd libsodium-1.0.13; ./configure; make; sudo make install
else
    echo "Libsodium cache hit"
fi
