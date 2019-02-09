#!/usr/bin/env bash

if [ -f libsodium.so]; then
    sudo mv libsodium.so /usr/local/lib/libsodium.so
fi

if [ ! -f /usr/local/lib/libsodium.so ]; then
    mkdir libsodium
    tar xf .circleci/deps/libsodium.tar.gz -C ./libsodium/ --strip-components=1
    cd libsodium; ./autogen.sh; ./configure; make; sudo make install
else
    echo "Libsodium cache hit"
fi
