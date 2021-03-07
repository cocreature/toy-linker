#!/usr/bin/env bash

cd examples
make
cd ..
cargo run -- -i examples/lib.o -i examples/main.o -o foo
./foo
