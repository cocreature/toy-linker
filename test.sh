#!/usr/bin/env bash

cd examples
make
valgrind ./examples/main
cd ..
cargo run -- -i examples/lib.o -i examples/main.o -o foo
valgrind ./foo
