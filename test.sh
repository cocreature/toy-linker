#!/usr/bin/env bash
set -eou pipefail
cd examples
make
objdump -x main
cd ..
cargo run -- -i examples/lib.o -i examples/main.o -o foo
valgrind ./foo
