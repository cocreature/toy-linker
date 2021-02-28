{pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/536fe36e23ab0fc8b7f35c24603422eee9fc17a2.tar.gz") {}
}:
with pkgs;

stdenv.mkDerivation {
  name = "env";
  nativeBuildInputs = [
    rustc cargo rls racer pkgconfig
#    clang
#    llvm
#    gdb
    gcc
#    lldb
  ];
  buildInputs = [
  ];
}
