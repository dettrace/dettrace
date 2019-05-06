{ system ? builtins.currentSystem }:

let
  # pkgs = import <nixpkgs> { inherit system; };
  # Alternative pinned, strategy:
  pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs-channels/archive/nixos-19.03.tar.gz") {};

in
rec {
  libelfin = import ./deps/libelfin {
    inherit (pkgs) stdenv fetchurl python3 git;
  };
  
  dettrace = import ./dettrace.nix {
    # Use custom pkgconfig and gpm packages as dependencies
    inherit libelfin;
    # The remaining dependencies come from Nixpkgs
    inherit (pkgs) stdenv clang gnumake less libseccomp python3 libarchive cpio pkgconfig openssl libelf;
  };
}
