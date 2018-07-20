
# Pin that sucker for reproducibility:
with (import (fetchTarball "https://github.com/NixOS/nixpkgs-channels/archive/nixos-18.03.tar.gz") {});

# OR use whatever the user makes default:
# with (import <nixpkgs> { });

stdenv.mkDerivation {
  name = "dettrace";
  buildInputs = [
    # fuse strace
    # gcc
    clang
    gnumake
    less
    libseccomp
    python3
    
    # For development/testing
    which
  ];
}
