
# Option (1): Use the user's default environment
# with import <nixpkgs> { inherit system; };

# Option (2): Pinned, strategy:
with import (fetchTarball "https://github.com/NixOS/nixpkgs-channels/archive/nixos-19.03.tar.gz") {};

stdenv.mkDerivation {
  name = "dettrace";
  buildInputs = [
    clang
    libseccomp
    python3
    libarchive
    cpio
    pkgconfig
    openssl
  ];

  # Substract repo files that we don't actually need for the build:
  src = nix-gitignore.gitignoreSourcePure [ ./.nixignores ./.gitignore ] ./. ;

  buildPhase = ''
    make;
    pushd test/samplePrograms/;
    make -j;
    popd;
  '';
  installPhase = ''
    echo Copying dettrace binary;
    mkdir -p "$out/bin";
    cp bin/dettrace "$out/bin/";
    cp -a root "$out/root";
    cp -a test/samplePrograms "$out/samplePrograms";
  '';
}
