# Build dettrace itself as a nix package.
{ stdenv,
  # Custom dependency:
  libelfin,
  # Standard dependencies:
  clang, gnumake, less, libseccomp, python3, libarchive, cpio, pkgconfig, openssl, libelf  
}:

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
    libelf
    libelfin  
  ];

  src = ./. ;

  buildPhase = ''
    make
  '';  
  installPhase = ''
    echo Copying dettrace binary;
    mkdir -p "$out/bin";
    cp bin/dettrace "$out/bin/";
  '';  
}
