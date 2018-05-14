with (import <nixpkgs> { });

stdenv.mkDerivation {
  name = "dettrace";
  buildInputs = [
    fuse
    gcc
    gnumake
    less
    libseccomp
    python3
    strace
  ];
}
