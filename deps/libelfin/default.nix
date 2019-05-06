{ stdenv
, fetchurl, python3, git
# # , autoreconfHook, gettext
}:

# with import <nixpkgs> {};

stdenv.mkDerivation rec {
  name = "libelfin-0.3";
  src = fetchurl {
    url = "https://github.com/aclements/libelfin/archive/v0.3.tar.gz";
    sha256 = "1irs8i6q46gnivfr5nv8jqd0baaw2y9lpd8l6lmr50kmjqmr8f63";
  };

  configureFlags = [];  
  buildInputs = [ python3 git ];

  installPhase = ''
    make PREFIX=$out install
    echo "Hack regarding header paths:"
    cd "$out/include"
    ln -s ./libelfin/* ./;
    echo "Finished with header hack."
  '';
   
  meta = {
    description = "C++ interface for reading ELF files";
#    homepage = https://github.com/Distrotech/libelf;
#    license = stdenv.lib.licenses.lgpl2Plus;
    platforms = stdenv.lib.platforms.all;
    maintainers = [ ];
  };
}
