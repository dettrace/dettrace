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

#  doCheck = true;

  configureFlags = [];
       # Configure check for dynamic lib support is broken, see
       # http://lists.uclibc.org/pipermail/uclibc-cvs/2005-August/019383.html
#    ++ stdenv.lib.optional (stdenv.hostPlatform != stdenv.buildPlatform) "mr_cv_target_elf=yes"
       # Libelf's custom NLS macros fail to determine the catalog file extension
       # on Darwin, so disable NLS for now.
#    ++ stdenv.lib.optional stdenv.hostPlatform.isDarwin "--disable-nls";
  
   buildInputs = [ python3 git ];
#  nativeBuildInputs = [ gettext ]
       # Need to regenerate configure script with newer version in order to pass
       # "mr_cv_target_elf=yes", but `autoreconfHook` brings in `makeWrapper`
       # which doesn't work with the bootstrapTools bash, so can only do this
       # for cross builds when `stdenv.shell` is a newer bash.
#    ++ stdenv.lib.optional (stdenv.hostPlatform != stdenv.buildPlatform) autoreconfHook;

  installPhase = ''
    make PREFIX=$out install
  '';
   
  meta = {
    description = "C++ interface for reading ELF files";
#    homepage = https://github.com/Distrotech/libelf;
#    license = stdenv.lib.licenses.lgpl2Plus;
    platforms = stdenv.lib.platforms.all;
    maintainers = [ ];
  };
}
