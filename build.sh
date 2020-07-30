#!/bin/sh

if [ "$(id -u)" = 0 ]
  then echo "  Please don't run as root/using sudo..."
  exit
fi

REPO=$(dirname "$0")
SRCDIR="${REPO}/src"
OUTDIR="${REPO}/out"
LIBDIR="${REPO}/lib/ed448goldilocks/ubuntu20-x64"

case "$OSTYPE" in 
  *darwin*)
    LIBDIR="${REPO}/lib/ed448goldilocks/macos-10.14.6-x64"
    ;;
esac

if [ -d "${OUTDIR}" ]; then
  rm -r "${OUTDIR}"
fi

mkdir -p ${OUTDIR}

gcc -Wall \
  "${SRCDIR}/ed448_keygen.c" \
  -o "${OUTDIR}/ed448_keygen" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf

gcc -Wall \
  "${SRCDIR}/ed25519_keygen.c" \
  -o "${OUTDIR}/ed25519_keygen" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf

gcc -Wall \
  "${SRCDIR}/ed448_sign.c" \
  -o "${OUTDIR}/ed448_sign" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf

gcc -Wall \
  "${SRCDIR}/ed448_verify.c" \
  -o "${OUTDIR}/ed448_verify" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf

gcc -Wall \
  "${SRCDIR}/ed25519_sign.c" \
  -o "${OUTDIR}/ed25519_sign" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf

gcc -Wall \
  "${SRCDIR}/ed25519_verify.c" \
  -o "${OUTDIR}/ed25519_verify" \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf
