#!/bin/sh

if [ "$EUID" -eq 0 ]
  then echo "\n    Please don't run as root/using sudo..."
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
  -o ${OUTDIR}/ed448_keygen \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf \
  "${SRCDIR}/ed448_keygen.c"

gcc -Wall \
  -o ${OUTDIR}/ed25519_keygen \
  -I${LIBDIR}/include \
  -L${LIBDIR} \
  -ldecaf \
  "${SRCDIR}/ed25519_keygen.c"
  