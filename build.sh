#!/bin/sh
CD=$(dirname "$0")
OUTDIR="${CD}/out"
LIBDIR="${CD}/lib/ed448goldilocks/macos-10.14.6-x64"
mkdir -p ${OUTDIR}
gcc -Wall -o ${OUTDIR}/ed448_keygen -I${LIBDIR}/include -L${LIBDIR} -ldecaf "${CD}/ed448_keygen.c"
gcc -Wall -o ${OUTDIR}/ed25519_keygen -I${LIBDIR}/include -L${LIBDIR} -ldecaf "${CD}/ed25519_keygen.c"
