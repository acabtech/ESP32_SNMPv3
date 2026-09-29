# tests/host — build the host-side test runner (no Arduino SDK, no hardware)

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -O2 -g
PY      ?= /tmp/pv/bin/python

SRC     := ../../src
INCLUDES := -I$(SRC) -I$(SRC)/ber -I$(SRC)/usm -Isoft -Ivec

OBJS := build/main.o build/test_soft.o build/test_ber.o build/test_usm.o \
        build/crypto_soft.o build/BER.o build/USM.o

all: build/test_runner

# Regenerate tables + vectors from the Python oracles (pysnmp/cryptography).
vectors:
	$(PY) vgen/gen_vectors.py

build/test_runner: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

build/%.o: %.c soft/crypto_soft.c vec/vectors.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/crypto_soft.o: soft/crypto_soft.c soft/sha256_k.inc soft/aes_tables.inc
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/BER.o: $(SRC)/ber/BER.c $(SRC)/ber/BER.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/USM.o: $(SRC)/usm/USM.c $(SRC)/usm/USM.h $(SRC)/usm/crypto.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf build

.PHONY: all vectors clean
.DEFAULT_GOAL := all