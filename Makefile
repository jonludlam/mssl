.PHONY: all clean install build uninstall
all: build

BINDIR ?= /usr/bin

export OCAMLRUNPARAM=b

build: dist/setup
	obuild build

dist/setup: mssl.obuild
	obuild configure

clean:
	@obuild clean
