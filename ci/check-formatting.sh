#!/bin/sh

if [ -z "$1" ]; then
    exit 0
fi

# Checks the format for a single file.
exec clang-format "$1" | diff -u "$1" -
