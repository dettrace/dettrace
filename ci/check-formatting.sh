#!/bin/sh

# Checks the format for a single file.
exec clang-format "$1" | diff -u "$1" -
