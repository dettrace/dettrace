FROM ubuntu:18.04

# Icky nondeterminism:
RUN apt-get update -y && \
    apt-get install -y seccomp openssh-server

COPY bin/dettrace /usr/bin/det
COPY lib/libdet.so /usr/lib/libdet.so
