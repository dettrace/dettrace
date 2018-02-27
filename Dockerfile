FROM ubuntu:16.04

# Icky nondeterminism:
RUN apt-get update -y && \
    apt-get install -y g++ make strace python3

ADD ./ /detTrace/

RUN cd /detTrace/src && make && \
    mv /detTrace/src/dettrace /usr/bin/

WORKDIR /detTrace/
