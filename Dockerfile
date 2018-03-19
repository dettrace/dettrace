FROM ubuntu:16.04

# Icky nondeterminism:
RUN apt-get update -y && \
    apt-get install -y g++ make strace python3 libseccomp-dev openssh-server

ADD ./ /detTrace/

RUN cd /detTrace/ && make

WORKDIR /detTrace/
