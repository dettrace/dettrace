# STAGE 1: Build the tool.

FROM ubuntu:18.04

# Icky nondeterminism:
RUN apt-get update -y && \
    apt-get install -y g++ make strace python3 libseccomp-dev openssh-server fuse libfuse-dev 

# RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update -y
RUN apt-get install -y software-properties-common clang-6.0 clang++-6.0 lldb-6.0 lld-6.0

RUN apt-get update -y
RUN apt-get install -y pkg-config libarchive-dev libacl1-dev liblzo2-dev liblzma-dev liblz4-dev libbz2-dev libxml2-dev libssl-dev

RUN apt-get update -y
RUN apt-get install -y cpio

RUN apt-get update -y
RUN apt-get install -y libelfin-dev

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-6.0 60 \
		--slave /usr/bin/clang++ clang++ /usr/bin/clang++-6.0 \
		--slave /usr/bin/clang-cpp clang-cpp /usr/bin/clang-cpp-6.0 \
		--slave /usr/bin/lldb lldb /usr/bin/lldb-6.0

# This is odd, where does the -lnettle dependence come from? -RN [2019.06.10]
RUN apt-get install -y nettle-dev rsync

# Lame attempt to improve caching, esp. re: examples:
ADD ./src      /detTrace/src
ADD ./include  /detTrace/include
ADD ./Makefile /detTrace/Makefile
ADD ./root     /detTrace/root

WORKDIR /detTrace/
RUN make -j build static

# ADD ./ /detTrace/
ADD ./initramfs.cpio /detTrace/initramfs.cpio
ADD ./package        /detTrace/package
RUN make -j package

# For now we just install everything under user:
RUN rsync -av ./package/ /usr/

# STAGE 2:
# Copy only the deployment files into the final image:
FROM ubuntu:18.04
RUN apt-get update -y && apt-get install -y python3 bsdmainutils dnsutils curl
RUN apt-get install -y fractalnow libarchive
COPY --from=0 /detTrace/package /alpha_pkg
RUN ln -s /alpha_pkg/bin/* /usr/bin/

WORKDIR /alpha_pkg/examples

RUN echo 'export PS1="\[\033[1;36m\]$ \[\033[0m\]"' >> /root/.bashrc
