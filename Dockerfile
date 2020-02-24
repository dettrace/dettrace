# STAGE 1: Build the tool.
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -qq update && apt-get install -y \
    clang++-6.0 \
    clang-6.0 \
    clang-format-6.0 \
    clang-tidy-6.0 \
    cpio \
    fuse \
    git \
    less \
    libacl1-dev \
    libarchive-dev \
    libbz2-dev \
    libfuse-dev \
    liblz4-dev \
    liblzma-dev \
    liblzo2-dev \
    libseccomp-dev \
    libssl-dev \
    libxml2-dev \
    lld-6.0 \
    lldb-6.0 \
    make \
    nettle-dev \
    openssh-server \
    pkg-config \
    python3 \
    software-properties-common \
    strace \
    sudo \
    valgrind

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-6.0 60 \
    --slave /usr/bin/clang++ clang++ /usr/bin/clang++-6.0 \
    --slave /usr/bin/clang-cpp clang-cpp /usr/bin/clang-cpp-6.0 \
    --slave /usr/bin/lldb lldb /usr/bin/lldb-6.0 \
    --slave /usr/bin/clang-format clang-format /usr/bin/clang-format-6.0 \
    --slave /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-6.0

WORKDIR /code

ADD ./ ./

ARG BUILDID=0

RUN make -j deb "BUILDID=${BUILDID}"

# STAGE 2:
# Copy only the deployment files into the final image:
FROM ubuntu:18.04
RUN apt-get update -y && apt-get install -y python3 bsdmainutils dnsutils curl

COPY --from=0 /code/*.deb /root/
RUN dpkg --install /root/*.deb
WORKDIR /usr/share/dettrace/examples

RUN echo 'export PS1="\w \[\033[1;36m\]$ \[\033[0m\]"' >> /root/.bashrc
