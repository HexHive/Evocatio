#!/bin/sh

set -e

apt update && \
        DEBIAN_FRONTEND=noninteractive apt install -y \
        jq \
        git \
        vim \
        wget \
        python3 \
        make \
        autoconf \
        automake \
        libtool \
	libssl-dev \
	sudo \
	build-essential \
	apt-transport-https \
	gnupg \
        software-properties-common \
	llvm \
	clang \
	pkg-config 
