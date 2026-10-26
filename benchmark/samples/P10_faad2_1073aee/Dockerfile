# Reproducible build for benchmark sample P10 (faad2 @ 1073aee), binary: faad
# Build:  docker build -t agenticsec/p10-faad2 .
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make git ca-certificates autoconf automake libtool pkg-config \
        binutils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/knik0/faad2.git . && \
    git checkout 1073aeef823cafd844704389e9a497c257768e2f
COPY build.sh /build.sh
RUN chmod +x /build.sh && /build.sh
