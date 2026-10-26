# Reproducible build for benchmark sample P09b (libredwg @ 93c2512), binary: dwg2dxf
# Build:  docker build -t agenticsec/p09b-libredwg .
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make git ca-certificates autoconf automake libtool pkg-config \
        texinfo perl binutils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/LibreDWG/libredwg.git . && \
    git checkout 93c25124c191987af168ace9fe4b5623061874bd
COPY build.sh /build.sh
RUN chmod +x /build.sh && /build.sh
