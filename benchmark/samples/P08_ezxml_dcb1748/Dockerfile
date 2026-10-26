# Reproducible build for benchmark sample P08 (ezxml @ dcb1748), binary: ezxml
# Build:  docker build -t agenticsec/p08-ezxml .
# Extract: docker run --rm -v "$PWD/out:/out" agenticsec/p08-ezxml cp -r /artifacts/. /out
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make git ca-certificates binutils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/lxfontes/ezxml.git . && \
    git checkout dcb17484da2591e42c739598729fe5bdf687cca6
COPY build.sh /build.sh
RUN chmod +x /build.sh && /build.sh
