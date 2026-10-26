# Reproducible build for benchmark sample P09a (libredwg @ 5f99814), binary: dwg2SVG
# Build:  docker build -t agenticsec/p09a-libredwg .
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make git ca-certificates autoconf automake libtool pkg-config \
        texinfo perl binutils && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/LibreDWG/libredwg.git . && \
    git checkout 5f998146dd695a8b4bfdbd21c233e42fbb94e90d
COPY build.sh /build.sh
RUN chmod +x /build.sh && /build.sh
