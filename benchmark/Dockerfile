# Builds one benchmark sample's binaries with build.sh (run from the repo root):
#   docker build -t p10 --build-arg SAMPLE=P10_faad2_1073aee benchmark
#   docker run --rm -v "$PWD/artifacts:/out" p10 cp -r /artifacts/. /out
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make git ca-certificates autoconf automake libtool pkg-config \
        texinfo perl binutils && \
    rm -rf /var/lib/apt/lists/*
ARG SAMPLE
COPY build.sh /build.sh
RUN bash /build.sh "$SAMPLE"
