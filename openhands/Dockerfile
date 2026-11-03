# Build once, retain the image by digest/ID, and use the same ID for both runs.
ARG BASE=debian:bookworm-slim
FROM ${BASE} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git gcc make autoconf automake libtool pkg-config \
    libonig-dev bison flex python3 binutils && rm -rf /var/lib/apt/lists/*
COPY build_jq.sh /build_jq.sh
RUN bash /build_jq.sh

# Export only the binary and evaluator-side build/symbol provenance.
FROM scratch AS binary
COPY --from=builder /export/ /

FROM ${BASE} AS tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    file binutils checksec gdb python3 python3-venv libonig5 coreutils \
    procps bash ca-certificates && rm -rf /var/lib/apt/lists/*
ARG ANGR_VERSION=9.2.180
RUN python3 -m venv /opt/analysis && \
    /opt/analysis/bin/pip install --no-cache-dir angr==${ANGR_VERSION}
ENV PATH="/opt/analysis/bin:${PATH}"
RUN mkdir /target /work && touch /target/jq && chmod 755 /target /work && \
    (dpkg-query -W; /opt/analysis/bin/pip freeze) > /tool-versions.txt
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
