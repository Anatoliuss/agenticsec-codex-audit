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
# Keep apt lists until after the radare2 .deb is installed (apt resolves its deps).
RUN apt-get update && apt-get install -y --no-install-recommends \
    file binutils checksec gdb valgrind python3 python3-venv libonig5 coreutils \
    procps bash ca-certificates openjdk-17-jdk-headless unzip wget
# radare2 is no longer packaged in Debian bookworm; install the upstream amd64
# .deb (pinned release + verified hash). apt pulls in its runtime dependencies.
ARG RADARE2_VERSION=6.2.6
ARG RADARE2_SHA256=0dddf90e217e38a6a658881b9ec7e217198487c75b7f82a332b3cbd30834636f
RUN wget -q "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" -O /tmp/r2.deb && \
    echo "${RADARE2_SHA256}  /tmp/r2.deb" | sha256sum -c - && \
    apt-get install -y --no-install-recommends /tmp/r2.deb && \
    rm /tmp/r2.deb && rm -rf /var/lib/apt/lists/*
# Headless Ghidra (pinned release + verified hash). 11.0.3 is the last 11.x line
# that runs on JDK 17 (11.1+ require JDK 21, absent from Debian bookworm main).
ARG GHIDRA_VERSION=11.0.3
ARG GHIDRA_RELEASE=ghidra_11.0.3_PUBLIC_20240410
ARG GHIDRA_SHA256=2462a2d0ab11e30f9e907cd3b4aa6b48dd2642f325617e3d922c28e752be6761
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_RELEASE}.zip" -O /tmp/ghidra.zip && \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra && \
    printf '#!/bin/bash\nexec /opt/ghidra/support/analyzeHeadless "$@"\n' > /usr/local/bin/ghidra-headless && \
    chmod 755 /usr/local/bin/ghidra-headless && rm /tmp/ghidra.zip
ARG ANGR_VERSION=9.2.180
RUN python3 -m venv /opt/analysis && \
    /opt/analysis/bin/pip install --no-cache-dir angr==${ANGR_VERSION}
ENV PATH="/opt/analysis/bin:${PATH}"
RUN mkdir /target /work && touch /target/jq && chmod 755 /target /work && \
    (dpkg-query -W; /opt/analysis/bin/pip freeze; \
     echo "ghidra ${GHIDRA_VERSION}"; r2 -v 2>/dev/null | head -1) > /tool-versions.txt
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
