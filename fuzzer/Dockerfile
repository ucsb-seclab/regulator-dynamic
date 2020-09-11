FROM ubuntu:18.04 AS builder

RUN mkdir -p /opt/regulator

RUN apt-get update
RUN apt-get install -y git build-essential python3 python3-distutils

RUN mkdir -p /opt/regulator/src
RUN mkdir -p /opt/regulator/test
ADD Makefile /opt/regulator/
ADD copy_headers.py /opt/regulator/

WORKDIR /opt/regulator

RUN make node -j

ADD . /opt/regulator

RUN make -j

RUN strip -s -o build/fuzzer_stripped build/fuzzer

FROM ubuntu:18.04

WORKDIR /opt/regulator

COPY --from=builder /opt/regulator/build/fuzzer_stripped .
