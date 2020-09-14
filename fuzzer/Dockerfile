FROM ubuntu:18.04 AS builder

RUN mkdir -p /opt/regulator

RUN apt-get update
RUN apt-get install -y git build-essential python3 python3-distutils

RUN mkdir -p /opt/regulator/src
RUN mkdir -p /opt/regulator/test
ADD Makefile /opt/regulator/
ADD copy_headers.py /opt/regulator/

WORKDIR /opt/regulator

RUN make node -j2

ADD . /opt/regulator

RUN make -j2

FROM ubuntu:18.04

WORKDIR /opt/regulator

RUN apt-get update && apt-get install -y python3 python3-distutils python3-psycopg2

COPY --from=builder /opt/regulator/build/fuzzer_stripped .

ADD main.py /opt/regulator

ADD requirements.txt /opt/regulator

