FROM ubuntu:18.04

RUN mkdir -p /opt/regulator

RUN apt-get update
RUN apt-get install -y git build-essential python3 python3-distutils

RUN mkdir -p /opt/regulator/src
RUN mkdir -p /opt/regulator/test
ADD Makefile /opt/regulator/
ADD copy_headers.py /opt/regulator/

WORKDIR /opt/regulator

RUN make node

ADD . /opt/regulator

RUN make
