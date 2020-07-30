FROM ubuntu:18.04

RUN mkdir -p /opt/regulator

ADD . /opt/regulator

RUN apt-get update
RUN apt-get install -y git build-essential python3 python3-distutils
