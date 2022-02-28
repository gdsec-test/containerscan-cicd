FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/alpine-golang:1.17-alpine-3.14


WORKDIR /home


USER root

RUN rm /usr/local/go/src/crypto/tls/testdata/example-key.pem

RUN adduser -S appuser
USER appuser
