FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/alpine-golang:1.21-alpine-3.18 as build

ENV CONTAINERSCAN_VERSION 1.3.0
ENV SCAN_ENV prod

USER root

## We specify that we now wish to execute
## any further commands inside our /app
## directory. This directory is created
## if it doesn't already exist
WORKDIR /build

## We copy everything in the root directory
## into our /app directory
ADD . /build

## we run go build to compile the binary
## executable of our Go program
RUN rm /usr/local/go/src/crypto/tls/testdata/example-key.pem && \
    go build -trimpath -ldflags "-s -w" -o main . && \
    chmod -R a+rwxX /build && \
    echo "nobody:x:2000:2000:Nobody:/:" > passwd.minimal

FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/alpine:3.18
WORKDIR /app
COPY --from=build /build/passwd.minimal /etc/passwd
COPY --from=build /build/main /app/main
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER nobody
## Our start command which kicks off
## our newly created binary executable
# use ${SCANNER_STATUS:-github} ensures that if SCANNER_STATUS is not defined, it will default to "github"
# AWS_DEFAULT_REGION should be set as an environment variable
CMD /bin/sh -c '/app/main --container=$CONTAINER --status=${SCANNER_STATUS:-github} --githubtoken=$PAT --targeturl=$TARGET_URL --githuburl=$GITHUB_URL --repo=$GITHUB_REPO --commit=$COMMIT_SHA --format=${FORMAT:-table}'
