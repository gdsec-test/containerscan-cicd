FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/alpine-golang:1.15-alpine-3.12

ENV CONTAINERSCAN_VERSION 1.0.5
ENV SCAN_ENV prod

USER root

RUN rm /usr/local/go/src/crypto/tls/testdata/example-key.pem

RUN mkdir /app
## We copy everything in the root directory
## into our /app directory
ADD . /app
## We specify that we now wish to execute
## any further commands inside our /app
## directory
WORKDIR /app
## we run go build to compile the binary
## executable of our Go program
RUN go build -o main .
## Our start command which kicks off
## our newly created binary executable

RUN chmod -R a+rwxX /app

USER worker

CMD "/app/main" "$CONTAINER" "${SCANNER_STATUS:-${PAT}}" "$TARGET_URL" "$GITHUB_URL" "$GITHUB_REPO" "$COMMIT_SHA"
