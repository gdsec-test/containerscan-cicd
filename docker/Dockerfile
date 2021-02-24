# FROM 764525110978.dkr.ecr.us-east-1.amazonaws.com/alpine-golang:1.15-alpine
FROM golang:alpine




RUN apk add git

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

# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# USER appuser

ENTRYPOINT /app/main $CONTAINER
# CMD /app/main $AK $SI $CONTAINER













