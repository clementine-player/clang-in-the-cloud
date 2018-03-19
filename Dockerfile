FROM golang:1.10 as build

WORKDIR /build
ENV GOPATH /go
ADD . /go/src/github.com/clementine-player/clang-in-the-cloud/
RUN go get github.com/clementine-player/clang-in-the-cloud/server
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' github.com/clementine-player/clang-in-the-cloud/server

FROM alpine:3.7
RUN apk add --no-cache clang libc6-compat ca-certificates
COPY --from=build /go/bin/server /opt/clang-in-the-cloud
ADD server/*.html /opt/
ADD server/static/ /opt/
WORKDIR /opt

CMD ["/opt/clang-in-the-cloud", "-address", "0.0.0.0"]
