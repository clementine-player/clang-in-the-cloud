FROM golang:1.10 as build

WORKDIR /build
ENV GOPATH /go
COPY server.go /go/src/github/clementine-player/clang-in-the-cloud/
RUN go get github.com/clementine-player/clang-in-the-cloud
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' github.com/clementine-player/clang-in-the-cloud

FROM alpine:3.7
RUN apk add --no-cache clang libc6-compat ca-certificates
COPY --from=build /go/bin/clang-in-the-cloud /opt/clang-in-the-cloud
ADD diff_template.html /opt/
WORKDIR /opt

CMD ["/opt/clang-in-the-cloud", "-address", "0.0.0.0"]
