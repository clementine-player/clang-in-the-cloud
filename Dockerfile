FROM golang:1.10 as build

WORKDIR /build
ENV GOPATH /go
ADD . /go/src/github.com/clementine-player/clang-in-the-cloud/
RUN go get github.com/clementine-player/clang-in-the-cloud/server
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' github.com/clementine-player/clang-in-the-cloud/server

FROM alpine:3.7
RUN apk add --no-cache clang libc6-compat ca-certificates openjdk8-jre-base
COPY --from=build /go/bin/server /opt/clang-in-the-cloud
ADD server/*.html /opt/
ADD server/static/ /opt/static/
ADD https://github.com/google/google-java-format/releases/download/google-java-format-1.5/google-java-format-1.5-all-deps.jar /opt/google-java-format-1.5.jar
WORKDIR /opt

CMD ["/opt/clang-in-the-cloud", "-address", "0.0.0.0"]
