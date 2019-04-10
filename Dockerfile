FROM golang:1.12 as build

WORKDIR /build
ADD . /build
RUN CGO_ENABLED=0 go build -o clang-in-the-cloud -a -ldflags '-extldflags "-static"' server/server.go

FROM alpine:3.7
RUN apk add --no-cache clang libc6-compat ca-certificates openjdk8-jre-base
COPY --from=build /build/clang-in-the-cloud /opt/clang-in-the-cloud
ADD server/*.html /opt/
ADD server/static/ /opt/static/
ADD https://github.com/google/google-java-format/releases/download/google-java-format-1.5/google-java-format-1.5-all-deps.jar /opt/google-java-format-1.5.jar
Add clang-formatter.2019-04-10.private-key.pem.enc /opt
WORKDIR /opt

CMD ["/opt/clang-in-the-cloud", "-verify", "false"]
