FROM golang:1.9 as build

WORKDIR /build/clang-in-the-cloud
COPY server.go /build/clang-in-the-cloud
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' .

FROM alpine:3.7
RUN apk add --no-cache clang
COPY --from=build /build/clang-in-the-cloud/clang-in-the-cloud /opt/clang-in-the-cloud

CMD ["/opt/clang-in-the-cloud"]
