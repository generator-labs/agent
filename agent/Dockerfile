FROM alpine:3 AS builder
RUN apk add --no-cache build-base cmake pkgconf jansson-dev openssl-dev curl-dev util-linux-dev
WORKDIR /src
COPY . .
RUN cmake -B build && cmake --build build -j$(nproc) || cmake --build build -j1

FROM alpine:3
RUN apk add --no-cache libstdc++ libgcc libcurl jansson openssl libuuid ca-certificates && \
    adduser -D -H agent
WORKDIR /app
COPY --from=builder /src/build/agent .
USER agent
STOPSIGNAL SIGTERM
CMD ["./agent"]
