ARG DOCKER_HUB="docker.io"

FROM ${DOCKER_HUB}/alpine:3.22 AS builder

RUN apk add --no-cache go git build-base olm-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o matrix-line ./cmd/matrix-line

FROM ${DOCKER_HUB}/alpine:3.22

ENV UID=1337 \
    GID=1337

RUN apk add --no-cache ffmpeg su-exec ca-certificates bash jq curl yq-go olm

COPY --from=builder /build/matrix-line /usr/bin/matrix-line
COPY ./docker-run.sh /docker-run.sh
RUN chmod +x /docker-run.sh
ENV BRIDGEV2=1
VOLUME /data
WORKDIR /data

CMD ["/docker-run.sh"]
