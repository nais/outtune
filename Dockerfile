FROM library/golang:1.16-alpine as builder

RUN apk add build-base

WORKDIR /build

COPY . /build

RUN make test

RUN make outtune-api

FROM library/alpine:3.13

COPY --from=builder /build/outtune-api /outtune-api

CMD ["/outtune-api"]