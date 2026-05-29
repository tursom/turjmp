FROM golang:1.26-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/turjmp ./cmd/turjmp

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/turjmp /usr/local/bin/turjmp
ENTRYPOINT ["turjmp"]
