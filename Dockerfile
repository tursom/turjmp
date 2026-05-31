FROM node:24-alpine3.22 AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/turjmp ./cmd/turjmp

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/turjmp /usr/local/bin/turjmp
COPY --from=build /src/migrations /migrations
COPY --from=web-build /src/web/dist /usr/share/turjmp/web
ENV TURJMP_WEB_DIST=/usr/share/turjmp/web
ENTRYPOINT ["turjmp"]
