FROM golang:1.26

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

RUN go build -o app .

FROM debian:trixie-slim

WORKDIR /app

COPY --from=builder /app/app .

EXPOSE 9000

CMD ["./app"]
