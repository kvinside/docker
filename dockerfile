FROM golang:1.26

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

EXPOSE 9000

CMD ["go", "run", "main.go"]
