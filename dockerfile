FROM golang:1.26

WORKDIR /app

COPY main.go .

CMD ["go", "run", "main.go"]

