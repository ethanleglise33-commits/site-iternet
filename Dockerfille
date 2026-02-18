FROM golang:1.22 AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server .

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /app/server /app/server
COPY --from=build /app/templates /app/templates
ENV ADDR=:8080
ENV DB_PATH=/app/data/app.db
EXPOSE 8080
CMD ["/app/server"]