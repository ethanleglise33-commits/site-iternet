# ---- Build stage ----
FROM golang:1.22 AS build

WORKDIR /app

# Copier go.mod ET go.sum
COPY go.mod go.sum ./

# Télécharger les dépendances
RUN go mod download

# Copier tout le code
COPY . .

# Compiler en binaire statique Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server .

# ---- Runtime stage ----
FROM gcr.io/distroless/base-debian12

WORKDIR /app

# Copier le binaire compilé
COPY --from=build /app/server /app/server

# Copier les templates
COPY --from=build /app/templates /app/templates

# Render utilise la variable PORT automatiquement
EXPOSE 8080

CMD ["/app/server"]