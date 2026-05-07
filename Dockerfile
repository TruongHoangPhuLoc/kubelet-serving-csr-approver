# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/kubelet-csr-approver \
    ./cmd/kubelet-csr-approver

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /out/kubelet-csr-approver /kubelet-csr-approver
USER 65532:65532
ENTRYPOINT ["/kubelet-csr-approver"]
