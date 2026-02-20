# ---- Build Stage ----
FROM quay.io/centos/centos:stream10 AS builder

RUN dnf install -y golang git && dnf clean all

WORKDIR /src
COPY go.mod go.sum ./
# Download dependencies with GOTOOLCHAIN=local to use the installed Go version
# (go.mod may reference a Red Hat-specific version string)
RUN GOTOOLCHAIN=local go mod download

COPY . .
RUN GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /puppet-ca     ./cmd/puppet-ca/ && \
    go build -ldflags="-s -w" -o /puppet-ca-ctl ./cmd/puppet-ca-ctl/

# ---- Runtime Stage ----
FROM quay.io/centos/centos:stream10

# curl: health checks and agent CSR submission
# openssl: CSR generation and cert verification in integration tests
RUN dnf install -y curl openssl && dnf clean all && \
    useradd -m puppet && \
    mkdir -p /etc/puppetlabs/puppet/ssl/ca /data && \
    chown -R puppet:puppet /etc/puppetlabs/puppet /data

COPY --from=builder /puppet-ca     /usr/local/bin/puppet-ca
COPY --from=builder /puppet-ca-ctl /usr/local/bin/puppet-ca-ctl

USER puppet
EXPOSE 8140

# --cadir      : where CA state is stored
# --autosign-config=true : sign all incoming CSRs immediately (dev/test only)
# -v=1         : debug logging
ENTRYPOINT ["/usr/local/bin/puppet-ca"]
CMD ["--cadir=/etc/puppetlabs/puppet/ssl/ca", \
     "--autosign-config=true", \
     "-v=1"]
