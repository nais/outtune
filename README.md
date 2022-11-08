# outtune

Utility to provide client certs for conditional access

## Generate new root CA

Run `go run ./cmd/outtune-api/main.go --local-ca-init` and copy the contents of `ca.key` and `ca.pem` to the
secret defined in GCP project `naisdevice-prod`.
