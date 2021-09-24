package cert

import "context"

type CA interface {
	MakeCert(ctx context.Context, serial string, keyPem []byte) (string, error)
}
