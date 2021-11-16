package cert_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"os"
	"strings"
	"testing"

	"github.com/nais/outtune/pkg/cert"
	"github.com/stretchr/testify/assert"
)

func TestMakeCert(t *testing.T) {
	caCertFileName := "ca.pem"
	caKeyFileName := "ca.key"

	dir, err := os.MkdirTemp("", "outtune-unittest-dir")
	assert.NoError(t, err)
	if len(dir) > 0 && strings.Contains(dir, "/tmp/") {
		defer os.RemoveAll(dir)
	}

	err = os.Chdir(dir)
	assert.NoError(t, err)

	t.Logf("Working in temp dir: %s", dir)

	err = cert.LocalCAInit(caCertFileName, caKeyFileName)
	assert.NoError(t, err)

	certAndKeyPair, err := tls.LoadX509KeyPair(caCertFileName, caKeyFileName)
	assert.NoError(t, err)

	ca := cert.NewLocalCA(&certAndKeyPair)

	serial := "test-serial"

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)

	publicKeyPem, err := cert.PublicKeytoPem(&key.PublicKey)
	assert.NoError(t, err)

	cert, err := ca.MakeCert(context.TODO(), serial, []byte(publicKeyPem))
	assert.NoError(t, err)

	assert.True(t, len(cert) > 0)
}
