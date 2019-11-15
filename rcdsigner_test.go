package factom_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/Factom-Asset-Tokens/factom"
)

func TestValidateRCD(t *testing.T) {
	// Tests random created addresses creates signatures that pass
	// validation and generate the expected rcdhash

	t.Run("rcd1", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			assert := assert.New(t)
			adr, err := GenerateFsAddress()
			assert.NoError(err)

			valid, err := ValidateRCD(rcdFields(adr))
			assert.NoError(err)
			rcdHash := adr.FAAddress()
			assert.Equal(rcdHash[:], valid[:])
		}
	})

	t.Run("rcd-e", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			assert := assert.New(t)
			adr, err := GenerateEthSecret()
			assert.NoError(err)

			valid, err := ValidateRCD(rcdFields(adr))
			assert.NoError(err)
			rcdHash := adr.FAAddress()
			assert.Equal(rcdHash[:], valid[:])
		}
	})
}

func rcdFields(adr RCDSigner) (rcd []byte, sig []byte, digest []byte) {
	digest = make([]byte, 32)
	_, _ = crand.Read(digest)

	sig = adr.Sign(digest)
	rcd = adr.RCD()
	return
}
