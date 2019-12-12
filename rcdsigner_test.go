package factom_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/Factom-Asset-Tokens/factom/varintf"

	"github.com/stretchr/testify/assert"

	. "github.com/Factom-Asset-Tokens/factom"
)

func TestValidateRCD0e(t *testing.T) {
	fmt.Printf("%x\n", varintf.Encode(14))
	fmt.Println(varintf.Decode([]byte{0x0e}))
}

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

// These are vectors taken from the etheruem repo
func TestValidateRCD0eVectors(t *testing.T) {
	assert := assert.New(t)

	// Vector from
	// https://github.com/ethereum/go-ethereum/blob/f03b2db7db123a569672b0caed5c1cd735c72ba7/crypto/signature_test.go#L31-L34
	testmsg, _ := hex.DecodeString("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	testsig, _ := hex.DecodeString("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
	testpubkey, _ := hex.DecodeString("e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")

	valid, err := ValidateRCD0e(append([]byte{0x0e}, testpubkey[:]...), testsig, testmsg)
	assert.NoError(err)
	assert.False(valid.IsZero())

	// TestVerifySignatureMalleable Vector from
	// https://github.com/ethereum/go-ethereum/blob/f03b2db7db123a569672b0caed5c1cd735c72ba7/crypto/signature_test.go#L80-L82
	testsig, _ = hex.DecodeString("638a54215d80a6713c8d523a6adc4e6e73652d859103a36b700851cb0e61b66b8ebfc1a610c57d732ec6e0a8f06a9a7a28df5051ece514702ff9cdff0b11f454")
	testsig = append(testsig, 0) // Make it 65 bytes

	testpubkeyC, _ := hex.DecodeString("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138")
	ecdsaPub, err := crypto.DecompressPubkey(testpubkeyC)
	assert.NoError(err)
	testpubkey = crypto.FromECDSAPub(ecdsaPub)

	testmsg, _ = hex.DecodeString("d301ce462d3e639518f482c7f03821fec1e602018630ce621e1e7851c12343a6")
	if !crypto.VerifySignature(testpubkey[:], testmsg, testsig) {
		t.Errorf("VerifySignature returned true for malleable signature")
	}

	// Our function runs the sha256d hash function on the msg data.
	//valid, err = ValidateRCD0e(append([]byte{0x0e}, testpubkey[:]...), testsig, testmsg)
	//if err == nil {
	//	t.Errorf("VerifySignature returned true for malleable signature")
	//}
}

// generateVector prints out all the fields needed to check an implementation.
func generateVector() {
	s, _ := GenerateEthSecret()
	fmt.Printf("%20s: %s\n", "Private Key", s)
	fmt.Printf("%20s: 0x%x\n", "Public Key", s.PublicKeyBytes())
	fmt.Printf("%20s: %s\n", "FAAddress", s.FAAddress())
	fmt.Printf("%20s: %s\n", "EthAddress", s.EthAddress())
	fmt.Println()
	fmt.Printf("%20s: %x\n", "Digest", make([]byte, 32))
	fmt.Printf("%20s: %x\n", "Signature", s.Sign(make([]byte, 32)))
}

func rcdFields(adr RCDSigner) (rcd []byte, sig []byte, msg []byte, flag int) {
	msg = make([]byte, 32)
	_, _ = crand.Read(msg)

	sig = adr.Sign(msg)
	rcd = adr.RCD()
	flag = R_ALL
	return
}
