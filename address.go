// MIT License
//
// Copyright 2018 Canonical Ledgers, LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

package factom

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// Notes: This file contains all types, interfaces, and methods related to
// Factom Addresses as specified by
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md
//
// There are four Factom address types, forming two pairs: public and private
// Factoid addresses, and public and private Entry Credit addresses. All
// addresses are a 32 byte payload encoded using base58check with various
// prefixes.

// FAAddress is a Public Factoid Address.
type FAAddress [sha256.Size]byte

// FsAddress is the secret key to a FAAddress.
type FsAddress [sha256.Size]byte

// EthSecret is the secret key to a FAAddress
// It uses rcd type 0x0e with ecdsa signing.
// TODO: To get the bitsize, you need to do `priv.Params().Bitsize`.
//		It is not in a constant.
type EthSecret [32]byte

// FeAddress is a Public Factoid Address using the rcde.
type FeAddress [sha256.Size]byte

// FeAddress is a Public Factoid Gateway Address using the rcde.
type FEGatewayAddress [sha256.Size]byte

// ECAddress is a Public Entry Credit Address.
type ECAddress [sha256.Size]byte

// EsAddress is the secret key to a ECAddress.
type EsAddress [sha256.Size]byte

// payloadPtr returns adr as *payload. This is syntactic sugar useful in other
// methods that leverage *payload.
func (adr *FAAddress) payload() *payload {
	return (*payload)(adr)
}
func (adr *FsAddress) payload() *payload {
	return (*payload)(adr)
}
func (adr *FeAddress) payload() *payload {
	return (*payload)(adr)
}
func (adr *FEGatewayAddress) payload() *payload {
	return (*payload)(adr)
}
func (adr *ECAddress) payload() *payload {
	return (*payload)(adr)
}
func (adr *EsAddress) payload() *payload {
	return (*payload)(adr)
}

var (
	faPrefixBytes = [...]byte{0x5f, 0xb1}
	fsPrefixBytes = [...]byte{0x64, 0x78}
	ecPrefixBytes = [...]byte{0x59, 0x2a}
	esPrefixBytes = [...]byte{0x5d, 0xb6}

	// RCD-e prefixes
	fePrefixBytes = [...]byte{0x62, 0xf4} // Fe...
	fEPrefixBytes = [...]byte{0x60, 0x28} // FE...
)

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x5f, 0xb1}.
func (FAAddress) PrefixBytes() Bytes {
	prefix := faPrefixBytes
	return prefix[:]
}

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x64, 0x78}.
func (FsAddress) PrefixBytes() Bytes {
	prefix := fsPrefixBytes
	return prefix[:]
}

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x62, 0xf4}.
func (FeAddress) PrefixBytes() Bytes {
	prefix := fePrefixBytes
	return prefix[:]
}

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x60, 0x28}.
func (FEGatewayAddress) PrefixBytes() Bytes {
	prefix := fEPrefixBytes
	return prefix[:]
}

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x59, 0x2a}.
func (ECAddress) PrefixBytes() Bytes {
	prefix := ecPrefixBytes
	return prefix[:]
}

// PrefixBytes returns the two byte prefix for the address type as a byte
// slice. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns []byte{0x5d, 0xb6}.
func (EsAddress) PrefixBytes() Bytes {
	prefix := esPrefixBytes
	return prefix[:]
}

const (
	faPrefixStr        = "FA"
	fsPrefixStr        = "Fs"
	fePrefixStr        = "Fe"
	feGatewayPrefixStr = "FE"
	ecPrefixStr        = "EC"
	esPrefixStr        = "Es"
)

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "FA".
func (FAAddress) PrefixString() string {
	return faPrefixStr
}

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "Fs".
func (FsAddress) PrefixString() string {
	return fsPrefixStr
}

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "Fe".
func (FeAddress) PrefixString() string {
	return fePrefixStr
}

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "FE".
func (FEGatewayAddress) PrefixString() string {
	return feGatewayPrefixStr
}

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "EC".
func (ECAddress) PrefixString() string {
	return ecPrefixStr
}

// PrefixString returns the two prefix bytes for the address type as an encoded
// string. Note that the prefix for a given address type is always the same and
// does not depend on the address value. Returns "Es".
func (EsAddress) PrefixString() string {
	return esPrefixStr
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr FAAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr FsAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr FeAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr FEGatewayAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr EthSecret) String() string {
	return "0x" + hex.EncodeToString(adr[:])
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr ECAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// String encodes adr into its human readable form: base58check with
// adr.PrefixBytes().
func (adr EsAddress) String() string {
	return adr.payload().StringWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr FAAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr FsAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr FeAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr FEGatewayAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr EthSecret) MarshalText() ([]byte, error) {
	return []byte(adr.String()), nil
}

// MarshalText encodes adr as a string using adr.String().
func (adr ECAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

// MarshalText encodes adr as a string using adr.String().
func (adr EsAddress) MarshalText() ([]byte, error) {
	return adr.payload().MarshalTextWithPrefix(adr.PrefixBytes())
}

const adrStrLen = 52

// GenerateFsAddress generates a secure random private Factoid address using
// crypto/rand.Random as the source of randomness.
func GenerateFsAddress() (FsAddress, error) {
	return generatePrivKey()
}

// GenerateEthSecret generates a secure random private Etheruem address using
// crypto/rand.Random as the source of randomness.
func GenerateEthSecret() (EthSecret, error) {
	return generatePrivKey()
}

// GenerateEsAddress generates a secure random private Entry Credit address
// using crypto/rand.Random as the source of randomness.
func GenerateEsAddress() (EsAddress, error) {
	return generatePrivKey()
}
func generatePrivKey() (key [sha256.Size]byte, err error) {
	var priv ed25519.PrivateKey
	if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return
	}
	copy(key[:], priv)
	return key, nil
}

// NewFAAddress attempts to parse adrStr into a new FAAddress.
func NewFAAddress(adrStr string) (adr FAAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// NewFsAddress attempts to parse adrStr into a new FsAddress.
func NewFsAddress(adrStr string) (adr FsAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// NewFeAddress attempts to parse adrStr into a new FeAddress.
func NewFeAddress(adrStr string) (adr FeAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// NewFEGatewayAddress attempts to parse adrStr into a new FEGatewayAddress.
func NewFEGatewayAddress(adrStr string) (adr FEGatewayAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// NewEthSecret attempts to parse adrStr into a new EthSecret.
func NewEthSecret(adrStr string) (adr EthSecret, err error) {
	err = adr.Set(adrStr)
	return
}

// NewECAddress attempts to parse adrStr into a new ECAddress.
func NewECAddress(adrStr string) (adr ECAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// NewEsAddress attempts to parse adrStr into a new EsAddress.
func NewEsAddress(adrStr string) (adr EsAddress, err error) {
	err = adr.Set(adrStr)
	return
}

// Set attempts to parse adrStr into adr.
func (adr *FAAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// Set attempts to parse adrStr into adr.
func (adr *FsAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// Set attempts to parse adrStr into adr.
func (adr *FeAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// Set attempts to parse adrStr into adr.
func (adr *FEGatewayAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// Set attempts to parse adrStr into adr.
// adrStr is in format 0x[64 character hex]
func (e *EthSecret) Set(adrStr string) error {
	// TODO: Payload code expects base 58. So this address type cannot
	//		use those generic functions
	if !has0xPrefix(adrStr) {
		return fmt.Errorf("exp 0x prefix")
	}
	if len(adrStr) != 66 { // 66 is 64 hex + 2 character prefix
		return fmt.Errorf("exp 64 hex characters")
	}
	secret, err := hex.DecodeString(adrStr[2:])
	if err != nil {
		return err
	}
	copy(e[:], secret)
	return nil
}

// Set attempts to parse adrStr into adr.
func (adr *ECAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// Set attempts to parse adrStr into adr.
func (adr *EsAddress) Set(adrStr string) error {
	return adr.payload().SetWithPrefix(adrStr, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable public Factoid address
// into adr.
func (adr *FAAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable secret Factoid address
// into adr.
func (adr *FsAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable public Factoid address
// for rcde into adr.
func (adr *FeAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable public Factoid address
// for rcde into adr. This adr is a gateway address
func (adr *FEGatewayAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable secret Factoid address
// into adr.
func (adr *EthSecret) UnmarshalText(text []byte) error {
	return adr.Set(string(text))
}

// UnmarshalText decodes a string with a human readable public Entry Credit
// address into adr.
func (adr *ECAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// UnmarshalText decodes a string with a human readable secret Entry Credit
// address into adr.
func (adr *EsAddress) UnmarshalText(text []byte) error {
	return adr.payload().UnmarshalTextWithPrefix(text, adr.PrefixString())
}

// GetFsAddress queries factom-walletd for the FsAddress corresponding to adr.
func (adr FAAddress) GetFsAddress(ctx context.Context, c *Client) (FsAddress, error) {
	var privAdr FsAddress
	err := c.getAddress(ctx, adr, &privAdr)
	return privAdr, err
}

func (adr FeAddress) GetEthSecret(ctx context.Context, c *Client) (EthSecret, error) {
	var privAdr EthSecret
	err := c.getAddress(ctx, adr, &privAdr)
	return privAdr, err
}

func (adr FEGatewayAddress) GetEthSecret(ctx context.Context, c *Client) (EthSecret, error) {
	var privAdr EthSecret
	err := c.getAddress(ctx, FeAddress(adr), &privAdr)
	return privAdr, err
}

// GetEsAddress queries factom-walletd for the EsAddress corresponding to adr.
func (adr ECAddress) GetEsAddress(ctx context.Context, c *Client) (EsAddress, error) {
	var privAdr EsAddress
	err := c.getAddress(ctx, adr, &privAdr)
	return privAdr, err
}

func (c *Client) getAddress(ctx context.Context, pubAdr, privAdr interface{}) error {
	params := struct{ Address interface{} }{Address: pubAdr}
	result := struct{ Secret interface{} }{Secret: privAdr}
	if err := c.WalletdRequest(ctx, "address", params, &result); err != nil {
		return err
	}
	return nil
}

// GetPrivateAddresses queries factom-walletd for all private addresses.
func (c *Client) GetPrivateAddresses(ctx context.Context) ([]FsAddress, []EsAddress, []EthSecret,
	error) {
	var result struct{ Addresses []struct{ Secret string } }
	if err := c.WalletdRequest(ctx, "all-addresses", nil, &result); err != nil {
		return nil, nil, nil, err
	}
	fss := make([]FsAddress, 0, len(result.Addresses))
	ess := make([]EsAddress, 0, len(result.Addresses))
	eths := make([]EthSecret, 0, len(result.Addresses))
	for _, adr := range result.Addresses {
		adrStr := adr.Secret
		if has0xPrefix(adrStr) {
			eth, err := NewEthSecret(adrStr)
			if err != nil {
				return nil, nil, nil, err
			}
			eths = append(eths, eth)
			continue
		}
		switch adrStr[:2] {
		case fsPrefixStr:
			fs, err := NewFsAddress(adrStr)
			if err != nil {
				return nil, nil, nil, err
			}
			fss = append(fss, fs)
		case esPrefixStr:
			es, err := NewEsAddress(adrStr)
			if err != nil {
				return nil, nil, nil, err
			}
			ess = append(ess, es)
		}
	}
	return fss, ess, eths, nil
}

// Save adr with factom-walletd.
func (adr FsAddress) Save(ctx context.Context, c *Client) error {
	return c.SavePrivateAddresses(ctx, adr.String())
}

func (adr EthSecret) Save(ctx context.Context, c *Client) error {
	return c.SavePrivateAddresses(ctx, adr.String())
}

// Save adr with factom-walletd.
func (adr EsAddress) Save(ctx context.Context, c *Client) error {
	return c.SavePrivateAddresses(ctx, adr.String())
}

// SavePrivateAddresses saves many adrs with factom-walletd.
func (c *Client) SavePrivateAddresses(ctx context.Context, adrs ...string) error {
	var params struct{ Addresses []struct{ Secret string } }
	params.Addresses = make([]struct{ Secret string }, len(adrs))
	for i, adr := range adrs {
		params.Addresses[i].Secret = adr
	}
	if err := c.WalletdRequest(ctx, "import-addresses", params, nil); err != nil {
		return err
	}
	return nil
}

// GetBalance queries factomd for the Factoid Balance for adr.
func (adr FAAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return c.getBalance(ctx, "factoid-balance", adr.String())
}

// GetBalance queries factomd for the Factoid Balance for adr.
func (adr FsAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return adr.FAAddress().GetBalance(ctx, c)
}

// GetBalance queries factomd for the Factoid Balance for adr.
func (adr FeAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return adr.FAAddress().GetBalance(ctx, c)
}

// GetBalance queries factomd for the Factoid Balance for adr.
func (adr FEGatewayAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return adr.FAAddress().GetBalance(ctx, c)
}

// GetBalance queries factomd for the Factoid Balance for adr.
func (adr EthSecret) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return adr.FAAddress().GetBalance(ctx, c)
}

// GetBalance queries factomd for the Entry Credit Balance for adr.
func (adr ECAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return c.getBalance(ctx, "entry-credit-balance", adr.String())
}

// GetBalance queries factomd for the Entry Credit Balance for adr.
func (adr EsAddress) GetBalance(ctx context.Context, c *Client) (uint64, error) {
	return adr.ECAddress().GetBalance(ctx, c)
}

func (c *Client) getBalance(ctx context.Context, method, adrStr string) (uint64, error) {
	params := struct {
		Address string `json:"address"`
	}{Address: adrStr}
	var result struct{ Balance uint64 }
	if err := c.FactomdRequest(ctx, method, params, &result); err != nil {
		return 0, err
	}
	return result.Balance, nil
}

// Remove adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (adr FAAddress) Remove(ctx context.Context, c *Client) error {
	return c.removeAddress(ctx, adr.String())
}

// Remove adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (adr FsAddress) Remove(ctx context.Context, c *Client) error {
	return adr.FAAddress().Remove(ctx, c)
}

// Remove adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (adr EthSecret) Remove(ctx context.Context, c *Client) error {
	panic("Not yet implemented") // TODO: Implement
	return nil
}

// Remove adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (adr ECAddress) Remove(ctx context.Context, c *Client) error {
	return c.removeAddress(ctx, adr.String())
}

// Remove adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (adr EsAddress) Remove(ctx context.Context, c *Client) error {
	return adr.ECAddress().Remove(ctx, c)
}

// removeAddress removes adr from factom-walletd. WARNING: THIS IS DESTRUCTIVE.
func (c *Client) removeAddress(ctx context.Context, adrStr string) error {
	params := struct{ Address string }{Address: adrStr}
	if err := c.WalletdRequest(ctx, "remove-address", params, nil); err != nil {
		return err
	}
	return nil
}

// FAAddress returns the FAAddress corresponding to adr.
func (adr FsAddress) FAAddress() FAAddress {
	return sha256d(adr.RCD())
}

// FAAddress returns the FAAddress corresponding to adr.
func (e EthSecret) FeAddress() FeAddress {
	return sha256d(e.RCD())
}

// FAAddress returns the FAAddress corresponding to adr.
func (e EthSecret) FAAddress() FAAddress {
	return sha256d(e.RCD())
}

// FAAddress returns the FAAddress corresponding to adr.
func (e FeAddress) FAAddress() FAAddress {
	return FAAddress(e)
}

// FAAddress returns the FAAddress corresponding to adr.
func (e FEGatewayAddress) FAAddress() FAAddress {
	return FAAddress(e)
}

// ECAddress returns the ECAddress corresponding to adr.
func (adr EsAddress) ECAddress() (ec ECAddress) {
	copy(ec[:], adr.PublicKey())
	return
}

// sha256(sha256(data))
func sha256d(data []byte) [sha256.Size]byte {
	hash := sha256.Sum256(data)
	return sha256.Sum256(hash[:])
}

// RCD computes the RCD for adr.
func (adr FsAddress) RCD() []byte {
	return append([]byte{RCDType01}, adr.PublicKey()[:]...)
}

func (s EthSecret) RCD() []byte {
	return append([]byte{RCDType0e}, s.PublicKeyBytes()...)
}

// Sign the msg.
func (adr FsAddress) Sign(msg []byte) []byte {
	return ed25519.Sign(adr.PrivateKey(), msg)
}

// Sign the msg.
func (adr EthSecret) Sign(msg []byte) []byte {
	// Ethereum uses Keccak256Hash to get the digest.
	// We will use sha256d
	digest := sha256d(msg)
	eth, err := crypto.Sign(digest[:], adr.PrivateKey())
	if err != nil {
		return nil
	}

	return eth
}

// PublicKey returns the ed25519.PublicKey for adr.
func (adr ECAddress) PublicKey() ed25519.PublicKey {
	return adr[:]
}

// PublicKey computes the ed25519.PublicKey for adr.
func (adr EsAddress) PublicKey() ed25519.PublicKey {
	return adr.PrivateKey().Public().(ed25519.PublicKey)
}

// PublicKey computes the ed25519.PublicKey for adr.
func (adr FsAddress) PublicKey() ed25519.PublicKey {
	return adr.PrivateKey().Public().(ed25519.PublicKey)
}

func (s EthSecret) PublicKey() ecdsa.PublicKey {
	secret := s.PrivateKey()
	if secret == nil {
		return ecdsa.PublicKey{}
	}
	return secret.PublicKey
}

// PublicKeyBytes returns the byte representation of the public key
func (s EthSecret) PublicKeyBytes() []byte {
	pub := s.PublicKey()
	bytes := crypto.FromECDSAPub(&pub)
	// Strip off the 0x04 prefix to indicate an uncompressed key.
	// You can find the prefix list here:
	// https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
	return bytes[1:]
}

// PrivateKey returns the ed25519.PrivateKey for adr.
func (adr FsAddress) PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(adr[:])
}

func (s EthSecret) PrivateKey() *ecdsa.PrivateKey {
	secret, err := crypto.ToECDSA(s[:])
	if err != nil {
		return nil
	}
	return secret
}

// PrivateKey returns the ed25519.PrivateKey for adr.
func (adr EsAddress) PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(adr[:])
}

// Extra EthSecret functions

// EthAddress returns the linked eth address
func (adr EthSecret) EthAddress() string {
	return crypto.PubkeyToAddress(adr.PublicKey()).String()
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}
