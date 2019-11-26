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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"crypto/ed25519"
)

// Entry represents a Factom Entry.
//
// Entry can be used to Get data when the Hash is known, or submit a new Entry
// to a given ChainID.
type Entry struct {
	// EBlock.Get populates the Hash, Timestamp, ChainID, and Height.
	Hash      *Bytes32  `json:"entryhash,omitempty"`
	Timestamp time.Time `json:"-"`
	ChainID   *Bytes32  `json:"chainid,omitempty"`

	// Entry.Get populates the Content and ExtIDs.
	ExtIDs  []Bytes `json:"extids"`
	Content Bytes   `json:"content"`
}

// IsPopulated returns true if e has already been successfully populated by a
// call to Get.
func (e Entry) IsPopulated() bool {
	return e.ExtIDs != nil &&
		e.Content != nil &&
		e.ChainID != nil
}

// Get populates e with the Entry data for its e.Hash.
//
// If e.Hash is nil, an error will be returned.
//
// After a successful call e.Content, e.ExtIDs, and e.ChainID  will be
// populated.
func (e *Entry) Get(c *Client) error {
	if e.IsPopulated() {
		return nil
	}

	if e.Hash == nil {
		return fmt.Errorf("Hash is nil")
	}

	params := struct {
		Hash *Bytes32 `json:"hash"`
	}{Hash: e.Hash}
	var result struct {
		Data Bytes `json:"data"`
	}

	if err := c.FactomdRequest("raw-data", params, &result); err != nil {
		return err
	}
	return e.UnmarshalBinary(result.Data)
}

type chainFirstEntryParams struct {
	Entry Entry `json:"firstentry"`
}
type composeChainParams struct {
	Chain chainFirstEntryParams `json:"chain"`
	EC    ECAddress             `json:"ecpub"`
}
type composeEntryParams struct {
	Entry Entry     `json:"entry"`
	EC    ECAddress `json:"ecpub"`
}

type composeJRPC struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}
type composeResult struct {
	Commit composeJRPC `json:"commit"`
	Reveal composeJRPC `json:"reveal"`
}
type commitResult struct {
	TxID *Bytes32
}

// Create queries factom-walletd to compose an entry, and then queries factomd
// to commit and reveal a new Entry or new Chain, if newChain is true.
//
// The given ec must exist in factom-walletd's keystore.
func (e Entry) Create(c *Client, ec ECAddress, newChain bool) (*Bytes32, error) {
	var params interface{}
	var method string

	if newChain {
		method = "compose-chain"
		params = composeChainParams{
			Chain: chainFirstEntryParams{Entry: e},
			EC:    ec,
		}
	} else {
		method = "compose-entry"
		params = composeEntryParams{Entry: e, EC: ec}
	}
	result := composeResult{}

	if err := c.WalletdRequest(method, params, &result); err != nil {
		return nil, err
	}
	if len(result.Commit.Method) == 0 {
		return nil, fmt.Errorf("Wallet request error: method: %#v", method)
	}

	var commit commitResult
	if err := c.FactomdRequest(
		result.Commit.Method, result.Commit.Params, &commit); err != nil {
		return nil, err
	}

	if err := c.FactomdRequest(
		result.Reveal.Method, result.Reveal.Params, e); err != nil {
		return nil, err
	}
	return commit.TxID, nil
}

// ComposeCreate calls e.Compose and then Commit and Reveals it to factomd.
//
// This does not make any calls to factom-walletd.
//
// The Factom Entry Transaction ID is returned. The e.Hash will be populated if
// not nil.
func (e *Entry) ComposeCreate(c *Client, es EsAddress, newChain bool) (*Bytes32, error) {
	commit, reveal, txID, err := e.Compose(es, newChain)
	if err != nil {
		return nil, err
	}

	if err := c.Commit(commit); err != nil {
		return txID, err
	}
	if err := c.Reveal(reveal); err != nil {
		return txID, err
	}

	return txID, nil
}

// Commit sends an entry or new chain commit to factomd.
func (c *Client) Commit(commit []byte) error {
	var method string
	switch len(commit) {
	case commitLen:
		method = "commit-entry"
	case chainCommitLen:
		method = "commit-chain"
	default:
		return fmt.Errorf("invalid length")
	}

	params := struct {
		Commit Bytes `json:"message"`
	}{Commit: commit}

	if err := c.FactomdRequest(method, params, nil); err != nil {
		return err
	}
	return nil
}

// Reveal reveals an entry or new chain entry to factomd.
func (c *Client) Reveal(reveal []byte) error {
	params := struct {
		Reveal Bytes `json:"entry"`
	}{Reveal: reveal}
	if err := c.FactomdRequest("reveal-entry", params, nil); err != nil {
		return err
	}
	return nil
}

const (
	commitLen = 1 + // version
		6 + // timestamp
		32 + // entry hash
		1 + // ec cost
		32 + // ec pub
		64 // sig
	chainCommitLen = 1 + // version
		6 + // timestamp
		32 + // chain id hash
		32 + // commit weld
		32 + // entry hash
		1 + // ec cost
		32 + // ec pub
		64 // sig
)

// Compose generates the commit and reveal data required to submit an entry to
// factomd.
//
// If e.Hash is nil, it will be populated.
//
// To compose the first entry in a new chain, you must set up the correct
// ChainID for the Entry by calling e.SetNewChainID before calling e.Compose
// with newChain to true.
func (e *Entry) Compose(es EsAddress, newChain bool) (
	commit []byte, reveal []byte, txID *Bytes32, err error) {
	reveal, err = e.MarshalBinary()
	if err != nil {
		return
	}

	size := commitLen
	if newChain {
		size = chainCommitLen
	}
	commit = make([]byte, size)

	i := 1 // Skip version byte

	// Timestamp in milliseconds.
	ms := time.Now().Unix()*1e3 + rand.Int63n(1000)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ms))
	i += copy(commit[i:], buf[2:]) // Omit the top 2 bytes.

	if e.Hash == nil {
		e.Hash = new(Bytes32)
		*e.Hash = ComputeEntryHash(reveal)
	}

	if newChain {
		// ChainID Hash
		chainIDHash := sha256d(e.ChainID[:])
		i += copy(commit[i:], chainIDHash[:])

		// Commit Weld sha256d(entryhash | chainid)
		weld := sha256d(append(e.Hash[:], e.ChainID[:]...))
		i += copy(commit[i:], weld[:])
	}

	// Entry Hash
	i += copy(commit[i:], e.Hash[:])

	// EntryCost will never error since e.MarshalBinary already did a
	// length check.
	cost, _ := EntryCost(len(reveal), newChain)
	commit[i] = byte(cost)
	i++

	txID = new(Bytes32)
	*txID = sha256.Sum256(commit[:i])

	// Public Key
	signedDataLen := i
	i += copy(commit[i:], es.PublicKey())

	// Signature
	sig := ed25519.Sign(es.PrivateKey(), commit[:signedDataLen])
	copy(commit[i:], sig)

	return
}

// SetNewChainID populates e.ChainID with a new(Bytes32) initialized to the
// result of ChainID(e.ExtIDs).
func (e *Entry) SetNewChainID() {
	e.ChainID = new(Bytes32)
	*e.ChainID = ChainID(e.ExtIDs)
}

// NewChainCost is the fixed added cost of creating a new chain.
const NewChainCost = 10

// EntryCost returns the required Entry Credit cost for an entry with encoded
// length equal to size. An error is returned if size exceeds 10275.
//
// Set newChain to true to add the NewChainCost.
func EntryCost(size int, newChain bool) (int8, error) {
	size -= EntryHeaderLen
	if size > 10240 {
		return 0, fmt.Errorf("Entry cannot be larger than 10KB")
	}
	cost := int8(size / 1024)
	if size%1024 > 0 {
		cost++
	}
	if cost < 1 {
		cost = 1
	}
	if newChain {
		cost += NewChainCost
	}
	return cost, nil
}

// Cost returns the EntryCost of e, using e.MarshalBinaryLen().
func (e Entry) Cost(newChain bool) (int8, error) {
	return EntryCost(e.MarshalBinaryLen(), newChain)
}

// MarshalBinaryLen returns the total encoded length of e.
func (e Entry) MarshalBinaryLen() int {
	extIDTotalLen := len(e.ExtIDs) * 2 // Two byte len(ExtID) per ExtID
	for _, extID := range e.ExtIDs {
		extIDTotalLen += len(extID)
	}
	return EntryHeaderLen + extIDTotalLen + len(e.Content)
}

// MarshalBinary returns the raw Entry data for e. This will return an error if
// !e.IsPopulated(). The data format is as follows.
//
//      [Version byte (0x00)] +
//      [ChainID (Bytes32)] +
//      [Total ExtID encoded length (uint16 BE)] +
//      [ExtID 0 length (uint16)] + [ExtID 0 (Bytes)] +
//      ... +
//      [ExtID X length (uint16)] + [ExtID X (Bytes)] +
//      [Content (Bytes)]
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#entry
func (e Entry) MarshalBinary() ([]byte, error) {
	if !e.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	totalLen := e.MarshalBinaryLen()
	if totalLen > EntryMaxTotalLen {
		return nil, fmt.Errorf("length exceeds %v", EntryMaxTotalLen)
	}

	// Header, version byte 0x00
	data := make([]byte, totalLen)
	i := 1
	i += copy(data[i:], e.ChainID[:])
	binary.BigEndian.PutUint16(data[i:i+2],
		uint16(totalLen-len(e.Content)-EntryHeaderLen))
	i += 2

	// Payload
	for _, extID := range e.ExtIDs {
		n := len(extID)
		binary.BigEndian.PutUint16(data[i:i+2], uint16(n))
		i += 2
		i += copy(data[i:], extID)
	}
	copy(data[i:], e.Content)
	return data, nil
}

// EntryHeaderLen is the exact length of an Entry header.
const EntryHeaderLen = 1 + // version
	32 + // chain id
	2 // total len

// EntryMaxDataLen is the maximum data length of an Entry.
const EntryMaxDataLen = 10240

// EntryMaxTotalLen is the maximum total encoded length of an Entry.
const EntryMaxTotalLen = EntryMaxDataLen + EntryHeaderLen

// UnmarshalBinary unmarshals raw entry data, and populates or validates the
// e.Hash and e.ChainID, if not nil. Entries are encoded as follows:
//
//      [Version byte (0x00)] +
//      [ChainID (Bytes32)] +
//      [Total ExtID encoded length (uint16 BE)] +
//      [ExtID 0 length (uint16)] + [ExtID 0 (Bytes)] +
//      ... +
//      [ExtID X length (uint16)] + [ExtID X (Bytes)] +
//      [Content (Bytes)]
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#entry
func (e *Entry) UnmarshalBinary(data []byte) error {
	if len(data) < EntryHeaderLen || len(data) > EntryMaxTotalLen {
		return fmt.Errorf("invalid length")
	}

	if data[0] != 0x00 {
		return fmt.Errorf("invalid version byte")
	}

	i := 1 // Skip version byte.

	var chainID Bytes32
	i += copy(chainID[:], data[i:i+len(e.ChainID)])
	if e.ChainID != nil {
		if *e.ChainID != chainID {
			return fmt.Errorf("invalid ChainID")
		}
	} else {
		e.ChainID = &chainID
	}

	extIDTotalLen := int(binary.BigEndian.Uint16(data[i : i+2]))
	if extIDTotalLen == 1 || EntryHeaderLen+extIDTotalLen > len(data) {
		return fmt.Errorf("invalid ExtIDs length")
	}
	i += 2

	e.ExtIDs = make([]Bytes, 0)
	for i < EntryHeaderLen+extIDTotalLen {
		extIDLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		if i+2+extIDLen > EntryHeaderLen+extIDTotalLen {
			return fmt.Errorf("error parsing ExtIDs")
		}
		i += 2

		e.ExtIDs = append(e.ExtIDs, Bytes(data[i:i+extIDLen]))
		i += extIDLen
	}

	e.Content = data[i:]

	// Verify Hash, if set, otherwise populate it.
	hash := ComputeEntryHash(data)
	if e.Hash != nil {
		if *e.Hash != hash {
			return fmt.Errorf("invalid hash")
		}
	} else {
		e.Hash = &hash
	}

	return nil
}
