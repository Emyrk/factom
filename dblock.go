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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"
)

var (
	aBlockChainID  = Bytes32{31: 0x0a}
	ecBlockChainID = Bytes32{31: 0x0c}
	fBlockChainID  = Bytes32{31: 0x0f}
)

// ABlockChainID returns the ChainID of the Admin Block Chain, 0x00..0a.
func ABlockChainID() Bytes32 { return aBlockChainID }

// ECBlockChainID returns the ChainID of the Entry Credit Block Chain,
// 0x00..0c.
func ECBlockChainID() Bytes32 { return ecBlockChainID }

// FBlockChainID returns the ChainID of the Factoid Block Chain, 0x00..0f.
func FBlockChainID() Bytes32 { return fBlockChainID }

// DBlock represents a Factom Directory Block.
type DBlock struct {
	// Computed
	KeyMR    *Bytes32
	FullHash *Bytes32

	// Unmarshaled
	NetworkID    NetworkID
	BodyMR       *Bytes32
	PrevKeyMR    *Bytes32
	PrevFullHash *Bytes32
	Height       uint32
	Timestamp    time.Time

	// DBlock.Get populates EBlocks with their ChainID, KeyMR, Timestamp,
	// and Height.
	EBlocks []EBlock
}

// IsPopulated returns true if db has already been populated by a successful
// call to Get.
func (db DBlock) IsPopulated() bool {
	return len(db.EBlocks) > 0 &&
		db.KeyMR != nil &&
		db.FullHash != nil &&
		db.BodyMR != nil &&
		db.PrevKeyMR != nil &&
		db.PrevFullHash != nil
}

// Get queries factomd for the Directory Block at db.Height. After a
// successful call, the EBlocks will all have their ChainID and KeyMR, but not
// their Entries. Call Get on the EBlocks individually to populate their
// Entries.
func (db *DBlock) Get(ctx context.Context, c *Client) (err error) {
	if db.IsPopulated() {
		return nil
	}

	// Normally query by height.
	method := "dblock-by-height"
	params := interface{}(struct {
		Height uint32 `json:"height"`
	}{db.Height})
	var res struct {
		Data Bytes `json:"rawdata"`
		// DBlock nesting required for factomd API.
		DBlock struct {
			// Use a double pointer so that the db.KeyMR pointer
			// will be populated during unmarshalling.
			KeyMR **Bytes32 `json:"keymr"`
		} `json:"dblock"`
	}
	res.DBlock.KeyMR = &db.KeyMR
	result := interface{}(&res)

	// If a KeyMR is specified, query for that DBlock specifically.
	if db.KeyMR != nil {
		method = "raw-data"
		params = struct {
			Hash *Bytes32 `json:"hash"`
		}{Hash: db.KeyMR}

		// Use a typecase to overwrite the JSON field names. Only Data
		// will be populated.
		result = (*struct {
			Data   Bytes `json:"data"`
			DBlock struct {
				KeyMR **Bytes32 `json:"-"`
			} `json:"-"`
		})(&res)
	}

	if err := c.FactomdRequest(ctx, method, params, result); err != nil {
		return err
	}
	return db.UnmarshalBinary(res.Data)
}

// DBlockHeaderLen is the exact length of a DBlock header.
const DBlockHeaderLen = 1 + // [Version byte (0x00)]
	4 + // NetworkID
	32 + // BodyMR
	32 + // PrevKeyMR
	32 + // PrevFullHash
	4 + // Timestamp
	4 + // DB Height
	4 // EBlock Count

// DBlockEBlockLen is the exact length of an EBlock within a DBlock.
const DBlockEBlockLen = 32 + // ChainID
	32 // KeyMR

// DBlockMinBodyLen is the minimum length of the body of a DBlock, which must
// include at least an Admin Block, EC Block, and FCT Block.
const DBlockMinBodyLen = DBlockEBlockLen + // Admin Block
	DBlockEBlockLen + // EC Block
	DBlockEBlockLen // FCT Block

// DBlockMaxBodyLen is the maximum length of the body of a DBlock, which is
// determined by the largest EBlock count that can be stored in 4 bytes.
const DBlockMaxBodyLen = math.MaxUint32 * DBlockEBlockLen

// DBlockMinTotalLen is the minumum total length of a DBlock.
const DBlockMinTotalLen = DBlockHeaderLen + DBlockMinBodyLen

// DBlockMaxTotalLen is the maximum length of a DBlock.
const DBlockMaxTotalLen = DBlockHeaderLen + DBlockMaxBodyLen

// UnmarshalBinary unmarshals raw DBlock data, verifies the BodyMR, and
// populates db.FullHash and db.KeyMR, if nil. If db.KeyMR is populated, it is
// verified. The following format is expected for data.
//
// Header
//      [Version byte (0x00)] +
//      [NetworkID (4 bytes)] +
//      [BodyMR (Bytes32)] +
//      [PrevKeyMR (Bytes32)] +
//      [PrevFullHash (Bytes32)] +
//      [Timestamp (4 bytes)] +
//      [DB Height (4 bytes)] +
//      [EBlock Count (4 bytes)]
//
// Body
//      [Admin Block ChainID (Bytes32{31:0x0a})] +
//      [Admin Block LookupHash (Bytes32)] +
//      [EC Block ChainID (Bytes32{31:0x0c})] +
//      [EC Block HeaderHash (Bytes32)] +
//      [FCT Block ChainID (Bytes32{31:0x0f})] +
//      [FCT Block KeyMR (Bytes32)] +
//      [ChainID 0 (Bytes32)] +
//      [KeyMR 0 (Bytes32)] +
//      ... +
//      [ChainID N (Bytes32)] +
//      [KeyMR N (Bytes32)] +
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#directory-block
func (db *DBlock) UnmarshalBinary(data []byte) error {
	if uint64(len(data)) < DBlockMinTotalLen ||
		uint64(len(data)) > DBlockMaxTotalLen {
		return fmt.Errorf("invalid length")
	}

	// There is currently only one DBlock encoding version.
	if data[0] != 0x00 {
		return fmt.Errorf("invalid version byte")
	}

	i := 1

	// Parse the Header
	i += copy(db.NetworkID[:], data[i:])

	db.BodyMR = new(Bytes32)
	i += copy(db.BodyMR[:], data[i:])

	db.PrevKeyMR = new(Bytes32)
	i += copy(db.PrevKeyMR[:], data[i:])

	db.PrevFullHash = new(Bytes32)
	i += copy(db.PrevFullHash[:], data[i:])

	db.Timestamp = time.Unix(int64(binary.BigEndian.Uint32(data[i:i+4]))*60, 0)
	i += 4

	db.Height = binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	// eBlockCount defines how many EBlock ChainID|KeyMRs are in the
	// DBlock.
	eBlockCount := int(binary.BigEndian.Uint32(data[i : i+4]))
	i += 4

	// Ensure we have enough data left to read all of the EBlocks.
	if len(data[i:]) < eBlockCount*DBlockEBlockLen {
		return fmt.Errorf("insufficient length")
	}

	// elements are used to compute the BodyMR.
	elements := make([][]byte, eBlockCount)

	// prevChainID is used to ensure that ChainIDs are in ascending order.
	var prevChainID *Bytes32

	// Parse the EBlocks.
	db.EBlocks = make([]EBlock, eBlockCount)
	for ebi := range db.EBlocks {
		// Ensure that ChainIDs are in ascending order.
		if prevChainID != nil &&
			bytes.Compare(data[i:i+len(prevChainID)],
				prevChainID[:]) <= 0 {
			return fmt.Errorf("out of order or duplicate Chain ID")
		}

		elements[ebi] = data[i : i+2*len(Bytes32{})]

		// Populate ChainID, KeyMR, Timestamp, and Height.
		eb := &db.EBlocks[ebi]

		eb.ChainID = new(Bytes32)
		i += copy(eb.ChainID[:], data[i:])
		prevChainID = eb.ChainID

		eb.KeyMR = new(Bytes32)
		i += copy(eb.KeyMR[:], data[i:])

		eb.Timestamp = db.Timestamp
		eb.Height = db.Height
	}

	// Verify BodyMR.
	bodyMR, err := ComputeDBlockBodyMR(elements)
	if err != nil {
		return err
	}
	if *db.BodyMR != bodyMR {
		return fmt.Errorf("invalid BodyMR")
	}

	// Compute KeyMR
	headerHash := ComputeDBlockHeaderHash(data)
	keyMR := ComputeKeyMR(&headerHash, &bodyMR)

	// Verify KeyMR, if set.
	if db.KeyMR != nil {
		if *db.KeyMR != keyMR {
			return fmt.Errorf("invalid KeyMR")
		}
	} else {
		// Populate KeyMR.
		db.KeyMR = &keyMR
	}

	// Populate FullHash.
	db.FullHash = new(Bytes32)
	*db.FullHash = ComputeFullHash(data)

	return nil
}

// MarshalBinary returns the raw DBlock data for db. This will return an error
// if !db.IsPopulated() or if there are more than math.MaxUint32 EBlocks.  The
// data format is as follows.
//
// Header
//      [Version byte (0x00)] +
//      [NetworkID (4 bytes)] +
//      [BodyMR (Bytes32)] +
//      [PrevKeyMR (Bytes32)] +
//      [PrevFullHash (Bytes32)] +
//      [Timestamp (4 bytes)] +
//      [DB Height (4 bytes)] +
//      [EBlock Count (4 bytes)]
//
// Body
//      [Admin Block ChainID (Bytes32{31:0x0a})] +
//      [Admin Block LookupHash (Bytes32)] +
//      [EC Block ChainID (Bytes32{31:0x0c})] +
//      [EC Block HeaderHash (Bytes32)] +
//      [FCT Block ChainID (Bytes32{31:0x0f})] +
//      [FCT Block KeyMR (Bytes32)] +
//      [ChainID 0 (Bytes32)] +
//      [KeyMR 0 (Bytes32)] +
//      ... +
//      [ChainID N (Bytes32)] +
//      [KeyMR N (Bytes32)] +
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#directory-block
func (db DBlock) MarshalBinary() ([]byte, error) {
	if !db.IsPopulated() {
		return nil, fmt.Errorf("not populated")
	}

	totalLen := db.MarshalBinaryLen()
	if uint64(totalLen) > DBlockMaxTotalLen {
		return nil, fmt.Errorf("too many EBlocks")
	}
	data := make([]byte, totalLen)

	i := 1 // Skip version byte
	i += copy(data[i:], db.NetworkID[:])
	i += copy(data[i:], db.BodyMR[:])
	i += copy(data[i:], db.PrevKeyMR[:])
	i += copy(data[i:], db.PrevFullHash[:])

	binary.BigEndian.PutUint32(data[i:], uint32(db.Timestamp.Unix()/60))
	i += 4

	binary.BigEndian.PutUint32(data[i:], db.Height)
	i += 4

	binary.BigEndian.PutUint32(data[i:], uint32(len(db.EBlocks)))
	i += 4

	for _, eb := range db.EBlocks {
		i += copy(data[i:], eb.ChainID[:])
		i += copy(data[i:], eb.KeyMR[:])
	}
	return data, nil
}

// MarshalBinaryLen returns the length of the binary encoding of db,
//      DBlockHeaderLen + len(db.EBlocks)*DBlockEBlockLen
func (db DBlock) MarshalBinaryLen() int {
	return DBlockHeaderLen + len(db.EBlocks)*DBlockEBlockLen
}

// EBlock efficiently finds and returns the *EBlock in db.EBlocks for the given
// chainID, if it exists. Otherwise, EBlock returns nil.
//
// This assumes that db.EBlocks ordered by ascending ChainID.
func (db DBlock) EBlock(chainID Bytes32) *EBlock {
	ei := sort.Search(len(db.EBlocks), func(i int) bool {
		return bytes.Compare(db.EBlocks[i].ChainID[:], chainID[:]) >= 0
	})
	if ei < len(db.EBlocks) && *db.EBlocks[ei].ChainID == chainID {
		return &db.EBlocks[ei]
	}
	return nil
}
