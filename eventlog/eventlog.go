// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main 

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type EventType uint32
type HashAlg uint8
type Algorithm uint16
const eventTypeNoAction = 0x03

const (
	PrebootCert          EventType = 0x00000000
	PostCode             EventType = 0x00000001
	unused               EventType = 0x00000002
	NoAction             EventType = 0x00000003
	Separator            EventType = 0x00000004
	Action               EventType = 0x00000005
	EventTag             EventType = 0x00000006
	SCRTMContents        EventType = 0x00000007
	SCRTMVersion         EventType = 0x00000008
	CpuMicrocode         EventType = 0x00000009
	PlatformConfigFlags  EventType = 0x0000000A
	TableOfDevices       EventType = 0x0000000B
	CompactHash          EventType = 0x0000000C
	Ipl                  EventType = 0x0000000D
	IplPartitionData     EventType = 0x0000000E
	NonhostCode          EventType = 0x0000000F
	NonhostConfig        EventType = 0x00000010
	NonhostInfo          EventType = 0x00000011
	OmitBootDeviceEvents EventType = 0x00000012
)

const (
	EFIEventBase               EventType = 0x80000000
	EFIVariableDriverConfig    EventType = 0x80000001
	EFIVariableBoot            EventType = 0x80000002
	EFIBootServicesApplication EventType = 0x80000003
	EFIBootServicesDriver      EventType = 0x80000004
	EFIRuntimeServicesDriver   EventType = 0x80000005
	EFIGPTEvent                EventType = 0x80000006
	EFIAction                  EventType = 0x80000007
	EFIPlatformFirmwareBlob    EventType = 0x80000008
	EFIHandoffTables           EventType = 0x80000009
	EFIHCRTMEvent              EventType = 0x80000010
	EFIVariableAuthority       EventType = 0x800000e0
)

var eventTypeNames = map[EventType]string{
	PrebootCert:          "Preboot Cert",
	PostCode:             "POST Code",
	unused:               "Unused",
	NoAction:             "No Action",
	Separator:            "Separator",
	Action:               "Action",
	EventTag:             "Event Tag",
	SCRTMContents:        "S-CRTM Contents",
	SCRTMVersion:         "S-CRTM Version",
	CpuMicrocode:         "CPU Microcode",
	PlatformConfigFlags:  "Platform Config Flags",
	TableOfDevices:       "Table of Devices",
	CompactHash:          "Compact Hash",
	Ipl:                  "IPL",
	IplPartitionData:     "IPL Partition Data",
	NonhostCode:          "Non-Host Code",
	NonhostConfig:        "Non-HostConfig",
	NonhostInfo:          "Non-Host Info",
	OmitBootDeviceEvents: "Omit Boot Device Events",

	EFIEventBase:               "EFI Event Base",
	EFIVariableDriverConfig:    "EFI Variable Driver Config",
	EFIVariableBoot:            "EFI Variable Boot",
	EFIBootServicesApplication: "EFI Boot Services Application",
	EFIBootServicesDriver:      "EFI Boot Services Driver",
	EFIRuntimeServicesDriver:   "EFI Runtime Services Driver",
	EFIGPTEvent:                "EFI GPT Event",
	EFIAction:                  "EFI Action",
	EFIPlatformFirmwareBlob:    "EFI Platform Firmware Blob",
	EFIVariableAuthority:       "EFI Variable Authority",
	EFIHandoffTables:           "EFI Handoff Tables",
	EFIHCRTMEvent:              "EFI H-CRTM Event",
}
type digest struct {
	hash crypto.Hash
	data []byte
}

type rawEvent struct {
	sequence int
	index    int
	typ      EventType
	data     []byte
	digests  []digest
}

type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

type SpecIDHdr struct {
	Sign [16]byte
        Pc   uint32
        VMi  uint8
        VMa  uint8
        Erta uint8
	Siz  uint8
        NAlgs uint32
}

type SpecIDEvent struct {
	algs []SpecAlgSize
}

type SpecAlgSize struct {
	ID   uint16
	Size uint16
}

const (
	AlgSHA1      Algorithm = 0x0004
	AlgSHA256    Algorithm = 0x000B
)

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(AlgSHA1)
	HashSHA256 = HashAlg(AlgSHA256)
)

func (a HashAlg) cryptoHash() crypto.Hash {
	switch a {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	}
	return 0
}

func (a HashAlg) goTPMAlg() Algorithm {
	switch a {
	case HashSHA1:
		return AlgSHA1
	case HashSHA256:
		return AlgSHA256
	}
	return 0
}

// String returns a human-friendly representation of the hash algorithm.
func (a HashAlg) String() string {
	switch a {
	case HashSHA1:
		return "SHA1"
	case HashSHA256:
		return "SHA256"
	}
	return fmt.Sprintf("HashAlg<%d>", int(a))
}

func parseSpecIDEvent(data []byte) (SpecIDEvent, error ){
	treader := bytes.NewReader(data)
	var hdr SpecIDHdr
	if err := binary.Read(treader, binary.LittleEndian, &hdr); err != nil {
		return SpecIDEvent{}, err 
	}
        sa := SpecAlgSize{}	
	var specID SpecIDEvent
	for i := 0; i < int(hdr.NAlgs); i++ {
		if err := binary.Read(treader, binary.LittleEndian, &sa); err != nil {
			return SpecIDEvent{}, err
		}
		specID.algs = append(specID.algs, sa)
	}
	fmt.Println(specID)
	return specID, nil
}

func getSpecIDEvent(r *bytes.Buffer) (rawEvent, error) {
	var h rawEventHeader
	var event rawEvent
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	if h.EventSize == 0 {
		return event, errors.New("event data size is 0")
	}
	if h.EventSize > uint32(r.Len()) {
		return event, fmt.Errorf("Event Size error")
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, err
	}

	digests := []digest{{hash: crypto.SHA1, data: h.Digest[:]}}

	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: digests,
	}, nil
}

func parseEvent(r *bytes.Buffer, specID SpecIDEvent) (rawEvent, error) {
	var h rawEvent2Header

	var event rawEvent

	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	event.typ = EventType(h.Type)
	event.index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if uint16(r.Len()) < alg.Size {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.data = make([]byte, alg.Size)
			digest.hash = HashAlg(alg.ID).cryptoHash()
		}
		if len(digest.data) == 0 {
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.data); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize == 0 {
		return event, errors.New("event data size is 0")
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, nil
}

func ParseEvents(eventLogFile string) ([]rawEvent, error) {
	eventLogBytes, err := ioutil.ReadFile(eventLogFile)
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(eventLogBytes)
	event, err := getSpecIDEvent(r)
	specID, err := parseSpecIDEvent(event.data)
	var events []rawEvent
	if event.typ == eventTypeNoAction {
		fmt.Println("Crypto Agile Format")
		sequence := 1
		for (r.Len() > 0) {
			event, err := parseEvent(r, specID)
			if err == nil {
				event.sequence  = sequence
		        	events = append(events, event)	
				sequence++
			}
		}
	}
	return events, nil
}

func dumpEventLog(events []rawEvent) {
	for  _, event := range events {
		fmt.Printf("----Event %d----\n", event.sequence)
		fmt.Printf("Type: %s\n", eventTypeNames[event.typ])
		fmt.Printf("PCR:  %d\n", event.index)
		h := sha256.New()
		h.Write(event.data)
		fmt.Printf("Computed Hash: %x\n", h.Sum(nil))
		if event.index == 8 || event.index == 9 {
			fmt.Printf("Data: %s\n", event.data)
		}
		if err := parseEventDataTCG(event.typ, event.data); err != nil {
			fmt.Printf("Error in parseEventDataTCG: %v\n", err)
		}
		for _, digest := range event.digests {
			if digest.hash == crypto.SHA256 {
				fmt.Printf("Digest: %x\n", digest.data)
			}
		}
	}
}

func parseEventDataTCG(eventType EventType, data []byte) error {
	switch eventType {
		case NoAction, Action, Separator, EFIAction:
			return nil
		case EFIVariableDriverConfig, EFIVariableBoot, EFIVariableAuthority:
			return parseEventDataEFIVariable(data, eventType)
		case EFIBootServicesApplication, EFIBootServicesDriver, EFIRuntimeServicesDriver:
		     return parseEventDataEFIImageLoad(data)
		case EFIGPTEvent:
		     return parseEventDataEFIGPT(data)
		default:
	}
    return nil
}

// Guid corresponds to the EFI_GUID type
type Guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func (g *Guid) String() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}", 
		g.Data1, g.Data2, g.Data3, 
		binary.BigEndian.Uint16(g.Data4[0:2]),
		g.Data4[2:])
}

