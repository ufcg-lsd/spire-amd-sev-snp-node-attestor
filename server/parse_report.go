package main

import (
	"bytes"
	"encoding/binary"
)

type TCBVersion struct {
	BootLoader byte
	TEE        byte
	Reserved   [4]byte
	SNP        byte
	Microcode  byte
}

type Signature struct {
	R        [72]byte
	S        [72]byte
	Reserved [512 - 144]byte
}

type AttestationReport struct {
	Version         uint32
	GuestSVN        uint32
	Policy          uint64
	FamilyId        [16]byte
	ImageId         [16]byte
	VMPL            uint32
	SignatureAlgo   uint32
	PlatformVersion TCBVersion
	PlatformInfo    uint64
	Flags           uint32
	Reserved0       uint32
	ReportData      [64]byte
	Measurement     [48]byte
	HostData        [32]byte
	IdKeyDigest     [48]byte
	AuthorKeyDigest [48]byte
	ReportId        [32]byte
	ReportIdMA      [32]byte
	ReportedTCB     TCBVersion
	Reserved1       [24]byte
	ChipId          [64]byte
	Reserved2       [192]byte
	Signature       Signature
}

func BuildAttestationReport(reportBin []byte) AttestationReport {
	report := AttestationReport{}

	binary.Read(bytes.NewBuffer(reportBin), binary.LittleEndian, &report)

	return report
}
