package snp

import (
	"bytes"
	"encoding/binary"
)

func GetSigningKey(report *[]byte) uint32 {

	reportStruct := AttestationReport{}
	binary.Read(bytes.NewBuffer(*report), binary.LittleEndian, &reportStruct)

	SIGNIN_KEY_SHIFT := 0x02
	SIGNIN_KEY_MASK := (uint32(0xff) << (SIGNIN_KEY_SHIFT))
	flags := reportStruct.Flags
	flagsStruct := Flags{}
	flagsStruct.SIGNING_KEY = (flags & SIGNIN_KEY_MASK >> SIGNIN_KEY_SHIFT)

	return flagsStruct.SIGNING_KEY
}
