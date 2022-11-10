package snp

import (
	"bytes"
	"encoding/binary"
	snp "snp/common"
)

func BuildAttestationReport(reportBin []byte) snp.AttestationReport {
	report := snp.AttestationReport{}

	binary.Read(bytes.NewBuffer(reportBin), binary.LittleEndian, &report)

	return report
}
