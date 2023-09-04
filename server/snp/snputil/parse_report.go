package snp

import (
	"bytes"
	"encoding/binary"
	snp "snp/common"
)

const (
	POLICY_SINGLE_SOCKET_SHIFT = 0x14
	POLICY_DEBUG_SHIFT         = 0x13
	POLICY_MIGRATE_MA_SHIFT    = 0x12
	POLICY_SMT_SHIFT           = 0x10
	POLICY_ABI_MAJOR_SHIFT     = 0x08
	POLICY_ABI_MINOR_SHIFT     = 0x00

	POLICY_SINGLE_SOCKET_MASK = (uint64(0x01) << (POLICY_SINGLE_SOCKET_SHIFT))
	POLICY_DEBUG_MASK         = (uint64(0x01) << (POLICY_DEBUG_SHIFT))
	POLICY_MIGRATE_MA_MASK    = (uint64(0x01) << (POLICY_MIGRATE_MA_SHIFT))
	POLICY_SMT_MASK           = (uint64(0x01) << (POLICY_SMT_SHIFT))
	POLICY_ABI_MAJOR_MASK     = (uint64(0xff) << (POLICY_ABI_MAJOR_SHIFT))
	POLICY_ABI_MINOR_MASK     = (uint64(0xff) << (POLICY_ABI_MINOR_SHIFT))

	TSME_EN_SHIFT = 0x01
	SMT_EN_SHIFT  = 0x00

	TSME_EN_MASK = (uint64(0x01) << (TSME_EN_SHIFT))
	SMT_EN_MASK  = (uint64(0x01) << (SMT_EN_SHIFT))

	SIGNIN_KEY_SHIFT    = 0x02
	MASK_CHIP_KEY_SHIFT = 0x01
	AUTHOR_KEY_EN_SHIFT = 0x00

	SIGNIN_KEY_MASK    = (uint32(0xff) << (SIGNIN_KEY_SHIFT))
	MASK_CHIP_KEY_MASK = (uint32(0x01) << (MASK_CHIP_KEY_SHIFT))
	AUTHOR_KEY_EN_MASK = (uint32(0x01) << (AUTHOR_KEY_EN_SHIFT))
)

func BuildAttestationReport(reportBin []byte) snp.AttestationReport {
	report := snp.AttestationReport{}

	binary.Read(bytes.NewBuffer(reportBin), binary.LittleEndian, &report)

	return report
}

func BuildPolicy(report snp.AttestationReport) snp.Policy {
	policy := report.Policy
	policyStruct := snp.Policy{}

	policyStruct.ABI_MINOR = (policy & POLICY_ABI_MINOR_MASK >> POLICY_ABI_MINOR_SHIFT)
	policyStruct.ABI_MAJOR = ((policy & POLICY_ABI_MAJOR_MASK) >> POLICY_ABI_MAJOR_SHIFT)
	policyStruct.SMT_ALLOWED = ((policy & POLICY_SMT_MASK) != 0)
	policyStruct.MIGRATE_MA_ALLOWED = ((policy & POLICY_MIGRATE_MA_MASK) != 0)
	policyStruct.DEBUG_ALLOWED = ((policy & POLICY_DEBUG_MASK) != 0)
	policyStruct.SINGLE_SOCKET_ALLOWED = ((policy & POLICY_SINGLE_SOCKET_MASK) != 0)

	return policyStruct
}

func BuildPlatformInfo(report snp.AttestationReport) snp.PlatformInfo {
	platforminfo := report.PlatformInfo
	platforminfoStruct := snp.PlatformInfo{}
	platforminfoStruct.SMT_EN = ((platforminfo & SMT_EN_MASK >> SMT_EN_SHIFT) != 0)
	platforminfoStruct.TSME_EN = ((platforminfo & TSME_EN_MASK) != 0)

	return platforminfoStruct
}

func BuildFlags(report snp.AttestationReport) snp.Flags {
	flags := report.Flags
	flagsStruct := snp.Flags{}
	flagsStruct.AUTHOR_KEY_EN = ((flags & AUTHOR_KEY_EN_MASK >> AUTHOR_KEY_EN_SHIFT) != 0)
	flagsStruct.MASK_CHIP_KEY = ((flags & MASK_CHIP_KEY_MASK >> MASK_CHIP_KEY_SHIFT) != 0)
	flagsStruct.SIGNING_KEY = (flags & SIGNIN_KEY_MASK >> SIGNIN_KEY_SHIFT)

	return flagsStruct
}
