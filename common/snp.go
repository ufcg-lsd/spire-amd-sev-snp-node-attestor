package snp

import (
	"bytes"
	"encoding/binary"
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

	CIPHERTEXT_HIDING_EN_SHIFT = 0x04
	RAPL_DIS_SHIFT             = 0x03
	ECC_EN_SHIFT               = 0x02
	TSME_EN_SHIFT              = 0x01
	SMT_EN_SHIFT               = 0x00

	CIPHERTEXT_HIDING_EN_MASK = (uint64(0x01) << (CIPHERTEXT_HIDING_EN_SHIFT))
	RAPL_DIS_MASK             = (uint64(0x01) << (RAPL_DIS_SHIFT))
	ECC_EN_MASK               = (uint64(0x01) << (ECC_EN_SHIFT))
	TSME_EN_MASK              = (uint64(0x01) << (TSME_EN_SHIFT))
	SMT_EN_MASK               = (uint64(0x01) << (SMT_EN_SHIFT))

	SIGNIN_KEY_SHIFT    = 0x02
	MASK_CHIP_KEY_SHIFT = 0x01
	AUTHOR_KEY_EN_SHIFT = 0x00

	SIGNIN_KEY_MASK    = (uint32(0xff) << (SIGNIN_KEY_SHIFT))
	MASK_CHIP_KEY_MASK = (uint32(0x01) << (MASK_CHIP_KEY_SHIFT))
	AUTHOR_KEY_EN_MASK = (uint32(0x01) << (AUTHOR_KEY_EN_SHIFT))
)

type Policy struct {
	ABI_MINOR             uint64
	ABI_MAJOR             uint64
	SMT_ALLOWED           bool
	MIGRATE_MA_ALLOWED    bool
	DEBUG_ALLOWED         bool
	SINGLE_SOCKET_ALLOWED bool
}

type Flags struct {
	SIGNING_KEY   uint32
	MASK_CHIP_KEY bool
	AUTHOR_KEY_EN bool
}

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

type PlatformInfo struct {
	SMT_EN               bool
	TSME_EN              bool
	ECC_EN               bool
	RAPL_DIS             bool
	CIPHERTEXT_HIDING_EN bool
}

/* The ATTESTATION_REPORT struct returned from the firmware */
type AttestationReport struct {
	Version         uint32
	GuestSVN        uint32
	Policy          uint64
	FamilyId        [16]byte
	ImageId         [16]byte
	VMPL            uint32
	SignatureAlgo   uint32
	CurrentTCB      TCBVersion
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
	CommitedTCB     TCBVersion
	CurrentBuild    byte
	CurrentMinor    byte
	CurrentMajor    byte
	Reserved2       byte
	CommitedBuild   byte
	CommitedMinor   byte
	CommitedMajor   byte
	Reserved3       byte
	LaunchTCB       TCBVersion
	Reserved4       [168]byte
	Signature       Signature
}

/* Expanded ATTESTATION_REPORT struct with fields programmer-friendly */
type AttestationReportExpanded struct {
	Version         uint32
	GuestSVN        uint32
	Policy          Policy
	FamilyId        [16]byte
	ImageId         [16]byte
	VMPL            uint32
	SignatureAlgo   uint32
	CurrentTCB      TCBVersion
	PlatformInfo    PlatformInfo
	Flags           Flags
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
	CommitedTCB     TCBVersion
	CurrentBuild    byte
	CurrentMinor    byte
	CurrentMajor    byte
	Reserved2       byte
	CommitedBuild   byte
	CommitedMinor   byte
	CommitedMajor   byte
	Reserved3       byte
	LaunchTCB       TCBVersion
	Reserved4       [168]byte
	Signature       Signature
}

type AttestationDataRequest struct {
	Report []byte
	Cert   []byte
}

type AttestationRequestAzure struct {
	Report      []byte
	Cert        []byte
	TPMAK       []byte
	RuntimeData []byte
	QuoteData   QuoteData
}

type RegistrationRequestSVSM struct {
	Report []byte
	Cert   []byte
	TPMEK  []byte
	TPMAK  []byte
}

type AttestationRequestSVSM struct {
	Challenge Challenge
	Nonce     []byte
}

type AttestationResponseSVSM struct {
	QuoteData QuoteData
	Secret    []byte
}

func BuildExpandedAttestationReport(reportBin []byte) AttestationReportExpanded {
	report := AttestationReport{}
	reportExtended := AttestationReportExpanded{}

	binary.Read(bytes.NewBuffer(reportBin), binary.LittleEndian, &report)
	policy := BuildPolicy(report)
	platformInfo := BuildPlatformInfo(report)
	flags := BuildFlags(report)

	reportExtended.Version = report.Version
	reportExtended.GuestSVN = report.GuestSVN
	reportExtended.Policy = policy
	reportExtended.FamilyId = report.FamilyId
	reportExtended.ImageId = report.ImageId
	reportExtended.VMPL = report.VMPL
	reportExtended.SignatureAlgo = report.SignatureAlgo
	reportExtended.CurrentTCB = report.CurrentTCB
	reportExtended.PlatformInfo = platformInfo
	reportExtended.Flags = flags
	reportExtended.Reserved0 = report.Reserved0
	reportExtended.ReportData = report.ReportData
	reportExtended.Measurement = report.Measurement
	reportExtended.HostData = report.HostData
	reportExtended.IdKeyDigest = report.IdKeyDigest
	reportExtended.AuthorKeyDigest = report.AuthorKeyDigest
	reportExtended.ReportId = report.ReportId
	reportExtended.ReportIdMA = report.ReportIdMA
	reportExtended.ReportedTCB = report.ReportedTCB
	reportExtended.Reserved1 = report.Reserved1
	reportExtended.ChipId = report.ChipId
	reportExtended.CommitedTCB = report.CommitedTCB
	reportExtended.CurrentBuild = report.CurrentBuild
	reportExtended.CurrentMinor = report.CurrentMinor
	reportExtended.CurrentMajor = report.CurrentMajor
	reportExtended.Reserved2 = report.Reserved2
	reportExtended.CommitedBuild = report.CommitedBuild
	reportExtended.CommitedMinor = report.CommitedMinor
	reportExtended.CommitedMajor = report.CommitedMajor
	reportExtended.Reserved3 = report.Reserved3
	reportExtended.LaunchTCB = report.LaunchTCB
	reportExtended.Reserved4 = report.Reserved4
	reportExtended.Signature = report.Signature

	return reportExtended
}

func BuildPolicy(report AttestationReport) Policy {
	policy := report.Policy
	policyStruct := Policy{}

	policyStruct.ABI_MINOR = (policy & POLICY_ABI_MINOR_MASK >> POLICY_ABI_MINOR_SHIFT)
	policyStruct.ABI_MAJOR = ((policy & POLICY_ABI_MAJOR_MASK) >> POLICY_ABI_MAJOR_SHIFT)
	policyStruct.SMT_ALLOWED = ((policy & POLICY_SMT_MASK) != 0)
	policyStruct.MIGRATE_MA_ALLOWED = ((policy & POLICY_MIGRATE_MA_MASK) != 0)
	policyStruct.DEBUG_ALLOWED = ((policy & POLICY_DEBUG_MASK) != 0)
	policyStruct.SINGLE_SOCKET_ALLOWED = ((policy & POLICY_SINGLE_SOCKET_MASK) != 0)

	return policyStruct
}

func BuildPlatformInfo(report AttestationReport) PlatformInfo {
	platforminfo := report.PlatformInfo
	platforminfoStruct := PlatformInfo{}

	platforminfoStruct.SMT_EN = ((platforminfo & SMT_EN_MASK >> SMT_EN_SHIFT) != 0)
	platforminfoStruct.TSME_EN = ((platforminfo & TSME_EN_MASK >> TSME_EN_SHIFT) != 0)
	platforminfoStruct.ECC_EN = ((platforminfo & ECC_EN_MASK >> ECC_EN_SHIFT) != 0)
	platforminfoStruct.RAPL_DIS = ((platforminfo & RAPL_DIS_MASK >> RAPL_DIS_SHIFT) != 0)
	platforminfoStruct.CIPHERTEXT_HIDING_EN = ((platforminfo & CIPHERTEXT_HIDING_EN_MASK >> CIPHERTEXT_HIDING_EN_SHIFT) != 0)

	return platforminfoStruct
}

func BuildFlags(report AttestationReport) Flags {
	flags := report.Flags
	flagsStruct := Flags{}
	flagsStruct.AUTHOR_KEY_EN = ((flags & AUTHOR_KEY_EN_MASK >> AUTHOR_KEY_EN_SHIFT) != 0)
	flagsStruct.MASK_CHIP_KEY = ((flags & MASK_CHIP_KEY_MASK >> MASK_CHIP_KEY_SHIFT) != 0)
	flagsStruct.SIGNING_KEY = (flags & SIGNIN_KEY_MASK >> SIGNIN_KEY_SHIFT)

	return flagsStruct
}
