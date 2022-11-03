package main

import (
	"encoding/binary"
	"fmt"
	"os"
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

const POLICY_DEBUG_SHIFT = 19
const POLICY_MIGRATE_MA_SHIFT = 18
const POLICY_SMT_SHIFT = 16
const POLICY_ABI_MAJOR_SHIFT = 8
const POLICY_ABI_MINOR_SHIFT = 0

const POLICY_DEBUG_MASK = (uint64(1) << (POLICY_DEBUG_SHIFT))
const POLICY_MIGRATE_MA_MASK = (uint64(1) << (POLICY_MIGRATE_MA_SHIFT))
const POLICY_SMT_MASK = (uint64(1) << (POLICY_SMT_SHIFT))
const POLICY_ABI_MAJOR_MASK = (uint64(0xFF) << (POLICY_ABI_MAJOR_SHIFT))
const POLICY_ABI_MINOR_MASK = (uint64(0xFF) << (POLICY_ABI_MINOR_SHIFT))

func LoadAttestationReport(file *os.File) AttestationReport {
	report := AttestationReport{}

	binary.Read(file, binary.LittleEndian, &report.Version)
	binary.Read(file, binary.LittleEndian, &report.GuestSVN)
	binary.Read(file, binary.LittleEndian, &report.Policy)
	binary.Read(file, binary.LittleEndian, &report.FamilyId)
	binary.Read(file, binary.LittleEndian, &report.ImageId)
	binary.Read(file, binary.LittleEndian, &report.VMPL)
	binary.Read(file, binary.LittleEndian, &report.SignatureAlgo)
	binary.Read(file, binary.LittleEndian, &report.PlatformVersion)
	binary.Read(file, binary.LittleEndian, &report.PlatformInfo)
	binary.Read(file, binary.LittleEndian, &report.Flags)
	binary.Read(file, binary.LittleEndian, &report.Reserved0)
	binary.Read(file, binary.LittleEndian, &report.ReportData)
	binary.Read(file, binary.LittleEndian, &report.Measurement)
	binary.Read(file, binary.LittleEndian, &report.HostData)
	binary.Read(file, binary.LittleEndian, &report.IdKeyDigest)
	binary.Read(file, binary.LittleEndian, &report.AuthorKeyDigest)
	binary.Read(file, binary.LittleEndian, &report.ReportId)
	binary.Read(file, binary.LittleEndian, &report.ReportIdMA)
	binary.Read(file, binary.LittleEndian, &report.ReportedTCB)
	binary.Read(file, binary.LittleEndian, &report.Reserved1)
	binary.Read(file, binary.LittleEndian, &report.ChipId)
	binary.Read(file, binary.LittleEndian, &report.Reserved2)
	binary.Read(file, binary.LittleEndian, &report.Signature.R)
	binary.Read(file, binary.LittleEndian, &report.Signature.S)
	binary.Read(file, binary.LittleEndian, &report.Signature.Reserved)

	return report
}

func PrintAttestationReport(report AttestationReport) {
	debugAllowed := report.Policy & POLICY_DEBUG_MASK
	migrationAgentAllowed := report.Policy & POLICY_MIGRATE_MA_MASK
	smtAllowed := report.Policy & POLICY_SMT_MASK
	minABIMajor := report.Policy & POLICY_ABI_MAJOR_MASK
	minABIMinor := report.Policy & POLICY_ABI_MINOR_MASK

	fmt.Println("Version: ", report.Version)
	fmt.Println("Guest_svn: ", report.GuestSVN)
	fmt.Printf("Policy: 0x%x\n", report.Policy)
	fmt.Printf("  - Debug Allowed: %t\n", debugAllowed > 0)
	fmt.Printf("  - Migration Agent Allowed: %t\n", migrationAgentAllowed > 0)
	fmt.Printf("  - SMT Allowed: %t\n", smtAllowed > 0)
	fmt.Printf("  - Min. ABI Major: %d\n", minABIMajor)
	fmt.Printf("  - Min. ABI Minor: %d\n", minABIMinor)
	fmt.Println("Family_id: ", PrintByteArray(report.FamilyId[:]))
	fmt.Println("Image_id: ", PrintByteArray(report.ImageId[:]))
	fmt.Println("Vmpl: ", report.VMPL)
	fmt.Println("Signature_algo: ", report.SignatureAlgo)
	fmt.Println("Platform_version:")
	fmt.Println("  - Boot_loader", report.PlatformVersion.BootLoader)
	fmt.Println("  - Tee", report.PlatformVersion.TEE)
	fmt.Println("  - Snp", report.PlatformVersion.SNP)
	fmt.Println("  - Microcode", report.PlatformVersion.Microcode)
	fmt.Println("Platform_info: ", report.PlatformInfo)
	fmt.Println("Report_data: ", PrintByteArray(report.ReportData[:]))
	fmt.Println("Measurement: ", PrintByteArray(report.Measurement[:]))
	fmt.Println("Host_data: ", PrintByteArray(report.HostData[:]))
	fmt.Println("Id_key_digest: ", PrintByteArray(report.IdKeyDigest[:]))
	fmt.Println("Author_key_digest: ", PrintByteArray(report.AuthorKeyDigest[:]))
	fmt.Println("Report_id: ", PrintByteArray(report.ReportId[:]))
	fmt.Println("Report_id_ma: ", PrintByteArray(report.ReportIdMA[:]))
	fmt.Println("Reported_tcb:")
	fmt.Println("  - Boot_loader: ", report.ReportedTCB.BootLoader)
	fmt.Println("  - Tee: ", report.ReportedTCB.TEE)
	fmt.Println("  - Snp: ", report.ReportedTCB.SNP)
	fmt.Println("  - Microcode: ", report.ReportedTCB.Microcode)
	fmt.Println("Chip_id: ", PrintByteArray(report.ChipId[:]))
	fmt.Println("Signature:")
	fmt.Println("    R: ", PrintByteArray(report.Signature.R[:]))
	fmt.Println("    S: ", PrintByteArray(report.Signature.S[:]))
}

func PrintByteArray(array []byte) string {
	str := ""

	for i := 0; i < len(array); i++ {
		value := array[i]
		str += fmt.Sprintf("%02x", value)
	}

	return str
}
