package snp

type TCBVersion struct {
	BootLoader byte    // 0x0
	TEE        byte    // 0x1
	Reserved   [4]byte // 0x2
	SNP        byte    // 0x6
	Microcode  byte    // 0x7
}

type Signature struct {
	R        [72]byte        // 0x00
	S        [72]byte        // 0x48
	Reserved [512 - 144]byte // 0x90
}

/* The ATTESTATION_REPORT struct returned from the firmware */
type AttestationReport struct {
	Version         uint32     // 0x000
	GuestSVN        uint32     // 0x004
	Policy          uint64     // 0x008
	FamilyId        [16]byte   // 0x010
	ImageId         [16]byte   // 0x020
	VMPL            uint32     // 0x030
	SignatureAlgo   uint32     // 0x034
	PlatformVersion TCBVersion // 0x038
	PlatformInfo    uint64     // 0x040
	Flags           uint32     // 0x048
	Reserved0       uint32     // 0x04C
	ReportData      [64]byte   // 0x050
	Measurement     [48]byte   // 0x090
	HostData        [32]byte   // 0x0C0
	IdKeyDigest     [48]byte   // 0x0E0
	AuthorKeyDigest [48]byte   // 0x110
	ReportId        [32]byte   // 0x140
	ReportIdMA      [32]byte   // 0x160
	ReportedTCB     TCBVersion // 0x180
	Reserved1       [24]byte   // 0x188
	ChipId          [64]byte   // 0x1A0
	Reserved2       [192]byte  // 0x1E0
	Signature       Signature  // 0x2A0
}
