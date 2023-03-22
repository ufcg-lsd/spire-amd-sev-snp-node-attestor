package snp

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

/* The ATTESTATION_REPORT struct returned from the firmware */
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

type Policy struct {
	ABI_MINOR             uint64
	ABI_MAJOR             uint64
	SMT_ALLOWED           bool
	MIGRATE_MA_ALLOWED    bool
	DEBUG_ALLOWED         bool
	SINGLE_SOCKET_ALLOWED bool
}
