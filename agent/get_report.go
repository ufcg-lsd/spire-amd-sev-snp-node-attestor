package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"github.com/rizzza/smart/ioctl"
)

type SnpReportReq struct {
	UserData [64]byte
	VMPL     uint32
	RSVD     [28]byte
}

type SnpReportResp struct {
	Data [4000]byte
}

type SnpGuestRequestIOCtl struct {
	MSGVersion byte
	ReqData    uint64
	RespData   uint64
	FWErr      uint64
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

type MsgReportResp struct {
	Status            uint32
	ReportSize        uint32
	Reserved          [24]byte
	AttestationReport AttestationReport
}

func GetReport(data [64]byte) ([]byte, error) {
	var req SnpReportReq
	var resp SnpReportResp
	var guestReq SnpGuestRequestIOCtl
	var reportResp MsgReportResp

	req.UserData = data

	guestReq.MSGVersion = 0x01
	guestReq.ReqData = uint64(uintptr(unsafe.Pointer(&req)))
	guestReq.RespData = uint64(uintptr(unsafe.Pointer(&resp)))

	file, err := os.Open("/dev/sev-guest")

	if err != nil {
		return nil, err
	}

	defer file.Close()

	fd := file.Fd()

	const SNP_GUEST_REQ_IOC_TYPE = 'S'
	var SNP_GET_REPORT = ioctl.Iowr(uintptr(SNP_GUEST_REQ_IOC_TYPE), 0x0, unsafe.Sizeof(SnpGuestRequestIOCtl{}))

	err = ioctl.Ioctl(fd, SNP_GET_REPORT, uintptr(unsafe.Pointer(&guestReq)))

	if err != nil {
		return nil, err
	}

	binary.Read(bytes.NewBuffer(resp.Data[:]), binary.LittleEndian, &reportResp)

	if reportResp.Status != 0 {
		return nil, fmt.Errorf("error: status: %d", reportResp.Status)
	}

	reportSize := unsafe.Sizeof(AttestationReport{})
	if reportResp.ReportSize > uint32(reportSize) {
		return nil, fmt.Errorf("error: received report size: %d, expected %d", reportResp.ReportSize, reportSize)
	}

	reportBin := resp.Data[32 : 1184+32]

	return reportBin, nil
}
