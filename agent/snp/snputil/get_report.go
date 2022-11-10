package snp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	snp "snp/common"

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

type MsgReportResp struct {
	Status            uint32
	ReportSize        uint32
	Reserved          [24]byte
	AttestationReport snp.AttestationReport
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

	reportSize := unsafe.Sizeof(reportResp.AttestationReport)
	if reportResp.ReportSize > uint32(reportSize) {
		return nil, fmt.Errorf("error: received report size: %d, expected %d", reportResp.ReportSize, reportSize)
	}

	reportBin := resp.Data[32 : 1184+32]

	return reportBin, nil
}
