package snp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	snp "snp/common"

	"io"
	"net/http"
	"net/url"
)

var GetVCEKFromAMD = getVCEKFromAMD

func getVCEKFromAMD(report snp.AttestationReportExpanded) ([]byte, error) {
	baseUrl := "https://kdsintf.amd.com/vcek/v1/Milan"
	hwId := hex.EncodeToString(report.ChipId[:])

	reqUrl, err := url.Parse(baseUrl)
	if err != nil {
		return nil, err
	}

	reqUrl = reqUrl.JoinPath(hwId)

	params := url.Values{}
	params.Add("blSPL", fmt.Sprintf("%02d", report.ReportedTCB.BootLoader))
	params.Add("teeSPL", fmt.Sprintf("%02d", report.ReportedTCB.TEE))
	params.Add("snpSPL", fmt.Sprintf("%02d", report.ReportedTCB.SNP))
	params.Add("ucodeSPL", fmt.Sprintf("%02d", report.ReportedTCB.Microcode))

	reqUrl.RawQuery = params.Encode()

	res, err := http.Get(reqUrl.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	vcekDerBytes, _ := io.ReadAll(res.Body)
	defer res.Body.Close()

	cert, err := x509.ParseCertificate(vcekDerBytes)
	if err != nil {
		return nil, err
	}

	vcek := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return vcek, err
}
