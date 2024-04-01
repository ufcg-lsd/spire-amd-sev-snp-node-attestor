package snp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	snp "snp/common"

	"io"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func GetVCEK() ([]byte, error) {
	url := "http://169.254.169.254/metadata/THIM/amd/certification"
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to make an http request to the ek azure service: %v", err)
	}

	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "Response not OK: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error reading rensponse body: %v", err)
	}

	var jsonData map[string]string
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return nil, status.Errorf(codes.Internal, "Error JSON unmarshal: %v", err)
	}

	pemData := jsonData["vcekCert"] + jsonData["certificateChain"]

	pemBlock, _ := pem.Decode([]byte(pemData))
	if pemBlock == nil {
		return nil, status.Error(codes.Internal, "Error decoding PEM block")
	}

	key := pem.EncodeToMemory(pemBlock)

	return key, nil
}

func GetVCEKFromAMD(report snp.AttestationReportExpanded) ([]byte, error) {
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
