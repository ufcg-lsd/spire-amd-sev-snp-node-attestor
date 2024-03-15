package snp

import (
	"encoding/json"
	"encoding/pem"

	"io"
	"net/http"
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
