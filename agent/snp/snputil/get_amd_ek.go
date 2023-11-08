package snp

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
)

func GetVCEK() ([]byte, error) {
	url := "http://169.254.169.254/metadata/THIM/amd/certification"
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		fmt.Errorf("Unable to make an http request to the ek azure service:", err)
	}

	req.Header.Add("Metadata", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Error HTTP request:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Errorf("Response not OK:", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("Error reading rensponse body:", err)
	}

	var jsonData map[string]string
	if err := json.Unmarshal(body, &jsonData); err != nil {
		fmt.Errorf("Error JSON unmarshal:", err)
	}

	pemData := jsonData["vcekCert"] + jsonData["certificateChain"]

	pemBlock, _ := pem.Decode([]byte(pemData))
	if pemBlock == nil {
		fmt.Errorf("Error decoding PEM block")
	}

	key := pem.EncodeToMemory(pemBlock)

	return key, nil
}
