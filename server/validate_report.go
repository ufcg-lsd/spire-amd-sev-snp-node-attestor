package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

func ValidateGuestReport(file *os.File, sevtoolBinPath string) error {
	cmd := exec.Command(sevtoolBinPath, "--validate_guest_report")

	res, err := cmd.Output()

	if err != nil {
		return err
	}

	if !strings.HasPrefix(string(res), "Guest report validated successfully!") {
		return errors.New("unable to validate guest report against vcek")
	}

	return nil
}
