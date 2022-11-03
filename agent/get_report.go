package main

import (
	"log"
	"os/exec"
)

func GetReport(pathToSave, nonceFile, pathToGetReportBin string) {
	cmd := exec.Command("sudo", pathToGetReportBin, "-f", nonceFile, pathToSave)

	err := cmd.Run()

	if err != nil {
		log.Fatal(err)
	}
}
