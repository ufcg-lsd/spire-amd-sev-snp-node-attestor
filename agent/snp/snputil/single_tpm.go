package snp

import (
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
)

var once sync.Once

type single struct {
	rwc io.ReadWriteCloser
}

var tpmSingleInstance *single

func GetTPM() *single {
	if tpmSingleInstance == nil {
		once.Do(
			func() {
				rwc, err := tpm2.OpenTPM("/dev/tpm0")

				if err != nil {
					fmt.Errorf("can't open TPM at %q: %v", "/dev/tpm0", err)
				}

				tpmSingleInstance = &single{rwc}
			})
	}

	return tpmSingleInstance
}
