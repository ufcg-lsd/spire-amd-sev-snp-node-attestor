package snp_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	agentsnputil "snp/agent/snp/snputil"
	tpm "snp/common"
	snputil "snp/server/snp/snputil"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/Daviiap/go-tpm-tools/simulator"
)

var (
	svsmOnPremiseReport = []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 8, 115, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 149, 7, 181, 57, 27, 61, 248, 121, 114, 49, 11, 141, 43, 197, 138, 100, 50, 179, 33, 165, 33, 255, 87, 157, 102, 71, 130, 130, 169, 154, 139, 141, 177, 198, 128, 57, 71, 175, 255, 6, 141, 140, 145, 143, 35, 13, 254, 163, 124, 175, 171, 189, 75, 202, 86, 14, 235, 22, 84, 230, 222, 83, 166, 160, 67, 28, 0, 195, 108, 67, 182, 135, 5, 229, 76, 117, 68, 131, 13, 31, 44, 245, 54, 166, 243, 185, 74, 153, 29, 30, 71, 93, 154, 136, 178, 170, 142, 68, 129, 232, 16, 123, 117, 200, 183, 97, 194, 53, 124, 14, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 129, 30, 68, 11, 61, 252, 216, 206, 107, 159, 212, 62, 154, 15, 231, 161, 231, 160, 19, 31, 231, 197, 197, 43, 248, 77, 52, 60, 213, 29, 142, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 141, 70, 54, 194, 104, 179, 189, 82, 91, 66, 157, 51, 60, 40, 39, 60, 252, 182, 56, 116, 248, 207, 247, 143, 166, 19, 136, 112, 2, 153, 14, 254, 199, 12, 76, 83, 139, 172, 94, 8, 67, 113, 243, 215, 102, 89, 54, 10, 142, 81, 87, 213, 231, 88, 128, 87, 167, 21, 168, 39, 45, 186, 3, 0, 0, 0, 0, 0, 8, 115, 4, 52, 1, 0, 4, 52, 1, 0, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 60, 221, 113, 241, 158, 55, 3, 15, 225, 131, 54, 240, 5, 99, 174, 37, 217, 35, 229, 32, 6, 218, 152, 44, 111, 102, 82, 252, 76, 223, 8, 222, 13, 44, 227, 86, 108, 178, 95, 61, 32, 15, 22, 64, 203, 68, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 193, 226, 109, 146, 218, 155, 190, 207, 185, 237, 104, 194, 175, 54, 61, 86, 188, 77, 170, 196, 212, 86, 181, 103, 55, 136, 67, 52, 61, 203, 45, 27, 245, 234, 155, 36, 217, 122, 210, 67, 40, 149, 140, 109, 162, 250, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	svsmAzureReport     = []byte{72, 67, 76, 65, 1, 0, 0, 0, 42, 9, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 31, 0, 3, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 8, 210, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 38, 190, 98, 78, 88, 153, 26, 125, 231, 128, 154, 252, 192, 77, 37, 30, 143, 67, 154, 243, 120, 26, 122, 63, 197, 31, 244, 145, 131, 212, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 132, 148, 117, 173, 32, 57, 246, 185, 141, 85, 232, 150, 29, 244, 143, 75, 126, 179, 16, 48, 42, 123, 207, 175, 243, 133, 63, 222, 103, 132, 38, 113, 226, 12, 143, 229, 58, 216, 245, 77, 50, 98, 134, 184, 47, 156, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 86, 33, 88, 130, 168, 37, 39, 154, 133, 179, 0, 176, 183, 66, 147, 29, 17, 59, 247, 227, 45, 222, 46, 80, 255, 222, 126, 199, 67, 202, 73, 30, 205, 215, 243, 54, 220, 40, 166, 224, 178, 187, 87, 175, 122, 68, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 245, 206, 169, 40, 129, 147, 111, 159, 131, 22, 34, 244, 177, 186, 164, 140, 173, 90, 136, 205, 68, 171, 185, 89, 228, 170, 253, 39, 180, 88, 98, 151, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 8, 206, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 117, 56, 41, 199, 68, 111, 155, 22, 181, 196, 44, 156, 110, 120, 179, 254, 89, 29, 215, 164, 21, 11, 118, 126, 94, 20, 251, 105, 73, 44, 83, 228, 194, 180, 210, 91, 207, 233, 225, 161, 206, 113, 111, 224, 43, 179, 50, 168, 232, 218, 241, 122, 179, 172, 206, 82, 201, 21, 43, 29, 242, 34, 203, 3, 0, 0, 0, 0, 0, 8, 206, 4, 52, 1, 0, 4, 52, 1, 0, 3, 0, 0, 0, 0, 0, 8, 206, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 214, 204, 116, 185, 231, 237, 12, 222, 62, 91, 33, 171, 227, 115, 50, 242, 30, 198, 83, 151, 160, 251, 34, 131, 208, 253, 152, 130, 132, 230, 213, 227, 128, 173, 110, 12, 177, 27, 246, 235, 28, 250, 30, 61, 39, 230, 242, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 142, 248, 109, 207, 38, 228, 204, 41, 61, 228, 245, 209, 18, 50, 65, 153, 199, 133, 235, 157, 156, 60, 83, 253, 228, 179, 44, 10, 130, 77, 158, 234, 186, 192, 145, 159, 208, 103, 222, 195, 25, 252, 8, 207, 159, 154, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106, 4, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 86, 4, 0, 0, 123, 34, 107, 101, 121, 115, 34, 58, 91, 123, 34, 107, 105, 100, 34, 58, 34, 72, 67, 76, 65, 107, 80, 117, 98, 34, 44, 34, 107, 101, 121, 95, 111, 112, 115, 34, 58, 91, 34, 115, 105, 103, 110, 34, 93, 44, 34, 107, 116, 121, 34, 58, 34, 82, 83, 65, 34, 44, 34, 101, 34, 58, 34, 65, 81, 65, 66, 34, 44, 34, 110, 34, 58, 34, 115, 118, 72, 66, 82, 65, 65, 65, 107, 106, 98, 89, 66, 106, 89, 111, 101, 68, 115, 82, 66, 106, 73, 82, 48, 105, 80, 69, 120, 66, 98, 116, 72, 112, 116, 119, 87, 102, 52, 57, 104, 69, 82, 52, 66, 101, 107, 65, 98, 78, 73, 88, 98, 118, 84, 99, 103, 99, 68, 83, 66, 84, 70, 116, 122, 117, 53, 70, 71, 65, 77, 98, 65, 121, 84, 101, 115, 75, 82, 115, 52, 77, 100, 120, 118, 104, 54, 74, 72, 116, 104, 78, 69, 108, 68, 83, 50, 77, 72, 77, 118, 85, 66, 54, 51, 52, 97, 120, 83, 90, 77, 52, 111, 76, 76, 119, 97, 49, 82, 67, 86, 57, 102, 72, 80, 79, 88, 112, 81, 88, 78, 115, 56, 71, 85, 112, 111, 112, 77, 107, 71, 120, 104, 85, 106, 65, 76, 50, 85, 70, 87, 97, 51, 103, 53, 108, 122, 66, 90, 119, 97, 118, 105, 99, 50, 80, 118, 105, 97, 97, 103, 81, 82, 71, 78, 112, 97, 55, 111, 50, 81, 55, 48, 53, 74, 116, 110, 114, 89, 109, 72, 56, 84, 101, 49, 115, 83, 110, 56, 89, 66, 56, 121, 74, 89, 66, 101, 54, 114, 76, 83, 95, 54, 95, 120, 68, 101, 119, 81, 103, 66, 110, 98, 49, 87, 101, 106, 57, 67, 80, 105, 71, 74, 106, 54, 67, 55, 95, 79, 79, 83, 104, 122, 50, 57, 86, 104, 69, 89, 89, 70, 89, 67, 52, 57, 103, 87, 45, 53, 72, 114, 55, 90, 122, 52, 88, 121, 108, 76, 89, 102, 76, 55, 118, 69, 118, 56, 111, 73, 87, 56, 111, 114, 106, 51, 85, 73, 106, 81, 67, 68, 103, 85, 101, 99, 78, 97, 81, 82, 87, 52, 74, 117, 71, 107, 70, 69, 74, 67, 66, 57, 87, 117, 81, 82, 87, 121, 98, 81, 101, 56, 68, 115, 53, 72, 98, 116, 109, 120, 86, 48, 80, 116, 54, 120, 83, 54, 45, 110, 98, 53, 119, 34, 125, 44, 123, 34, 107, 105, 100, 34, 58, 34, 72, 67, 76, 69, 107, 80, 117, 98, 34, 44, 34, 107, 101, 121, 95, 111, 112, 115, 34, 58, 91, 34, 101, 110, 99, 114, 121, 112, 116, 34, 93, 44, 34, 107, 116, 121, 34, 58, 34, 82, 83, 65, 34, 44, 34, 101, 34, 58, 34, 65, 81, 65, 66, 34, 44, 34, 110, 34, 58, 34, 109, 75, 122, 82, 99, 65, 65, 66, 77, 71, 98, 51, 99, 116, 122, 121, 45, 54, 101, 89, 111, 101, 50, 89, 70, 66, 67, 66, 108, 45, 85, 108, 73, 76, 76, 70, 70, 105, 122, 68, 115, 95, 78, 71, 57, 86, 90, 56, 119, 102, 115, 73, 106, 74, 116, 95, 57, 98, 112, 103, 103, 106, 66, 49, 88, 83, 71, 83, 71, 113, 118, 81, 118, 118, 48, 101, 52, 119, 74, 98, 110, 108, 112, 108, 55, 72, 55, 109, 74, 67, 97, 49, 103, 106, 115, 117, 79, 120, 72, 48, 76, 117, 56, 87, 81, 99, 104, 103, 81, 117, 121, 111, 104, 98, 103, 74, 105, 75, 121, 111, 101, 95, 49, 109, 86, 97, 117, 122, 54, 113, 49, 52, 121, 78, 68, 48, 72, 73, 55, 79, 110, 73, 116, 105, 98, 107, 78, 122, 85, 117, 57, 76, 68, 121, 115, 45, 83, 98, 103, 98, 71, 53, 85, 51, 105, 99, 80, 120, 77, 112, 69, 101, 87, 103, 55, 106, 122, 54, 49, 71, 71, 56, 48, 49, 95, 77, 84, 122, 99, 102, 97, 68, 78, 108, 112, 56, 106, 78, 107, 118, 89, 83, 119, 121, 85, 106, 102, 67, 83, 106, 106, 112, 72, 112, 57, 100, 67, 119, 101, 84, 108, 116, 52, 76, 86, 99, 118, 65, 111, 122, 66, 82, 84, 97, 84, 106, 101, 54, 115, 89, 45, 50, 50, 97, 77, 108, 55, 120, 78, 115, 66, 110, 86, 114, 86, 117, 108, 70, 71, 116, 104, 98, 89, 57, 106, 83, 121, 117, 78, 51, 102, 99, 76, 101, 109, 81, 80, 53, 88, 102, 80, 66, 57, 95, 50, 52, 103, 73, 102, 65, 112, 78, 101, 116, 82, 78, 57, 53, 90, 73, 77, 55, 100, 97, 88, 77, 115, 85, 75, 57, 55, 115, 76, 97, 84, 112, 68, 120, 115, 73, 105, 65, 102, 86, 71, 112, 45, 98, 90, 108, 70, 80, 71, 97, 54, 122, 88, 87, 100, 88, 89, 119, 34, 125, 93, 44, 34, 118, 109, 45, 99, 111, 110, 102, 105, 103, 117, 114, 97, 116, 105, 111, 110, 34, 58, 123, 34, 99, 111, 110, 115, 111, 108, 101, 45, 101, 110, 97, 98, 108, 101, 100, 34, 58, 116, 114, 117, 101, 44, 34, 115, 101, 99, 117, 114, 101, 45, 98, 111, 111, 116, 34, 58, 116, 114, 117, 101, 44, 34, 116, 112, 109, 45, 101, 110, 97, 98, 108, 101, 100, 34, 58, 116, 114, 117, 101, 44, 34, 118, 109, 85, 110, 105, 113, 117, 101, 73, 100, 34, 58, 34, 66, 56, 49, 48, 48, 49, 57, 52, 45, 53, 50, 66, 66, 45, 52, 65, 55, 68, 45, 65, 52, 70, 69, 45, 69, 68, 51, 52, 49, 51, 52, 49, 65, 50, 67, 67, 34, 125, 44, 34, 117, 115, 101, 114, 45, 100, 97, 116, 97, 34, 58, 34, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

type Key struct {
	Kid    string   `json:"kid"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	E      string   `json:"e"`
	N      string   `json:"n"`
}

type VMConfiguration struct {
	ConsoleEnabled bool   `json:"console-enabled"`
	SecureBoot     bool   `json:"secure-boot"`
	TpmEnabled     bool   `json:"tpm-enabled"`
	VmUniqueID     string `json:"vmUniqueId"`
}

type RuntimeData struct {
	Keys            []Key           `json:"keys"`
	VMConfiguration VMConfiguration `json:"vm-configuration"`
	UserData        string          `json:"user-data"`
}

type TPMSimulator struct {
	*simulator.Simulator
}

func (s *TPMSimulator) OpenTPM(path ...string) (io.ReadWriteCloser, error) {
	expectedTPMDevicePath := "/dev/tpmrm0"

	if len(path) != 0 && path[0] != expectedTPMDevicePath {
		return nil, fmt.Errorf("unexpected TPM device path %q (expected %q)", path[0], expectedTPMDevicePath)
	}
	return struct {
		io.ReadCloser
		io.Writer
	}{
		ReadCloser: io.NopCloser(s),
		Writer:     s,
	}, nil
}

func (sim *TPMSimulator) createAK() error {
	akTemplate := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	akHandle, _, _, _, _, _, err := tpm2.CreatePrimaryEx(
		sim,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"",
		"",
		akTemplate,
	)
	if err != nil {
		return fmt.Errorf("error on creating EK: %v", err)
	}
	defer tpm2.FlushContext(sim, akHandle)

	err = tpm2.EvictControl(sim, "", tpm2.HandleOwner, akHandle, agentsnputil.TPMAKHandle)
	if err != nil {
		err = fmt.Errorf("error on persisting EK: %v", err)
	}

	return err
}

func (sim *TPMSimulator) createEndorsementCertificate() error {
	ekTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	ekHandle, _, _, _, _, _, err := tpm2.CreatePrimaryEx(
		sim,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"",
		"",
		ekTemplate,
	)
	if err != nil {
		return fmt.Errorf("error on creating EK: %v", err)
	}
	defer tpm2.FlushContext(sim, ekHandle)

	err = tpm2.EvictControl(sim, "", tpm2.HandleOwner, ekHandle, agentsnputil.TPMEKHandle)
	if err != nil {
		err = fmt.Errorf("error on persisting EK: %v", err)
	}

	return err
}

func (sim *TPMSimulator) saveSVSMOnPremiseReport(handle tpmutil.Handle) error {
	ek, _, _, _ := tpm2.ReadPublic(sim, agentsnputil.TPMEKHandle)

	ekhash2 := tpm.ParseMagicNumber(ek)
	hash2 := sha512.Sum512(ekhash2)
	offset := 0x50
	size := 512 / 8

	copy(svsmOnPremiseReport[offset:offset+size], hash2[:])

	reportWithoutSig, _ := snputil.SplitReportFromSignature(&svsmOnPremiseReport)

	r, s, err := signMessage(dir+"/keys/private/vcek/key.pem", reportWithoutSig)
	if err != nil {
		return fmt.Errorf("unable to sign report: %w", err)
	}

	copy(svsmOnPremiseReport[snputil.SIGNATURE_OFFSET:snputil.SIGNATURE_OFFSET+72], r[:])

	copy(svsmOnPremiseReport[snputil.SIGNATURE_OFFSET+72:snputil.SIGNATURE_OFFSET+144], s[:])

	err = tpm2.NVDefineSpace(sim,
		tpm2.HandlePlatform,
		handle,
		"",
		"",
		nil,
		tpm2.AttrPlatformCreate|tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrOwnerRead,
		uint16(len(svsmOnPremiseReport)))

	if err != nil {
		return fmt.Errorf("error on define space: %v", err)
	}

	err = tpm2.NVWrite(sim, tpm2.HandlePlatform, handle, "", svsmOnPremiseReport, 0)

	if err != nil {
		err = fmt.Errorf("error on writing report: %v", err)
	}

	return err
}

func (sim *TPMSimulator) saveSVSMAzureReport(handle tpmutil.Handle) error {
	ak, _, _, _ := tpm2.ReadPublic(sim, agentsnputil.TPMAKHandle)
	akPublicBlob, _ := ak.Encode()
	akPub, _ := tpm2.DecodePublic(akPublicBlob)
	akPubRSA, _ := tpm.ExtractRSAPublicKey(akPub)

	ek, _, _, _ := tpm2.ReadPublic(sim, agentsnputil.TPMAKHandle)
	ekPublicBlob, _ := ek.Encode()
	ekPub, _ := tpm2.DecodePublic(ekPublicBlob)
	ekPubRSA, _ := tpm.ExtractRSAPublicKey(ekPub)

	runtimeData, err := agentsnputil.GetRuntimeData(svsmAzureReport)
	if err != nil {
		return fmt.Errorf("error geting runtime data: %v", err)
	}
	var runtimeDataStruct RuntimeData
	json.Unmarshal([]byte(runtimeData), &runtimeDataStruct)

	for i, key := range runtimeDataStruct.Keys {
		if key.Kid == "HCLAkPub" {
			runtimeDataStruct.Keys[i].N = base64.RawURLEncoding.EncodeToString(akPubRSA.N.Bytes())
			E := new(big.Int).SetInt64(int64(akPubRSA.E))
			runtimeDataStruct.Keys[i].E = base64.RawURLEncoding.EncodeToString(E.Bytes())
		} else {
			runtimeDataStruct.Keys[i].N = base64.RawURLEncoding.EncodeToString(ekPubRSA.N.Bytes())
			E := new(big.Int).SetInt64(int64(ekPubRSA.E))
			runtimeDataStruct.Keys[i].E = base64.RawURLEncoding.EncodeToString(E.Bytes())
		}
	}
	runtimeData, _ = json.Marshal(runtimeDataStruct)
	copy(svsmAzureReport[1236:], runtimeData)

	runtimeHash := sha256.Sum256(runtimeData)
	copy(svsmOnPremiseReport[80:144], runtimeHash[:])

	reportWithoutSig, _ := snputil.SplitReportFromSignature(&svsmOnPremiseReport)
	r, s, err := signMessage(dir+"/keys/private/vcek/key.pem", reportWithoutSig)
	if err != nil {
		return fmt.Errorf("unable to sign report: %w", err)
	}

	copy(svsmOnPremiseReport[snputil.SIGNATURE_OFFSET:snputil.SIGNATURE_OFFSET+72], r[:])
	copy(svsmOnPremiseReport[snputil.SIGNATURE_OFFSET+72:snputil.SIGNATURE_OFFSET+144], s[:])

	copy(svsmAzureReport[agentsnputil.AzureReportPrefixZeros:agentsnputil.AzureReportPrefixZeros+1184], svsmOnPremiseReport)
	err = tpm2.NVDefineSpace(sim,
		tpm2.HandlePlatform,
		handle,
		"",
		"",
		nil,
		tpm2.AttrPlatformCreate|tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrOwnerRead,
		uint16(len(svsmAzureReport)))

	if err != nil {
		return fmt.Errorf("error on define space: %v", err)
	}

	err = tpm2.NVWrite(sim, tpm2.HandlePlatform, handle, "", svsmAzureReport, 0)

	if err != nil {
		err = fmt.Errorf("error on writing report: %v", err)
	}

	return err
}

func bigIntToLittleEndianBytes(num *big.Int, size int) []byte {
	bytes := num.Bytes()
	paddedBytes := make([]byte, size)

	copy(paddedBytes[size-len(bytes):], bytes)

	for i, j := 0, len(paddedBytes)-1; i < j; i, j = i+1, j-1 {
		paddedBytes[i], paddedBytes[j] = paddedBytes[j], paddedBytes[i]
	}

	return paddedBytes
}

func signMessage(privateKeyPath string, message []byte) ([72]byte, [72]byte, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return [72]byte{}, [72]byte{}, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return [72]byte{}, [72]byte{}, fmt.Errorf("failed to decode PEM block containing the private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return [72]byte{}, [72]byte{}, fmt.Errorf("failed to parse ECDSA private key: %v", err)
	}

	hash := sha512.Sum384(message)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return [72]byte{}, [72]byte{}, fmt.Errorf("failed to sign message: %v", err)
	}
	rBytes := bigIntToLittleEndianBytes(r, 72)
	sBytes := bigIntToLittleEndianBytes(s, 72)

	var rArray, sArray [72]byte
	copy(rArray[:], rBytes)
	copy(sArray[:], sBytes)

	return rArray, sArray, nil
}

func NewTPMSim(reportHandle tpmutil.Handle) (*TPMSimulator, error) {
	simulator, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	sim := &TPMSimulator{
		Simulator: simulator,
	}

	err = sim.createEndorsementCertificate()
	if err != nil {
		return nil, fmt.Errorf("unable to create endorsement certificate: %w", err)
	}

	if reportHandle == agentsnputil.SVSMOnPremiseSNPReportIndex {
		err = sim.saveSVSMOnPremiseReport(reportHandle)
	} else if reportHandle == agentsnputil.AzureSNPReportIndex {
		err = sim.createAK()
		if err != nil {
			return nil, fmt.Errorf("unable to create endorsement certificate: %w", err)
		}
		err = sim.saveSVSMAzureReport(reportHandle)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to save report: %w", err)
	}

	return sim, err
}
