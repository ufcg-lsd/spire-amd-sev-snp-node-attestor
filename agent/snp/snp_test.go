package snp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	agent "snp/agent/snp"
	snp "snp/common"
	server "snp/server/snp"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	reportInvalidSignature = []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 8, 115, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 149, 7, 181, 57, 27, 61, 248, 121, 114, 49, 11, 141, 43, 197, 138, 100, 50, 179, 33, 165, 33, 255, 87, 157, 102, 71, 130, 130, 169, 154, 139, 141, 177, 198, 128, 57, 71, 175, 255, 6, 141, 140, 145, 143, 35, 13, 254, 163, 124, 175, 171, 189, 75, 202, 86, 14, 235, 22, 84, 230, 222, 83, 166, 160, 67, 28, 0, 195, 108, 67, 182, 135, 5, 229, 76, 117, 68, 131, 13, 31, 44, 245, 54, 166, 243, 185, 74, 153, 29, 30, 71, 93, 154, 136, 178, 170, 142, 68, 129, 232, 16, 123, 117, 200, 183, 97, 194, 53, 124, 14, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 129, 30, 68, 11, 61, 252, 216, 206, 107, 159, 212, 62, 154, 15, 231, 161, 231, 160, 19, 31, 231, 197, 197, 43, 248, 77, 52, 60, 213, 29, 142, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 141, 70, 54, 194, 104, 179, 189, 82, 91, 66, 157, 51, 60, 40, 39, 60, 252, 182, 56, 116, 248, 207, 247, 143, 166, 19, 136, 112, 2, 153, 14, 254, 199, 12, 76, 83, 139, 172, 94, 8, 67, 113, 243, 215, 102, 89, 54, 10, 142, 81, 87, 213, 231, 88, 128, 87, 167, 21, 168, 39, 45, 186, 3, 0, 0, 0, 0, 0, 8, 115, 4, 52, 1, 0, 4, 52, 1, 0, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 60, 221, 113, 241, 158, 55, 3, 15, 225, 131, 54, 240, 5, 99, 174, 37, 217, 35, 229, 32, 6, 218, 152, 44, 111, 102, 82, 252, 76, 223, 8, 222, 13, 44, 227, 86, 108, 178, 95, 61, 32, 15, 22, 64, 203, 68, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 193, 226, 109, 146, 218, 155, 190, 207, 185, 237, 104, 194, 175, 54, 61, 86, 188, 77, 170, 196, 212, 86, 181, 103, 55, 136, 67, 52, 61, 203, 45, 27, 245, 234, 155, 36, 217, 122, 210, 67, 40, 149, 140, 109, 162, 250, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reportInvalidLength    = []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 8, 115, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 149, 7, 181, 57, 27, 61, 248, 121, 114, 49, 11, 141, 43, 197, 138, 100, 50, 179, 33, 165, 33, 255, 87, 157, 102, 71, 130, 130, 169, 154, 139, 141, 177, 198, 128, 57, 71, 175, 255, 6, 141, 140, 145, 143, 35, 13, 254, 163, 124, 175, 171, 189, 75, 202, 86, 14, 235, 22, 84, 230, 222, 83, 166, 160, 67, 28, 0, 195, 108, 67, 182, 135, 5, 229, 76, 117, 68, 131, 13, 31, 44, 245, 54, 166, 243, 185, 74, 153, 29, 30, 71, 93, 154, 136, 178, 170, 142, 68, 129, 232, 16, 123, 117, 200, 183, 97, 194, 53, 124, 14, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 129, 30, 68, 11, 61, 252, 216, 206, 107, 159, 212, 62, 154, 15, 231, 161, 231, 160, 19, 31, 231, 197, 197, 43, 248, 77, 52, 60, 213, 29, 142, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 141, 70, 54, 194, 104, 179, 189, 82, 91, 66, 157, 51, 60, 40, 39, 60, 252, 182, 56, 116, 248, 207, 247, 143, 166, 19, 136, 112, 2, 153, 14, 254, 199, 12, 76, 83, 139, 172, 94, 8, 67, 113, 243, 215, 102, 89, 54, 10, 142, 81, 87, 213, 231, 88, 128, 87, 167, 21, 168, 39, 45, 186, 3, 0, 0, 0, 0, 0, 8, 115, 4, 52, 1, 0, 4, 52, 1, 0, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 60, 221, 113, 241, 158, 55, 3, 15, 225, 131, 54, 240, 5, 99, 174, 37, 217, 35, 229, 32, 6, 218, 152, 44, 111, 102, 82, 252, 76, 223, 8, 222, 13, 44, 227, 86, 108, 178, 95, 61, 32, 15, 22, 64, 203, 68, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 193, 226, 109, 146, 218, 155, 190, 207, 185, 237, 104, 194, 175, 54, 61, 86, 188, 77, 170, 196, 212, 86, 181, 103, 55, 136, 67, 52, 61, 203, 45, 27, 245, 234, 155, 36, 217, 122, 210, 67, 40, 149, 140, 109, 162, 250, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	report                 = []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 8, 115, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 149, 7, 181, 57, 27, 61, 248, 121, 114, 49, 11, 141, 43, 197, 138, 100, 50, 179, 33, 165, 33, 255, 87, 157, 102, 71, 130, 130, 169, 154, 139, 141, 177, 198, 128, 57, 71, 175, 255, 6, 141, 140, 145, 143, 35, 13, 254, 163, 124, 175, 171, 189, 75, 202, 86, 14, 235, 22, 84, 230, 222, 83, 166, 160, 67, 28, 0, 195, 108, 67, 182, 135, 5, 229, 76, 117, 68, 131, 13, 31, 44, 245, 54, 166, 243, 185, 74, 153, 29, 30, 71, 93, 154, 136, 178, 170, 142, 68, 129, 232, 16, 123, 117, 200, 183, 97, 194, 53, 124, 14, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 129, 30, 68, 11, 61, 252, 216, 206, 107, 159, 212, 62, 154, 15, 231, 161, 231, 160, 19, 31, 231, 197, 197, 43, 248, 77, 52, 60, 213, 29, 142, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 141, 70, 54, 194, 104, 179, 189, 82, 91, 66, 157, 51, 60, 40, 39, 60, 252, 182, 56, 116, 248, 207, 247, 143, 166, 19, 136, 112, 2, 153, 14, 254, 199, 12, 76, 83, 139, 172, 94, 8, 67, 113, 243, 215, 102, 89, 54, 10, 142, 81, 87, 213, 231, 88, 128, 87, 167, 21, 168, 39, 45, 186, 3, 0, 0, 0, 0, 0, 8, 115, 4, 52, 1, 0, 4, 52, 1, 0, 3, 0, 0, 0, 0, 0, 8, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 60, 221, 113, 241, 158, 55, 3, 15, 225, 131, 54, 240, 5, 99, 174, 37, 217, 35, 229, 32, 6, 218, 152, 44, 111, 102, 82, 252, 76, 223, 8, 222, 13, 44, 227, 86, 108, 178, 95, 61, 32, 15, 22, 64, 203, 68, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 193, 226, 109, 146, 218, 155, 190, 207, 185, 237, 104, 194, 175, 54, 61, 86, 188, 77, 170, 196, 212, 86, 181, 103, 55, 136, 67, 52, 61, 203, 45, 27, 245, 234, 155, 36, 217, 122, 210, 67, 40, 149, 140, 109, 162, 250, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	amdCertChain           = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----
`
	validEK = `
-----BEGIN CERTIFICATE-----
MIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD
VQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs
YXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl
czESMBAGA1UEAwwJU0VWLU1pbGFuMB4XDTIyMTIxNzAxMTAyNFoXDTI5MTIxNzAx
MTAyNFowejEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYD
VQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk
IE1pY3JvIERldmljZXMxETAPBgNVBAMMCFNFVi1WQ0VLMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEzksyQYOI7jIXUuHuNk1bT30EgSgdM3vnNOZxOc8qGq8QPQGVVlmt
M1YqlqAY+6pAPIBmT1tnQ6NJcF2qDtg2veeNYY8Zstr9hXkN53R8cncouroYCPjy
hHLnXxA4HqFgo4IBFjCCARIwEAYJKwYBBAGceAEBBAMCAQAwFwYJKwYBBAGceAEC
BAoWCE1pbGFuLUIwMBEGCisGAQQBnHgBAwEEAwIBAzARBgorBgEEAZx4AQMCBAMC
AQAwEQYKKwYBBAGceAEDBAQDAgEAMBEGCisGAQQBnHgBAwUEAwIBADARBgorBgEE
AZx4AQMGBAMCAQAwEQYKKwYBBAGceAEDBwQDAgEAMBEGCisGAQQBnHgBAwMEAwIB
CDARBgorBgEEAZx4AQMIBAMCAXMwTQYJKwYBBAGceAEEBEAgAo1GNsJos71SW0Kd
MzwoJzz8tjh0+M/3j6YTiHACmQ7+xwxMU4usXghDcfPXZlk2Co5RV9XnWIBXpxWo
Jy26MEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B
AQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBA4ICAQCFTrPXeXJOsrNEwZ4YU6x+
44QQvXspNNXh44JF452sJ1vHZK1NTQmfIWp+8ywUBxIxdcqNPNbyjPzSYEGjSR3i
HxMJxDDBqiyBWdwAMBVhJWpCOhMSVPBia9yHdHJgaua4jCRe6Dya4O4sSzKxNhiI
bjSq1XUZjv5snP48pe5DFQEgHu0HV9C5+GeZVTylt8Hd8fgqmCEvVqevEzMJsmvo
ncgD/sAJ1IAOpNnMVdxkbqNX5DwO0KpZBk/NOblCQMpNe6So2ed2Zwg3r/GJqVXy
HhT6snOw+hFNTu/iagYp0qN+cRKTwfavWkgiuCPSS1tWIb/EfdmeI7ZnkXOe8aAG
aQ92KU/rkZM8hBKHDfcq2S47JQU60s9TkFZkcCGCAuHvsPHhxBH511FmvsZYV25H
3QMYT+eXc8Gk2DnY5j79nZ/MfvgklvRQSXSDxh3bLws5zzo+IdMMvJ8E701tWaST
hyGVbBncrAOPd9zfJmqvG8uRSPeOFmsoscZhnMaE/fPdithqvpgnIW4dbVq/UlGR
6kNbfzeWu5fOoRMlJiEf7gvBFhKG0F2p7WZfVq4OHvTkADRrNBT6rBVJ+ZTveFXQ
+8xPLUvhOqWnZGSQ3e1AcUlVjx0rG551nF+GgyItlVvpi/txTc5Osb0lk4zXoXx9
DKpJt0E2bgfzQnLqhkHnog==
-----END CERTIFICATE-----`

	invalidEK = `
-----BEGIN CERTIFICATE-----
MIIDZzCCAk+gAwIBAgIUcL7A9bGVTX3iJQJGd/pa55HnXZgwDQYJKoZIhvcNAQEL
BQAwQzELMAkGA1UEBhMCQlIxCzAJBgNVBAgMAlBCMQswCQYDVQQHDAJDRzEMMAoG
A1UECgwDTFNEMQwwCgYDVQQLDANMU0QwHhcNMjMwODMxMTMxMDMzWhcNMjMwOTMw
MTMxMDMzWjBDMQswCQYDVQQGEwJCUjELMAkGA1UECAwCUEIxCzAJBgNVBAcMAkNH
MQwwCgYDVQQKDANMU0QxDDAKBgNVBAsMA0xTRDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMHBg1h+5gVgLp82NHlIejegp7rMSAmPbhb/7+M3r8rg2ibW
V3b7ohZWTMVqZY2kIlek4CNxhhetiG46hgz01QnjdnSq61LobFnNba8SztjCK9wo
t62ttsF4FYHzrMx4n5MwpDOQIJtVOpgwTaou5hrBl6KEylwJF0v+Qd8vHkRnIaoj
ek/uOx0LKdyOBJ03hqZHfrhdR7KEjY20lEcSLbMIb74HvP9zncADDnCRnp0J2QtS
AZ0WcQJwqE68tyAuPFMFacj0VTZRBUM9rAXgSB67kRC1ZjEXZos7gmS6rIiknF7w
8Aykn+SWWn2PhGv417tOlPgDjcEx/XwDOQhUBKECAwEAAaNTMFEwHQYDVR0OBBYE
FGnzxc+z4g0fI2JglBeOynigZbLtMB8GA1UdIwQYMBaAFGnzxc+z4g0fI2JglBeO
ynigZbLtMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJUEz5Hx
e/iIXf6nZFW4lZK/4FSpICNvVzJgADZkoYi392+ztHzJIWoXPWynTU2oOR4Z0OyO
H/by3g9f2zvLGP4EkW5AMBcarF4bqVjdrL6kOb/PJ+RLVvREYJEIAsZCaeP5Xws7
/rOChZi3jjhlG8EKQtqA/XvG8rrUC1nHcJGJqdr9Bts6l/v2zYQRJlDD9fU+JcpA
4Au8ICLOq46Nd3PVULBklkZvPG8LaNimfaxJPxuFRUGdqYkN12Pg3F3XoRIKADwL
5HaFpaY5vhiR5PDzZmuzm77ztkraBqWYXk5h/OW/kbMuVsJh8Z8EgjQjpxr0yxdp
XJ1Gm64MrJOzMuU=
-----END CERTIFICATE-----`
)

type testCases struct {
	name               string
	key                string
	hcl_amd_cert_chain string
	err                string
	report             []byte
}

func TestAttestor(t *testing.T) {

	dir := setup(t)
	testCases := []testCases{
		{
			name:               "error invalid ek",
			key:                invalidEK,
			hcl_amd_cert_chain: fmt.Sprintf("amd_cert_chain = \"%s\"\n", dir+"/cert_chain.pem"),
			err:                "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = InvalidArgument desc = unable to validate ek with AMD cert chain: x509: certificate signed by unknown authority",
		},
		{
			name:               "error report with wrong",
			hcl_amd_cert_chain: fmt.Sprintf("amd_cert_chain = \"%s\"\n", dir+"/cert_chain.pem"),
			err:                "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = invalid nonce received in report: <nil>",
			report:             report,
		},

		{
			name:               "error report invalid signature",
			hcl_amd_cert_chain: fmt.Sprintf("amd_cert_chain = \"%s\"\n", dir+"/cert_chain.pem"),
			err:                "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = unable to validate guest report against ek: <nil>",
			report:             reportInvalidSignature,
		},
		{
			name:               "error report invalid signature",
			hcl_amd_cert_chain: fmt.Sprintf("amd_cert_chain = \"%s\"\n", dir+"/cert_chain.pem"),
			err:                "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = invalid report size: invalid report length, expected: 1184, but received: 1181",
			report:             reportInvalidLength,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			agentPlugin := loadAgentPlugin(t, "")
			serverPlugin := loadServerPlugin(t, tc.hcl_amd_cert_chain)
			attribs, err := doAttestationFlow(t, agentPlugin, serverPlugin, tc)

			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, attribs)
		})
	}

}
func doAttestationFlow(t *testing.T, agentPlugin agentnodeattestorv1.NodeAttestorClient, serverPlugin servernodeattestorv1.NodeAttestorClient, tc testCases) (*servernodeattestorv1.AgentAttributes, error) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentStream, err := agentPlugin.AidAttestation(ctx)

	defer agentStream.Context().Done()

	if err != nil {
		return nil, status.Errorf(codes.Canceled, "failed opening agent AidAttestation stream: %v", err)
	}

	serverStream, err := serverPlugin.Attest(ctx)

	if err != nil {
		return nil, status.Errorf(codes.Canceled, "failed opening server Attest stream: %v", err)
	}

	agentResponse, err := agentStream.Recv()

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to receive payload from agent plugin: %v", err)
	}

	require.NotEmpty(t, agentResponse.GetPayload(), "agent plugin responded with an empty payload")

	if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
		Request: &servernodeattestorv1.AttestRequest_Payload{
			Payload: agentResponse.GetPayload(),
		},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send payload to server plugin: %v", err)
	}
	for {

		serverResponse, err := serverStream.Recv()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to receive response from server plugin: %v", err)
		}

		if attribs := serverResponse.GetAgentAttributes(); attribs != nil {
			return attribs, nil
		}

		require.NotEmpty(t, serverResponse.GetChallenge(), "server plugin responded with an empty challenge")

		if err := agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: serverResponse.GetChallenge(),
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challenge to agent plugin: %v", err)
		}

		agentResp, err := agentStream.Recv()

		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to receive challenge response from agent plugin: %v", err)
		}

		require.Nil(t, agentResp.GetPayload(), "agent plugin responded with a payload instead of a challenge")
		require.NotEmpty(t, agentResp.GetChallengeResponse(), "agent plugin responded with an empty challenge response")

		attestationData := agentResp.GetChallengeResponse()
		if tc.key != "" {
			attestationData, err = json.Marshal(snp.AttestationRequest{
				Report: agentResp.GetChallengeResponse()[:1184],
				Cert:   []byte(tc.key),
			})
		} else if tc.report != nil {
			attestationData, err = json.Marshal(snp.AttestationRequest{
				Report: tc.report,
				Cert:   []byte(validEK),
			})
		}

		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
		}

		if err := serverStream.Send(&servernodeattestorv1.AttestRequest{
			Request: &servernodeattestorv1.AttestRequest_ChallengeResponse{
				ChallengeResponse: attestationData,
			},
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to send challange response to server plugin: %v", err)
		}
	}
}
func loadAgentPlugin(t *testing.T, hclConfig string) agentnodeattestorv1.NodeAttestorClient {

	pluginAgent := new(agent.Plugin)

	nodeAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: agentnodeattestorv1.NodeAttestorPluginServer(pluginAgent),
		PluginClient: nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(pluginAgent),
		},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "domain.test",
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func loadServerPlugin(t *testing.T, hclConfig string) servernodeattestorv1.NodeAttestorClient {

	pluginServer := new(server.Plugin)
	nodeAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: servernodeattestorv1.NodeAttestorPluginServer(pluginServer),
		PluginClient: nodeAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(pluginServer),
		},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "domain.test",
		},
	})
	require.NoError(t, err)
	return nodeAttestorClient
}

func setup(t *testing.T) string {
	dir := t.TempDir()

	f2, _ := os.Create(dir + "/cert_chain.pem")
	f2.Close()

	f3, _ := os.Create(dir + "/invalidvcek.pem")
	f3.Close()

	os.WriteFile(dir+"/vcek.pem", []byte(validEK), 0644)
	os.WriteFile(dir+"/cert_chain.pem", []byte(amdCertChain), 0644)
	os.WriteFile(dir+"/invalidvcek.pem", []byte(invalidEK), 0644)

	return dir
}
