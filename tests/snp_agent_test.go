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
	dir, _ = os.Getwd()
	vlek, _ = os.ReadFile(dir + "/vlek.pem")
	vcek, _ = os.ReadFile(dir + "/vcek.pem")

)

type testCases struct {
	conf          string
	name            string
	key             string
	err             string
	report          []byte
	VcekAMDCertChain string
	VlekAMDCertChain string
	VcekCRLUrl       string
	VlekCRLUrl       string
}

func TestAttestor(t *testing.T) {

	testCases := []testCases{
		{
			name:            "error invalid amd_cert_chain: using vlek, but trying to verify signature using vcek_cert_chain",
			key:             string(vlek),
			conf: fmt.Sprintf(`vcek_cert_chain = "%s"`, dir + "/vcek_cert_chain.pem"),
			report: report,
			err:             "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = InvalidArgument desc = unable to validate ek with AMD cert chain: x509: certificate signed by unknown authority",
		},
		{
			name:            "URL does not return the crl",
			key:             string(vcek),
			conf: fmt.Sprintf(`
				vcek_cert_chain = "%s"
				vcek_crl_url = "https://kdsintf.amd.com/vcek/v1/Rome/crl"
			`, dir+"/vcek_cert_chain.pem"),
			err:             "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Aborted desc = failed at CRL verification: couldn't fetch CRL using the provided URL and cache is empty",
			report:          report,
		},
		{	
			name:            "error report with invalid nonce",
			key:             string(vcek),
			conf: fmt.Sprintf(`
				vcek_cert_chain = "%s"
				vcek_crl_url = "https://kdsintf.amd.com/vcek/v1/Milan/crl"
			`, dir + "/vcek_cert_chain.pem"),
			report:          report,
			err:             "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = invalid nonce received in report: <nil>",
		},
		{
			name:            "error report invalid signature",
			key:             string(vcek),
			conf: fmt.Sprintf(`
				vcek_cert_chain = "%s"
				vcek_crl_url = "https://kdsintf.amd.com/vcek/v1/Milan/crl"
			`, dir + "/vcek_cert_chain.pem"),
			err:             "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = unable to validate guest report against ek: Invalid signature",
			report:          reportInvalidSignature,
		},
		{
			name:            "error invalid report length",
			conf: fmt.Sprintf(`
				vcek_cert_chain = "%s"
				vcek_crl_url = "https://kdsintf.amd.com/vcek/v1/Milan/crl"
			`, dir + "/vcek_cert_chain.pem"),
			err:             "rpc error: code = Internal desc = failed to receive response from server plugin: rpc error: code = Internal desc = invalid report size: invalid report length, expected: 1184, but received: 1181",
			report:          reportInvalidLength,
		},
	}

	for _, tc := range testCases {
		ek_cert_chain := snp.GetSigningKey(&tc.report)
		t.Run(tc.name, func(t *testing.T) {
			agentPlugin := loadAgentPlugin(t, "")
			var serverPlugin servernodeattestorv1.NodeAttestorClient
			if ek_cert_chain == 0 {
				serverPlugin = loadServerPlugin(t, tc.conf)
			} else {
				serverPlugin = loadServerPlugin(t, tc.conf)
			}
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
		if tc.key != "" && tc.report == nil{ 
			attestationData, err = json.Marshal(snp.AttestationDataRequest{
				Report: agentResp.GetChallengeResponse()[:1184],
				Cert:   []byte(tc.key),
			})
		} else if tc.report != nil {
			attestationData, err = json.Marshal(snp.AttestationDataRequest{
				Report: tc.report,
				Cert:   []byte(tc.key), 
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
