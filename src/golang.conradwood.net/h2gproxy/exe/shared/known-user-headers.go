package shared

import (
	"strings"
)

var (
	known_cli_download_tools = []string{
		"Wget",
		"git",
		"ctools",
		"yacloud-fscache",
		"autodeployer",
	}
)

func IsKnownCLITool(useragent string) bool {
	ua := strings.ToLower(useragent)
	for _, kc := range known_cli_download_tools {
		if strings.Contains(ua, strings.ToLower(kc)) {
			return true
		}
	}
	return false
}
