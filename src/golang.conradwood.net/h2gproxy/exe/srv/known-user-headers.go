package srv

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

func (f *FProxy) IsKnownCLITool() bool {
	ua := strings.ToLower(f.GetUserAgent())
	for _, kc := range known_cli_download_tools {
		if strings.Contains(ua, strings.ToLower(kc)) {
			return true
		}
	}
	return false
}
