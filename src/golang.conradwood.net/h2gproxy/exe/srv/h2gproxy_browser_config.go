package srv

import (
	"flag"
	"fmt"

	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
)

const (
	CONFIG_COOKIE = `yacloud_h2gproxy_browser_config`
)

var (
	use_new_streamer      = flag.Bool("use_new_streamer", false, "if true use new streamping code")
	enable_browser_config = flag.Bool("enable_browser_config", false, "if true, allow client to configure some stuff in h2gproxy")
)

func config_h2gproxy_for_browser(f *FProxy) {
	br := browserconfig_default()

	if !*enable_browser_config {
		f.browserconfig = br
		return
	}

	for _, c := range f.SubmittedCookies() {
		if c.Name == CONFIG_COOKIE {
			err := utils.Unmarshal(c.Value, br)
			if err != nil {
				fmt.Printf("Invalid config cookie: %s\n", err)
			}
		}
	}
	new_streamer := f.RequestValues()["h2g_use_new_streamer"]
	changed := false
	if new_streamer != "" {
		if new_streamer == "true" {
			changed = true
			br.UseNewStreamer = true
		} else if new_streamer == "false" {
			changed = true
			br.UseNewStreamer = false
		}
	}
	if changed {
		s, err := utils.Marshal(br)
		if err != nil {
			fmt.Printf("Failed to marshal config cookie: %s\n", err)
		}
		f.AddCookie(&h2gproxy.Cookie{Name: CONFIG_COOKIE, Value: s})
	}
}

func browserconfig_default() *h2gproxy.BrowserConfig {
	res := &h2gproxy.BrowserConfig{
		UseNewStreamer: *use_new_streamer,
	}
	return res
}
