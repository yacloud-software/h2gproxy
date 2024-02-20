package srv

func option_handler(f *FProxy) {
	f.customHeaders(nil)
	f.SetHeader("Access-Control-Allow-Headers", "content-type")
	f.SetHeader("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
	f.WriteString("")
	f.Close()
	return
}
