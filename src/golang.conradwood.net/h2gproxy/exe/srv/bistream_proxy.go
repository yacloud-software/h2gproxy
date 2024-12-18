package srv

import (
	"fmt"

	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/h2gproxy/grpchelpers"

	//"golang.conradwood.net/go-easyops/utils"
	"io"
)

func BiStreamProxy(f *FProxy) {
	err := bistream_proxy_exe(f)
	if err != nil {
		f.Debugf("bistream proxy failed: %s\n", err)
	}
}

func bistream_proxy_exe(f *FProxy) error {
	/*
		b := f.RequestBody()
		fmt.Printf("Body length: %d\n", len(b))
		utils.WriteFile("/tmp/x.bin", b)
	*/
	form, err := f.GetForm()
	if err != nil {
		return err
	}

	auth_result, err := json_auth(f) // always check if we got auth stuff
	if err != nil {
		return err
	}

	svc := grpchelpers.GetGRPCConnection(f.hf.def.TargetService)
	f.Debugf("service: %s\n", svc)
	ctx, err := createContext(f, auth_result)
	if err != nil {
		return err
	}
	defer svc.Close()

	stream, err := svc.OpenStream(ctx, "StreamBiHTTP", true, true)
	if err != nil {
		return err
	}
	defer stream.Finish()
	f.Debugf("bistream proxy allocated new stream (%s)\n", stream)

	// stream the request to backend
	start := &pb.BiStreamRequest{HTTPRequest: &pb.StreamRequest{Path: f.RequestedPath()}}

	for k, v := range form.RequestValues() {
		p := &pb.Parameter{Name: k, Value: v}
		start.HTTPRequest.Parameters = append(start.HTTPRequest.Parameters, p)
	}
	err = stream.SendMsg(start)
	if err != nil {
		return err
	}

	// set up the streamer:
	fss := NewByteStreamSender(
		func(key, filename string) error {
			msg := &pb.BiStreamRequest{Data: &pb.StreamData{Key: key, Filename: filename}}
			return stream.SendMsg(msg)
		},
		func(b []byte) error {
			msg := &pb.BiStreamRequest{Data: &pb.StreamData{Data: b}}
			return stream.SendMsg(msg)
		},
	)

	// stream the uploaded files to backend
	files := form.GetFiles()
	f.Debugf("Sending %d files to backend\n", len(files))
	for _, file := range files {
		f.Debugf("sending file from field %s\n", file.Key())
		fss.SendBytes(file.Filename(), file.Key(), file.Data())
	}

	// stream the raw body to the backend
	fss.SendBytes("raw_body", "raw_body_file", f.RequestBody())
	err = stream.CloseSend()
	if err != nil {
		return err
	}

	// receive the response stream from backend
	msg := &pb.BiStreamResponse{}
	total_received := 0
	for {
		err := stream.RecvMsg(msg)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if msg.HTTPResponse != nil {
			resp := msg.HTTPResponse
			f.Debugf("receiving filename \"%s\"\n", resp.Filename)
			f.SetHeader("content-type", fmt.Sprintf("%s; charset=utf-8", resp.MimeType))
			f.SetHeader("content-length", fmt.Sprintf("%d", resp.Size))
			for k, v := range resp.ExtraHeaders {
				f.SetHeader(k, v)
			}
			code := 500
			if resp.StatusCode == 0 {
				code = 200
			} else {
				code = int(resp.StatusCode)
			}
			f.SetStatus(code)

		} else {
			//f.Debugf("message received: %s\n", msg)
			total_received = total_received + len(msg.Data)
			err := f.Write(msg.Data)
			if err != nil {
				fmt.Printf("failed to write data: %s\n", err)
				return err
			}
		}
	}
	f.Debugf("total bytes received: %d\n", total_received)

	return nil
}
