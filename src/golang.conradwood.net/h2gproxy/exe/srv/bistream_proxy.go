package srv

import (
	"fmt"
	"strings"

	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/h2gproxy/grpchelpers"

	//"golang.conradwood.net/go-easyops/utils"
	"io"
)

func BiStreamProxy(f *FProxy) {
	err := bistream_proxy_exe(f)
	if err != nil {
		f.SetError(err)
		f.Debugf("bistream proxy failed: %s\n", errors.ErrorStringWithStackTrace(err))
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
		return errors.Wrap(err)
	}
	defer stream.Finish()
	f.Debugf("bistream proxy allocated new stream (%s)\n", stream)

	// stream the request to backend
	sreq := &pb.StreamRequest{
		Host:      strings.ToLower(f.clientReqHost),
		Path:      f.RequestedPath(),
		Method:    f.req.Method,
		UserAgent: f.req.UserAgent(),
		SourceIP:  fixIP(f.PeerIP()),
	}
	if f.req.URL != nil {
		sreq.Query = f.req.URL.RawQuery
	}
	for name, values := range f.req.Header {
		nh := &pb.Header{Name: name, Values: values}
		sreq.Headers = append(sreq.Headers, nh)
	}

	brs, err := parseByteRange(f.GetHeader("range"))
	if err != nil {
		return err
	}
	sreq.ByteRanges = brs

	start := &pb.BiStreamRequest{HTTPRequest: sreq}

	for k, v := range form.RequestValues() {
		p := &pb.Parameter{Name: k, Value: v}
		start.HTTPRequest.Parameters = append(start.HTTPRequest.Parameters, p)
	}
	err = stream.SendMsg(start)
	if err != nil {
		f.Debugf("bistream proxy unable to send first message\n")
		return errors.Wrap(err)
	}

	// set up the streamer:
	fss := NewByteStreamSender(
		func(key, filename string) error {
			msg := &pb.BiStreamRequest{Data: &pb.StreamData{Key: key, Filename: filename}}
			return errors.Wrap(stream.SendMsg(msg))
		},
		func(b []byte) error {
			msg := &pb.BiStreamRequest{Data: &pb.StreamData{Data: b}}
			return errors.Wrap(stream.SendMsg(msg))
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
		return errors.Wrap(err)
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
			return errors.Wrap(err)
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
