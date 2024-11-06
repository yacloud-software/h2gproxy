/*
grpc backend receives a unary request and responds with a stream

/*****************************
* streaming download proxy
*
* apitype: download
* Backend: rpc StreamHTTP(StreamRequest) returns (stream StreamDataResponse);
* StreamDataResponse includes a "StreamRespose" which must be sent before data
****************************
*/
package unistream

import (
	"fmt"
	"io"

	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/h2gproxy/grpchelpers"
	"golang.conradwood.net/h2gproxy/shared"
	"golang.conradwood.net/h2gproxy/stream"
)

/*
one streamer is responsible for exactly one http request
*/
type Streamer struct {
	con        grpchelpers.GRPCConnection
	stream     grpchelpers.ClientStream
	reqdetails stream.RequestDetails
}

func Stream(reqdetails stream.RequestDetails) {
	streamer := &Streamer{reqdetails: reqdetails}
	streamer.Stream()
}

func (s *Streamer) Stream() {
	err := s.streamWithErr()
	if err != nil {
		fmt.Printf("stream failed: %s\n", err)
		st := shared.ConvertErrorToCode(err)
		if st == 401 {
			// trigger authentication
			s.reqdetails.TriggerAuthentication()
		}
	} else {
		fmt.Printf("stream complete\n")
	}
}
func (s *Streamer) streamWithErr() error {
	var err error
	ctx := s.reqdetails.UserContext()
	s.con = grpchelpers.GetGRPCConnection(s.reqdetails.TargetService())
	s.stream, err = s.con.OpenStream(ctx, "StreamHTTP", false, true)
	if err != nil {
		fmt.Printf("Failed: %s\n", err)
		return err
	}
	defer s.con.Close()
	fmt.Printf("CON: %s\n", s.con.String())

	// build the request
	rd := s.reqdetails
	fcr := &h2gproxy.StreamRequest{
		Headers:    rd.H2GHeaders(),
		Path:       rd.RequestedPath(),
		Method:     "GET",
		Parameters: rd.H2GParameters(),
		Host:       rd.RequestedHost(),
		UserAgent:  rd.UserAgent(),
		SourceIP:   rd.PeerIP(),
		Query:      rd.RequestedQuery(),
		Port:       0,
		ByteRanges: rd.ByteRanges(),
	}

	// send the request
	if err := s.stream.SendMsg(fcr); err != nil {
		s.backend_failure(err)
		s.stream.Fail(err)
		return err
	}
	if err := s.stream.CloseSend(); err != nil {
		s.backend_failure(err)
		s.stream.Fail(err)
		return err
	}

	// now read stream from backend and copy to browser
	backend_message := &h2gproxy.StreamDataResponse{}
	bytes_from_backend := uint64(0)
	for {
		err := s.stream.RecvMsg(backend_message)
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != nil {
				s.backend_failure(err)
				s.stream.Fail(err)
				return err
			}
		}
		// check for meta data and set appropriate headers
		s.parse_response_for_headers(backend_message.Response)
		bytes_from_backend = bytes_from_backend + uint64(len(backend_message.Data))
		if len(backend_message.Data) != 0 {
			//fmt.Printf("Received %d bytes\n", len(backend_message.Data))
			err := s.reqdetails.Write(backend_message.Data)
			if err != nil {
				return err
			}
		}
	}
	fmt.Printf("Received %d bytes from backend\n", bytes_from_backend)
	return nil
}

func (s *Streamer) backend_failure(err error) {
	st := shared.ConvertErrorToCode(err)
	s.reqdetails.SetStatus(st)
}

func (s *Streamer) parse_response_for_headers(msg *h2gproxy.StreamResponse) {
	if msg == nil {
		return
	}
	if msg.StatusCode != 0 {
		s.reqdetails.SetStatus(int(msg.StatusCode))
	}
	if msg.Size != 0 {
		s.reqdetails.SetContentLength(msg.Size)
	}
	if msg.Filename != "" {
		s.reqdetails.SetFilename(msg.Filename)
	}
	if msg.MimeType != "" {
		s.reqdetails.SetContentType(msg.MimeType)
	}
	if msg.ExtraHeaders != nil {
		for k, v := range msg.ExtraHeaders {
			s.reqdetails.SetHeader(k, v)
		}
	}

}
