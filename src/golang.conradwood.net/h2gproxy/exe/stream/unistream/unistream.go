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
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/grpchelpers"
	"golang.conradwood.net/h2gproxy/shared"
	"golang.conradwood.net/h2gproxy/stream"
)

const (
	MAX_IDLE_TIME = time.Duration(120) * time.Second // if no packet processed for this time, abort connection
)

/*
one streamer is responsible for exactly one http request
*/
type Streamer struct {
	chan_watchdog       chan bool
	run_watchdog        bool
	abort               bool
	con                 grpchelpers.GRPCConnection
	stream              grpchelpers.ClientStream
	reqdetails          stream.RequestDetails
	size                uint64
	last_packet_handled time.Time
}

func Stream(reqdetails stream.RequestDetails) {
	streamer := &Streamer{
		reqdetails:    reqdetails,
		chan_watchdog: make(chan bool),
	}
	streamer.Stream()
}

func (s *Streamer) Stream() {
	ctx, cf := s.reqdetails.UserContext()
	s.run_watchdog = true
	go s.stream_watchdog(cf)
	err := s.streamWithErr(ctx)
	s.run_watchdog = false
	close(s.chan_watchdog)
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
	ctx.Done()
	cf()
}
func (s *Streamer) streamWithErr(ctx context.Context) error {
	var err error
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
	p := utils.ProgressReporter{
		Prefix: fmt.Sprintf("download for %s@%s of %s", auth.UserIDString(rd.GetUser()), rd.PeerIP(), filepath.Base(s.reqdetails.RequestedPath())),
	}
	for !s.abort {
		s.last_packet_handled = time.Now()
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
		if s.abort {
			// don't send stuff to browser if we are aborting
			break
		}
		// check for meta data and set appropriate headers
		s.parse_response_for_headers(backend_message.Response)
		bytes_from_backend = bytes_from_backend + uint64(len(backend_message.Data))
		if len(backend_message.Data) != 0 {
			p.Add(uint64(len(backend_message.Data)))
			//fmt.Printf("Received %d bytes\n", len(backend_message.Data))
			err := s.reqdetails.Write(backend_message.Data)
			if err != nil {
				return err
			}
		}
		p.SetTotal(s.size)
		p.Print()
	}
	fmt.Printf("in total, received %d bytes from backend\n", bytes_from_backend)
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
		s.size = msg.Size
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

func (s *Streamer) stream_watchdog(cf context.CancelFunc) {
	for s.run_watchdog {
		suc := true
		select {
		case <-time.After(time.Duration(5) * time.Second):
			//
		case _, suc = <-s.chan_watchdog:
			//
		}
		if !suc {
			fmt.Printf("Watchdog requested to stop\n")
		}

		if time.Since(s.last_packet_handled) > MAX_IDLE_TIME {
			s.abort = true
			fmt.Printf("Watchdog: cancelling\n")
			cf()
			break
		}
	}
	fmt.Printf("Watchdog finished\n")

}
