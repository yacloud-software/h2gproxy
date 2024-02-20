package srv

import (
	"errors"
	"flag"
	"fmt"
	h2g "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/prometheus"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/iphelper"
	"io"
	"net"
	"sync"
	"time"
)

var (
	disable_tcp        = flag.Bool("disable_tcp", false, "disable tcp forwarding")
	debug_tcp          = flag.Bool("debug_tcp", false, "debug tcp forwarding")
	currentConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "h2gproxy_current_tcp_forwarded_connections",
			Help: "gauge indicating current number of proxied tcp connections",
		},
		[]string{},
	)

	byteCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_tcp_bytes_proxied",
			Help: "bytes proxied",
		},
		[]string{"direction", "target", "targethost"},
	)
	connectCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_tcp_reconnects",
			Help: "counter for reconnects",
		},
		[]string{"target", "targethost", "statuscode"},
	)
)

// https://stackoverflow.com/questions/22421375/how-to-print-the-bytes-while-the-file-is-being-downloaded-golang
// PassThru wraps an existing io.Reader.
//
// It simply forwards the Read() call, while displaying
// the results from individual calls to it.
type PassThru struct {
	io.Reader
	total      int64
	direction  string
	target     string
	targethost string
}

// Read 'overrides' the underlying io.Reader's Read method.
// This is the one that will be called by io.Copy(). We simply
// use it to keep track of byte counts and then forward the call.
func (pt *PassThru) Read(p []byte) (int, error) {
	n, err := pt.Reader.Read(p)
	pt.total = pt.total + int64(n)
	byteCounter.With(prometheus.Labels{
		"target":     pt.target,
		"direction":  pt.direction,
		"targethost": pt.targethost}).Add(float64(n))

	return n, err
}

type TCPForwarder struct {
	session         *h2g.AddConfigHTTPRequest // this does not appear to be set ever..
	config          *h2g.AddConfigTCPRequest
	Port            int
	Path            string
	active          bool
	shutdownRequest bool
	listener        net.Listener
	lock            sync.Mutex
	conlock         sync.Mutex
	conctr          uint64
}

func init() {
	err := prometheus.Register(byteCounter)
	if err != nil {
		tcp_Printf("Failed to register byteCounter: %s\n", err)
	}
	err = prometheus.Register(connectCounter)
	if err != nil {
		tcp_Printf("Failed to register connectCounter: %s\n", err)
	}
	err = prometheus.Register(currentConnections)
	if err != nil {
		tcp_Printf("Failed to register currentConnectionsCounter: %s\n", err)
	}

}
func (tf *TCPForwarder) startPortAcceptLoop() error {
	if *disable_tcp {
		return nil
	}
	go tf.acceptLoop()
	go func() {
		for {
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", tf.Port))
			if err != nil {
				s := fmt.Sprintf("Failed to listen on port %d with intent to forward to %s: %s", tf.Port, tf.Path, err)
				fmt.Println(s)
				time.Sleep(5 * time.Second)
				continue
			}
			tf.listener = listener
			break
		}
	}()
	return nil
}

func (tf *TCPForwarder) acceptLoop() {
	tf.active = true
	for tf.listener == nil {
		time.Sleep(1 * time.Second)
	}
	for !tf.shutdownRequest {
		conn, err := tf.listener.Accept()
		incNumberOfConnections()

		// ignore subsequent errors on port shutdown
		if tf.shutdownRequest {
			break
		}
		if err != nil {
			s := fmt.Sprintf("Failed to forward port %d to %s: %s", tf.Port, tf.Path, err)
			fmt.Println(s)
			break
		}
		go tf.forward(conn)
	}
	tf.active = false
	tcp_Printf("Accept() on port %d stopped.\n", tf.Port)
}

// got an incoming connection, lookup target, forward and copy
// datastreams
func (tf *TCPForwarder) forward(incoming net.Conn) {
	if *debug_tcp {
		tcp_Printf("Got connection: %s\n", incoming.RemoteAddr())
	}
	defer decNumberOfConnections()
	defer incoming.Close()
	// set KeepAlive to detect broken connections
	tcp, ok := incoming.(*net.TCPConn)
	if !ok {
		tcp_Printf("Bad connection type: %v\n", incoming)
		return
	}
	if tf.config.KeepAliveSeconds > 0 {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(time.Second * time.Duration(tf.config.KeepAliveSeconds))
	}
	// lookup address
	con, err := client.DialTCPWrapper(tf.Path)
	if err != nil {
		tf.lock.Lock()
		defer tf.lock.Unlock()
		connectCounter.With(prometheus.Labels{
			"statuscode": fmt.Sprintf("%d", INTERNAL_ERROR_NO_TARGET),
			"target":     tf.Path,
			"targethost": ""}).Inc()

		s := fmt.Sprintf("Unable to lookup %s: %s\n", tf.Path, err)
		fmt.Print(s)

		time.Sleep(5) // we sleep while holding a lock
		// if we cannot forward the connection we want to slow down incoming connections
		// (trampling hurd)

		return
	}
	sess := newTCPProxySession(tf, incoming, con)
	defer con.Close()
	defer sess.Closed()
	if *debug_tcp {
		tcp_Printf("Forwarding to %s\n", con.RemoteAddr())
	}
	connectCounter.With(prometheus.Labels{
		"statuscode": "200",
		"target":     tf.Path,
		"targethost": con.RemoteAddr().String()}).Inc()

	if tf.config.AddHeaderToTCP {
		err := tf.send_header(con, tcp)
		if err != nil {
			fmt.Printf("Failed to send header: %s\n", err)
			return
		}
	}
	// we have bidrectional streams, so
	// keep copying from incoming->server
	// and server->incoming.
	// if EITHER one errors/eofs, shutdown the lot
	terminator := make(chan string)
	src := &PassThru{Reader: incoming,
		target:     tf.Path,
		targethost: con.RemoteAddr().String(),
		direction:  "in",
	}
	target := &PassThru{Reader: con,
		target:     tf.Path,
		targethost: con.RemoteAddr().String(),
		direction:  "out",
	}
	go func() {
		_, e := io.Copy(incoming, target)
		if e != nil {
			terminator <- fmt.Sprintf("internal service closed connection (%s)", e)
		} else {
			terminator <- fmt.Sprintf("internal service closed connection (no error)")
		}
	}()
	go func() {
		io.Copy(con, src)
		select {
		case terminator <- "remote peer (user) closed connection":
		//
		default:
			fmt.Printf("Remote peer closed connection AFTER connection was stopped\n")
		}
	}()
	end := <-terminator
	if *debug_tcp {
		tcp_Printf("Connection %s from %s terminated (%s). Bytes in: %d, Bytes out: %d\n",
			tf.Path, incoming.RemoteAddr(), end,
			src.total, target.total,
		)
	}
}

func (tf *TCPForwarder) Stop() error {
	tf.shutdownRequest = true
	if tf.listener != nil {
		tf.listener.Close()
		i := 30
		for tf.active {
			tcp_Printf("Waiting for shutdown %d...\n", i)
			time.Sleep(1 * time.Second)
			i--
			if i == 0 {
				return errors.New("Failed to shutdown listener")
			}
		}
	}
	return nil
}

func (tf *TCPForwarder) Forward() error {
	tcp_Printf("Forwarding %d to %s\n", tf.Port, tf.Path)
	err := tf.startPortAcceptLoop()
	if err != nil {
		return err
	}
	// is there any point in registering the forwarders?
	// they all register as h2gproxy/tcp ?
	/*
		tsd := server.NewTCPServerDef("h2gproxy.H2GProxyService")
		tsd.SetPort(tf.Port)
		server.AddRegistry(tsd)
	*/
	return nil
}

func (tf *TCPForwarder) create_connection_id() string {
	tf.conlock.Lock()
	defer tf.conlock.Unlock()
	res := fmt.Sprintf("con_%d", tf.conctr)
	tf.conctr++
	return res
}

// send a header down this tcp connection
func (tf *TCPForwarder) send_header(nc net.Conn, incoming *net.TCPConn) error {
	addr := incoming.RemoteAddr().String()
	ip, rport, _, err := iphelper.ParseEndpoint(addr)
	if err != nil {
		return err
	}
	header := &h2g.TCPStart{
		ConnectionID: tf.create_connection_id(),
		RemoteIP:     ip,
		RemotePort:   rport,
	}
	if *debug_tcp {
		fmt.Printf("[tcp] Sending header %v\n", header)
	}
	ms, err := utils.Marshal(header)
	if err != nil {
		return err
	}
	msb := []byte{1, 1} // start-byte  + version
	msb = append(msb, ([]byte(ms))...)
	msb = append(msb, 0) // stop-byte
	nb, err := nc.Write(msb)
	if err != nil {
		return err
	}
	if nb != len(msb) {
		return fmt.Errorf("odd write, wanted to write %d bytes, but wrote %d", len(msb), nb)
	}
	return nil
}

/**********************************
* current connections gauge
***********************************/
func incNumberOfConnections() {
	if *debug_tcp {
		tcp_Printf("got one more additional connection\n")
	}
	currentConnections.With(prometheus.Labels{}).Inc()
}
func decNumberOfConnections() {
	if *debug_tcp {
		tcp_Printf("closed one connection\n")
	}
	currentConnections.With(prometheus.Labels{}).Dec()
}

func tcp_Printf(format string, args ...interface{}) {
	fmt.Printf("[tcp]"+format, args...)
}
