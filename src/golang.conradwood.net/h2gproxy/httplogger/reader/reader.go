package reader

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type LogReader interface {
	Read() (*Entry, error)
}
type reader struct {
	filename       string
	file           *os.File
	rd             *bufio.Reader
	started_lines  []string            // read-ahead
	finished_lines map[uint64]*EndLine // reqid -> read-ahead
}

type Entry struct {
	ReqID    uint64
	Duration time.Duration
	URL      string
	Code     int
	Message  string
}

func NewReader(filename string) (LogReader, error) {
	res := &reader{
		filename:       filename,
		finished_lines: make(map[uint64]*EndLine),
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	res.file = f
	res.rd = bufio.NewReader(res.file)
	return res, nil
}
func (r *reader) Read() (*Entry, error) {
	line, err := r.getNextStartLine()
	if err != nil {
		return nil, err
	}
	sl, err := parseStartLine(line)
	if err != nil {
		return nil, err
	}
	entry := &Entry{ReqID: sl.reqid, URL: sl.url}
	el, err := r.getEndLine(entry.ReqID)
	if err != nil {
		return nil, err
	}
	entry.Code = el.code
	entry.Duration = el.duration
	entry.Message = el.message
	return entry, nil
}

func (r *reader) getEndLine(reqid uint64) (*EndLine, error) {
	for {
		el, fd := r.finished_lines[reqid]
		if fd {
			return el, nil
		}
		var line string
		var err error
		line, err = r.rd.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		if err != nil {
			return nil, err
		}
		if strings.Contains(line, "] finished ") {
			err = r.addFinishLine(line)
			if err != nil {
				return nil, err
			}
		}
		if strings.Contains(line, "] started for") {
			r.started_lines = append(r.started_lines, line)
		}
	}
}
func (r *reader) getNextStartLine() (string, error) {
	for {
		var line string
		var err error
		if len(r.started_lines) != 0 {
			line = r.started_lines[0]
			r.started_lines = r.started_lines[1:]
		} else {
			line, err = r.rd.ReadString('\n')
		}
		line = strings.TrimSuffix(line, "\n")
		if err != nil {
			return line, err
		}
		if strings.Contains(line, "] finished ") {
			err = r.addFinishLine(line)
			if err != nil {
				return "", err
			}
		}
		if strings.Contains(line, "] started for") {
			return line, nil
		}
	}
}

func (r *reader) addFinishLine(line string) error {
	el, err := parseEndLine(line)
	if err != nil {
		return err
	}
	r.finished_lines[el.reqid] = el
	return nil
}

type EndLine struct {
	reqid    uint64
	code     int
	duration time.Duration
	message  string
}

func parseEndLine(line string) (*EndLine, error) {
	sx := strings.SplitN(line, " ", 6)
	if len(sx) != 6 {
		return nil, fmt.Errorf("endline must have 6 parts not %d", len(sx))
	}
	/*
		for i, s := range sx {
			fmt.Printf("sx[%d]=\"%s\"\n", i, s)
		}
	*/
	sl := &EndLine{}
	reqid, err := strconv.ParseUint(sx[1], 10, 64)
	if err != nil {
		return nil, err
	}
	sl.reqid = reqid

	sl.code, err = strconv.Atoi(sx[4])
	if err != nil {
		return nil, err
	}

	if sl.code != 200 {
		sl.message = sx[5]
	}
	secs_s := strings.TrimSuffix(sx[2], "s]")
	secs, err := strconv.ParseFloat(secs_s, 32)
	if err != nil {
		return nil, err
	}
	dur := time.Duration(secs * float64(time.Second))
	sl.duration = dur
	return sl, nil

}

type StartLine struct {
	reqid uint64
	url   string
}

func parseStartLine(line string) (*StartLine, error) {
	sx := strings.Split(line, " ")
	if len(sx) != 6 {
		return nil, fmt.Errorf("startline must have 6 parts not %d", len(sx))
	}
	/*
		for i, s := range sx {
			fmt.Printf("sx[%d]=\"%s\"\n", i, s)
		}
	*/
	sl := &StartLine{}
	reqid, err := strconv.ParseUint(sx[1], 10, 64)
	if err != nil {
		return nil, err
	}
	sl.reqid = reqid

	sl.url = sx[5]
	return sl, nil
}
