package srv

import (
	h2g "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
	"strconv"
	"strings"
)

// parseRange parses a Range header string as per RFC 7233.
// errNoOverlap is returned if none of the ranges overlap.
func parseByteRange(s string) ([]*h2g.ByteRange, error) {
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.Errorf("invalid range")
	}
	var ranges []*h2g.ByteRange
	noOverlap := false
	for _, ra := range strings.Split(s[len(b):], ",") {
		ra = byterange_TrimString(ra)
		if ra == "" {
			continue
		}
		i := strings.Index(ra, "-")
		if i < 0 {
			return nil, errors.Errorf("invalid range")
		}
		start, end := byterange_TrimString(ra[:i]), byterange_TrimString(ra[i+1:])
		r := &h2g.ByteRange{}
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file.
			// is that "-5000" means, "the last 5000 bytes" ?
			i, err := strconv.ParseUint(end, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid range")
			}
			r.Start = i
			r.Anchor = h2g.Anchor_FROM_END
		} else {
			// "500-1000":absolute range
			// or "500-" :from byte 500 to end
			i, err := strconv.ParseUint(start, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid range")
			}
			r.Start = i
			if end == "" {
				r.Anchor = h2g.Anchor_TO_END
			} else {
				i, err := strconv.ParseUint(end, 10, 64)
				if err != nil {
					return nil, errors.Errorf("invalid range")
				}
				r.End = i
				r.Anchor = h2g.Anchor_ABSOLUTE
			}
		}
		ranges = append(ranges, r)
	}
	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		return nil, nil
	}
	return ranges, nil
}

func byterange_TrimString(s string) string {
	for strings.HasPrefix(s, " ") {
		s = strings.TrimPrefix(s, " ")
	}
	for strings.HasSuffix(s, " ") {
		s = strings.TrimSuffix(s, " ")
	}
	return s
}
