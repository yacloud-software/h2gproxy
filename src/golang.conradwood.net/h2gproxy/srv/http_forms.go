package srv

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

type parsed_request struct {
	submitted_fields map[string]string
	f                *FProxy
	is_multi_part    bool
	parts            []*part
}
type part struct {
	filename string
	key      string
	data     []byte
}

func NewParsedForm(f *FProxy) (*parsed_request, error) {
	res := &parsed_request{
		submitted_fields: make(map[string]string),
		f:                f,
	}
	var err error
	if strings.Contains(f.GetContentType(), "multipart/form-data") {
		res.is_multi_part = true
		err = res.parse_multi_part_form()
		if err != nil {
			return nil, err
		}
	}

	err = f.req.ParseForm()
	if err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	// parse the form stuff
	for name, value := range f.req.Form {
		if len(value) < 1 {
			continue
		}
		res.submitted_fields[name] = value[0]
	}

	// special case - if we do post with content-type json, then submit the json as "body"
	// if it is a post we might have a funny url string (which are also values)
	// but we might also have other things.
	if f.req.Method == "POST" {
		ct := strings.ToLower(f.GetHeader("content-type"))
		if ct == "text/json" || ct == "application/json" {
			res.submitted_fields["body"] = string(f.RequestBody())
		} else {
			values, err := url.ParseQuery(string(f.RequestBody()))
			if err == nil {
				for k, v := range values {
					if len(v) < 1 {
						continue
					}
					res.submitted_fields[k] = v[0]
				}
			}
		}
	}

	return res, nil
}

/*
we need to parse the multi-part data outside the request, because we actually want the body as well as
the parsed form. The golang implementation of the request (specifically http.Request.ParseMultiPartForm()) reads
the body as stream, this results in an unexpected EOF if we have read the stream to the end before calling it (because the stream points to the end)
*/
func (pr *parsed_request) parse_multi_part_form() error {
	if !pr.is_multi_part {
		// this is not a form-data encoded request, so cannot have filenames
		return nil
	}
	//	max_mem := int64(1024 * 1024 * 1024 * 100)
	br := bytes.NewBuffer(pr.f.RequestBody()) // use the request body we retrieved earlier
	_, params, err := mime.ParseMediaType(pr.f.GetHeader("content-type"))
	if err != nil {
		return err
	}
	boundary := params["boundary"]

	mr := multipart.NewReader(br, boundary)
	for {
		mime_part, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("form parser error (part): %w", err)
		}
		pd, err := io.ReadAll(mime_part)
		if err != nil {
			return err
		}
		k := mime_part.FormName()
		if k == "" {
			mime_part.FileName()
		}
		pt := &part{filename: mime_part.FileName(), key: k, data: pd}
		pr.parts = append(pr.parts, pt)
		fmt.Printf("Filename: %s in \"%s\" (%d bytes)\n", mime_part.FileName(), pt.key, len(pt.data))
	}

	return nil
}
func (pr *parsed_request) GetFiles() []*part {
	return pr.parts
}

// fields (which are also in requestvalues()) which have a filename body
func (pr *parsed_request) FilenameFieldNames() []string {
	var res []string
	if !pr.is_multi_part {
		// this is not a form-data encoded request, so cannot have filenames
		return res
	}
	for _, p := range pr.parts {
		res = append(res, p.key)
	}
	return res
}

func (pr *parsed_request) RequestValues() map[string]string {
	return pr.submitted_fields
}

func (p *part) Filename() string {
	return p.filename
}
func (p *part) Key() string {
	return p.key
}
func (p *part) Data() []byte {
	return p.data
}
