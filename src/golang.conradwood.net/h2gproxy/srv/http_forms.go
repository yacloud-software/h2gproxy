package srv

import (
	"net/url"
	"strings"
)

type parsed_request struct {
	submitted_fields map[string]string
}

func NewParsedForm(f *FProxy) (*parsed_request, error) {
	err := f.req.ParseForm()
	if err != nil {
		return nil, err
	}

	res := &parsed_request{}

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

func (pr *parsed_request) RequestValues() map[string]string {
	return pr.submitted_fields
}
