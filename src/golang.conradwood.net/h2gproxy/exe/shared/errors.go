package shared

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type HTTPError struct {
	ErrorCode           int
	ErrorString         string
	ExtendedErrorString string
	ErrorMessage        string
}

// mapping as per https://cloud.google.com/apis/design/errors
var grpcToHTTPMap = map[codes.Code]*HTTPError{
	codes.OK:                 {200, "ok", "", ""},
	codes.Unknown:            {500, "unknown method", "", ""},
	codes.InvalidArgument:    {400, "invalid argument", "", ""},
	codes.DeadlineExceeded:   {504, "deadline exceeded", "", ""},
	codes.NotFound:           {404, "not found", "", ""},
	codes.AlreadyExists:      {409, "resource already exists", "", ""},
	codes.PermissionDenied:   {403, "insufficient permission", "", ""},
	codes.ResourceExhausted:  {429, "out of resource quota", "", ""},
	codes.FailedPrecondition: {400, "not possible in current system state", "", ""},
	codes.Aborted:            {409, "concurrency conflict", "", ""},
	codes.OutOfRange:         {400, "invalid range specified", "", ""},
	codes.Unimplemented:      {501, "method not implemented", "", ""},
	codes.Internal:           {500, "internal server error", "", ""},
	codes.Unavailable:        {503, "service unavailable", "", ""},
	codes.DataLoss:           {500, "internal server error", "", ""},
	codes.Unauthenticated:    {401, "missing, invalid, or expired authentication", "", ""},
}

func GrpcToHTTP(code codes.Code) *HTTPError {
	he := grpcToHTTPMap[code]
	if he != nil {
		return he
	}
	return &HTTPError{500, "unknown error", fmt.Sprintf("GRPCCode:%d", code), ""}
}
func ConvertErrorToCode(err error) int {
	cd := status.Convert(err).Code()
	hr := grpcToHTTPMap[cd]
	if hr == nil {
		return 501
	}
	return hr.ErrorCode

}
