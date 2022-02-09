// Code generated by protoc-gen-go.
// source: golang.yacloud.eu/apis/payments/payments.proto
// DO NOT EDIT!

/*
Package payments is a generated protocol buffer package.

It is generated from these files:
	golang.yacloud.eu/apis/payments/payments.proto

It has these top-level messages:
	PingResponse
	HTTPPageRequest
	HTMLPage
	Payment
	LineItem
	ShoppingBasket
	Tokens
*/
package payments

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common "golang.conradwood.net/apis/common"
import h2gproxy "golang.conradwood.net/apis/h2gproxy"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type TokenType int32

const (
	TokenType_UNDEFINED      TokenType = 0
	TokenType_PROD_ACCESS    TokenType = 1
	TokenType_SANDBOX_ACCESS TokenType = 2
)

var TokenType_name = map[int32]string{
	0: "UNDEFINED",
	1: "PROD_ACCESS",
	2: "SANDBOX_ACCESS",
}
var TokenType_value = map[string]int32{
	"UNDEFINED":      0,
	"PROD_ACCESS":    1,
	"SANDBOX_ACCESS": 2,
}

func (x TokenType) String() string {
	return proto.EnumName(TokenType_name, int32(x))
}
func (TokenType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// comment: message pingresponse
type PingResponse struct {
	// comment: field pingresponse.response
	Response string `protobuf:"bytes,1,opt,name=Response" json:"Response,omitempty"`
}

func (m *PingResponse) Reset()                    { *m = PingResponse{} }
func (m *PingResponse) String() string            { return proto.CompactTextString(m) }
func (*PingResponse) ProtoMessage()               {}
func (*PingResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *PingResponse) GetResponse() string {
	if m != nil {
		return m.Response
	}
	return ""
}

type HTTPPageRequest struct {
	ServeRequest *h2gproxy.ServeRequest `protobuf:"bytes,1,opt,name=ServeRequest" json:"ServeRequest,omitempty"`
	PaymentID    uint64                 `protobuf:"varint,2,opt,name=PaymentID" json:"PaymentID,omitempty"`
}

func (m *HTTPPageRequest) Reset()                    { *m = HTTPPageRequest{} }
func (m *HTTPPageRequest) String() string            { return proto.CompactTextString(m) }
func (*HTTPPageRequest) ProtoMessage()               {}
func (*HTTPPageRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *HTTPPageRequest) GetServeRequest() *h2gproxy.ServeRequest {
	if m != nil {
		return m.ServeRequest
	}
	return nil
}

func (m *HTTPPageRequest) GetPaymentID() uint64 {
	if m != nil {
		return m.PaymentID
	}
	return 0
}

type HTMLPage struct {
	Path        string `protobuf:"bytes,1,opt,name=Path" json:"Path,omitempty"`
	Body        string `protobuf:"bytes,2,opt,name=Body" json:"Body,omitempty"`
	IsEmpty     bool   `protobuf:"varint,3,opt,name=IsEmpty" json:"IsEmpty,omitempty"`
	DoNotModify bool   `protobuf:"varint,4,opt,name=DoNotModify" json:"DoNotModify,omitempty"`
}

func (m *HTMLPage) Reset()                    { *m = HTMLPage{} }
func (m *HTMLPage) String() string            { return proto.CompactTextString(m) }
func (*HTMLPage) ProtoMessage()               {}
func (*HTMLPage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *HTMLPage) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *HTMLPage) GetBody() string {
	if m != nil {
		return m.Body
	}
	return ""
}

func (m *HTMLPage) GetIsEmpty() bool {
	if m != nil {
		return m.IsEmpty
	}
	return false
}

func (m *HTMLPage) GetDoNotModify() bool {
	if m != nil {
		return m.DoNotModify
	}
	return false
}

// a central object storing payment related information
type Payment struct {
	ID          uint64          `protobuf:"varint,1,opt,name=ID" json:"ID,omitempty"`
	Amount      uint64          `protobuf:"varint,2,opt,name=Amount" json:"Amount,omitempty"`
	Currency    string          `protobuf:"bytes,3,opt,name=Currency" json:"Currency,omitempty"`
	PayeeUserID string          `protobuf:"bytes,4,opt,name=PayeeUserID" json:"PayeeUserID,omitempty"`
	Basket      *ShoppingBasket `protobuf:"bytes,5,opt,name=Basket" json:"Basket,omitempty"`
	Occured     uint32          `protobuf:"varint,6,opt,name=Occured" json:"Occured,omitempty"`
}

func (m *Payment) Reset()                    { *m = Payment{} }
func (m *Payment) String() string            { return proto.CompactTextString(m) }
func (*Payment) ProtoMessage()               {}
func (*Payment) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Payment) GetID() uint64 {
	if m != nil {
		return m.ID
	}
	return 0
}

func (m *Payment) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *Payment) GetCurrency() string {
	if m != nil {
		return m.Currency
	}
	return ""
}

func (m *Payment) GetPayeeUserID() string {
	if m != nil {
		return m.PayeeUserID
	}
	return ""
}

func (m *Payment) GetBasket() *ShoppingBasket {
	if m != nil {
		return m.Basket
	}
	return nil
}

func (m *Payment) GetOccured() uint32 {
	if m != nil {
		return m.Occured
	}
	return 0
}

type LineItem struct {
	Basket      *ShoppingBasket `protobuf:"bytes,1,opt,name=Basket" json:"Basket,omitempty"`
	Description string          `protobuf:"bytes,2,opt,name=Description" json:"Description,omitempty"`
	Quantity    uint32          `protobuf:"varint,3,opt,name=Quantity" json:"Quantity,omitempty"`
	NetAmount   uint64          `protobuf:"varint,4,opt,name=NetAmount" json:"NetAmount,omitempty"`
	Vat         uint64          `protobuf:"varint,5,opt,name=Vat" json:"Vat,omitempty"`
	GrosAmount  uint64          `protobuf:"varint,6,opt,name=GrosAmount" json:"GrosAmount,omitempty"`
	VatRate     float64         `protobuf:"fixed64,7,opt,name=VatRate" json:"VatRate,omitempty"`
}

func (m *LineItem) Reset()                    { *m = LineItem{} }
func (m *LineItem) String() string            { return proto.CompactTextString(m) }
func (*LineItem) ProtoMessage()               {}
func (*LineItem) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *LineItem) GetBasket() *ShoppingBasket {
	if m != nil {
		return m.Basket
	}
	return nil
}

func (m *LineItem) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *LineItem) GetQuantity() uint32 {
	if m != nil {
		return m.Quantity
	}
	return 0
}

func (m *LineItem) GetNetAmount() uint64 {
	if m != nil {
		return m.NetAmount
	}
	return 0
}

func (m *LineItem) GetVat() uint64 {
	if m != nil {
		return m.Vat
	}
	return 0
}

func (m *LineItem) GetGrosAmount() uint64 {
	if m != nil {
		return m.GrosAmount
	}
	return 0
}

func (m *LineItem) GetVatRate() float64 {
	if m != nil {
		return m.VatRate
	}
	return 0
}

type ShoppingBasket struct {
	ID             uint64      `protobuf:"varint,1,opt,name=ID" json:"ID,omitempty"`
	Items          []*LineItem `protobuf:"bytes,2,rep,name=Items" json:"Items,omitempty"`
	NetTotal       uint64      `protobuf:"varint,3,opt,name=NetTotal" json:"NetTotal,omitempty"`
	TotalVat       uint64      `protobuf:"varint,4,opt,name=TotalVat" json:"TotalVat,omitempty"`
	GrosTotal      uint64      `protobuf:"varint,5,opt,name=GrosTotal" json:"GrosTotal,omitempty"`
	Currency       string      `protobuf:"bytes,6,opt,name=Currency" json:"Currency,omitempty"`
	CurrencyPrefix string      `protobuf:"bytes,7,opt,name=CurrencyPrefix" json:"CurrencyPrefix,omitempty"`
	CurrencySuffix string      `protobuf:"bytes,8,opt,name=CurrencySuffix" json:"CurrencySuffix,omitempty"`
}

func (m *ShoppingBasket) Reset()                    { *m = ShoppingBasket{} }
func (m *ShoppingBasket) String() string            { return proto.CompactTextString(m) }
func (*ShoppingBasket) ProtoMessage()               {}
func (*ShoppingBasket) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ShoppingBasket) GetID() uint64 {
	if m != nil {
		return m.ID
	}
	return 0
}

func (m *ShoppingBasket) GetItems() []*LineItem {
	if m != nil {
		return m.Items
	}
	return nil
}

func (m *ShoppingBasket) GetNetTotal() uint64 {
	if m != nil {
		return m.NetTotal
	}
	return 0
}

func (m *ShoppingBasket) GetTotalVat() uint64 {
	if m != nil {
		return m.TotalVat
	}
	return 0
}

func (m *ShoppingBasket) GetGrosTotal() uint64 {
	if m != nil {
		return m.GrosTotal
	}
	return 0
}

func (m *ShoppingBasket) GetCurrency() string {
	if m != nil {
		return m.Currency
	}
	return ""
}

func (m *ShoppingBasket) GetCurrencyPrefix() string {
	if m != nil {
		return m.CurrencyPrefix
	}
	return ""
}

func (m *ShoppingBasket) GetCurrencySuffix() string {
	if m != nil {
		return m.CurrencySuffix
	}
	return ""
}

type Tokens struct {
	ID        uint64    `protobuf:"varint,1,opt,name=ID" json:"ID,omitempty"`
	TokenType TokenType `protobuf:"varint,2,opt,name=TokenType,enum=payments.TokenType" json:"TokenType,omitempty"`
	Token     string    `protobuf:"bytes,3,opt,name=Token" json:"Token,omitempty"`
}

func (m *Tokens) Reset()                    { *m = Tokens{} }
func (m *Tokens) String() string            { return proto.CompactTextString(m) }
func (*Tokens) ProtoMessage()               {}
func (*Tokens) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Tokens) GetID() uint64 {
	if m != nil {
		return m.ID
	}
	return 0
}

func (m *Tokens) GetTokenType() TokenType {
	if m != nil {
		return m.TokenType
	}
	return TokenType_UNDEFINED
}

func (m *Tokens) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func init() {
	proto.RegisterType((*PingResponse)(nil), "payments.PingResponse")
	proto.RegisterType((*HTTPPageRequest)(nil), "payments.HTTPPageRequest")
	proto.RegisterType((*HTMLPage)(nil), "payments.HTMLPage")
	proto.RegisterType((*Payment)(nil), "payments.Payment")
	proto.RegisterType((*LineItem)(nil), "payments.LineItem")
	proto.RegisterType((*ShoppingBasket)(nil), "payments.ShoppingBasket")
	proto.RegisterType((*Tokens)(nil), "payments.Tokens")
	proto.RegisterEnum("payments.TokenType", TokenType_name, TokenType_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Payments service

type PaymentsClient interface {
	// comment: rpc ping
	Ping(ctx context.Context, in *common.Void, opts ...grpc.CallOption) (*PingResponse, error)
	// serve an http page
	HandleHTTPRequest(ctx context.Context, in *HTTPPageRequest, opts ...grpc.CallOption) (*HTMLPage, error)
}

type paymentsClient struct {
	cc *grpc.ClientConn
}

func NewPaymentsClient(cc *grpc.ClientConn) PaymentsClient {
	return &paymentsClient{cc}
}

func (c *paymentsClient) Ping(ctx context.Context, in *common.Void, opts ...grpc.CallOption) (*PingResponse, error) {
	out := new(PingResponse)
	err := grpc.Invoke(ctx, "/payments.Payments/Ping", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *paymentsClient) HandleHTTPRequest(ctx context.Context, in *HTTPPageRequest, opts ...grpc.CallOption) (*HTMLPage, error) {
	out := new(HTMLPage)
	err := grpc.Invoke(ctx, "/payments.Payments/HandleHTTPRequest", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Payments service

type PaymentsServer interface {
	// comment: rpc ping
	Ping(context.Context, *common.Void) (*PingResponse, error)
	// serve an http page
	HandleHTTPRequest(context.Context, *HTTPPageRequest) (*HTMLPage, error)
}

func RegisterPaymentsServer(s *grpc.Server, srv PaymentsServer) {
	s.RegisterService(&_Payments_serviceDesc, srv)
}

func _Payments_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(common.Void)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PaymentsServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/payments.Payments/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PaymentsServer).Ping(ctx, req.(*common.Void))
	}
	return interceptor(ctx, in, info, handler)
}

func _Payments_HandleHTTPRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HTTPPageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PaymentsServer).HandleHTTPRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/payments.Payments/HandleHTTPRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PaymentsServer).HandleHTTPRequest(ctx, req.(*HTTPPageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Payments_serviceDesc = grpc.ServiceDesc{
	ServiceName: "payments.Payments",
	HandlerType: (*PaymentsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _Payments_Ping_Handler,
		},
		{
			MethodName: "HandleHTTPRequest",
			Handler:    _Payments_HandleHTTPRequest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "golang.yacloud.eu/apis/payments/payments.proto",
}

func init() { proto.RegisterFile("golang.yacloud.eu/apis/payments/payments.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 737 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xac, 0x54, 0xcf, 0x4e, 0xdb, 0x4e,
	0x10, 0xfe, 0x39, 0x18, 0x13, 0x4f, 0x20, 0xc0, 0xfe, 0x2a, 0x64, 0xa2, 0xaa, 0x8d, 0x72, 0xa8,
	0x22, 0x54, 0x19, 0x29, 0x54, 0x3d, 0x54, 0xaa, 0x2a, 0x82, 0xd3, 0x12, 0x09, 0x82, 0xd9, 0x04,
	0xd4, 0x5b, 0x65, 0xe2, 0x25, 0x58, 0x24, 0xbb, 0xae, 0xbd, 0x6e, 0xb1, 0xd4, 0x13, 0x52, 0x6f,
	0x7d, 0x82, 0x1e, 0xfb, 0x5c, 0x7d, 0x98, 0x6a, 0x77, 0xfd, 0x2f, 0x20, 0xf5, 0xd4, 0x53, 0xe6,
	0xfb, 0x66, 0x26, 0x33, 0xf3, 0xed, 0x78, 0xc0, 0x9e, 0xb1, 0xb9, 0x47, 0x67, 0x76, 0xea, 0x4d,
	0xe7, 0x2c, 0xf1, 0x6d, 0x92, 0xec, 0x7b, 0x61, 0x10, 0xef, 0x87, 0x5e, 0xba, 0x20, 0x94, 0x97,
	0x86, 0x1d, 0x46, 0x8c, 0x33, 0x54, 0xcf, 0x71, 0x2b, 0xcf, 0x9c, 0x32, 0x1a, 0x79, 0xfe, 0x57,
	0xc6, 0x7c, 0x9b, 0x12, 0xae, 0xb2, 0xa7, 0x6c, 0xb1, 0x60, 0x34, 0xfb, 0x51, 0x99, 0xad, 0xde,
	0x5f, 0xe2, 0x6f, 0x7a, 0xb3, 0x30, 0x62, 0x77, 0x69, 0x61, 0xa8, 0x9c, 0xce, 0x1e, 0xac, 0xbb,
	0x01, 0x9d, 0x61, 0x12, 0x87, 0x8c, 0xc6, 0x04, 0xb5, 0xa0, 0x9e, 0xdb, 0x96, 0xd6, 0xd6, 0xba,
	0x26, 0x2e, 0x70, 0xe7, 0x16, 0x36, 0x8f, 0x27, 0x13, 0xd7, 0xf5, 0x66, 0x04, 0x93, 0xcf, 0x09,
	0x89, 0x39, 0x7a, 0x03, 0xeb, 0x63, 0x12, 0x7d, 0xc9, 0xb1, 0x4c, 0x69, 0xf4, 0x76, 0xec, 0xa2,
	0x4a, 0xd5, 0x8b, 0x97, 0x62, 0xd1, 0x53, 0x30, 0x5d, 0x35, 0xea, 0xd0, 0xb1, 0x6a, 0x6d, 0xad,
	0xab, 0xe3, 0x92, 0xe8, 0x50, 0xa8, 0x1f, 0x4f, 0x4e, 0x4f, 0x44, 0x31, 0x84, 0x40, 0x77, 0x3d,
	0x7e, 0x93, 0x35, 0x24, 0x6d, 0xc1, 0xf5, 0x99, 0x9f, 0xca, 0x44, 0x13, 0x4b, 0x1b, 0x59, 0xb0,
	0x36, 0x8c, 0x07, 0x8b, 0x90, 0xa7, 0xd6, 0x4a, 0x5b, 0xeb, 0xd6, 0x71, 0x0e, 0x51, 0x1b, 0x1a,
	0x0e, 0x1b, 0x31, 0x7e, 0xca, 0xfc, 0xe0, 0x3a, 0xb5, 0x74, 0xe9, 0xad, 0x52, 0x9d, 0xdf, 0x1a,
	0xac, 0x65, 0xd5, 0x51, 0x13, 0x6a, 0x43, 0x47, 0x56, 0xd3, 0x71, 0x6d, 0xe8, 0xa0, 0x1d, 0x30,
	0x0e, 0x17, 0x2c, 0xa1, 0x3c, 0x6b, 0x33, 0x43, 0x42, 0xac, 0xa3, 0x24, 0x8a, 0x08, 0x9d, 0xaa,
	0x82, 0x26, 0x2e, 0xb0, 0xa8, 0xe8, 0x7a, 0x29, 0x21, 0x17, 0x31, 0x89, 0x86, 0x8e, 0xac, 0x68,
	0xe2, 0x2a, 0x85, 0xce, 0xc1, 0xe8, 0x7b, 0xf1, 0x2d, 0xe1, 0xd6, 0xaa, 0x54, 0xcd, 0xb2, 0x8b,
	0x4d, 0x18, 0xdf, 0xb0, 0x30, 0x0c, 0xe8, 0x4c, 0xf9, 0xfb, 0xcf, 0x7f, 0xde, 0xef, 0x1a, 0x49,
	0x40, 0xf9, 0xeb, 0x57, 0xbf, 0xee, 0x77, 0xb7, 0xe3, 0xcc, 0x7b, 0x25, 0xbd, 0x76, 0xe0, 0xe3,
	0xec, 0x8f, 0x84, 0x00, 0x67, 0xd3, 0x69, 0x12, 0x11, 0xdf, 0x32, 0xda, 0x5a, 0x77, 0x03, 0xe7,
	0xb0, 0xf3, 0xbd, 0x06, 0xf5, 0x93, 0x80, 0x92, 0x21, 0x27, 0x8b, 0x4a, 0x65, 0xed, 0x5f, 0x55,
	0x16, 0x02, 0x93, 0x78, 0x1a, 0x05, 0x21, 0x0f, 0x18, 0xcd, 0x5e, 0xa5, 0x4a, 0x09, 0xb1, 0xce,
	0x13, 0x8f, 0xf2, 0x20, 0x7b, 0x9d, 0x0d, 0x5c, 0x60, 0xb1, 0x0a, 0x23, 0xc2, 0x33, 0x8d, 0x75,
	0xb5, 0x0a, 0x05, 0x81, 0xb6, 0x60, 0xe5, 0xd2, 0x53, 0x2a, 0xe9, 0x58, 0x98, 0xe8, 0x19, 0xc0,
	0x87, 0x88, 0xc5, 0x59, 0x82, 0x21, 0x1d, 0x15, 0x46, 0xe8, 0x70, 0xe9, 0x71, 0xec, 0x71, 0x62,
	0xad, 0xb5, 0xb5, 0xae, 0x86, 0x73, 0xd8, 0xf9, 0x51, 0x83, 0xe6, 0xf2, 0x8c, 0x8f, 0x5e, 0xbb,
	0x0b, 0xab, 0x42, 0xa5, 0xd8, 0xaa, 0xb5, 0x57, 0xba, 0x8d, 0x1e, 0x2a, 0xc5, 0xc9, 0x05, 0xc4,
	0x2a, 0x40, 0x8c, 0x34, 0x22, 0x7c, 0xc2, 0xb8, 0x37, 0x97, 0x23, 0xe9, 0xb8, 0xc0, 0xc2, 0x27,
	0x0d, 0xd1, 0xb9, 0x9a, 0xa8, 0xc0, 0x62, 0x5c, 0xd1, 0xac, 0x4a, 0x54, 0x63, 0x95, 0xc4, 0xd2,
	0x56, 0x19, 0x0f, 0xb6, 0xea, 0x05, 0x34, 0x73, 0xdb, 0x8d, 0xc8, 0x75, 0x70, 0x27, 0xe7, 0x33,
	0xf1, 0x03, 0xb6, 0x1a, 0x37, 0x4e, 0xae, 0x45, 0x5c, 0x7d, 0x39, 0x4e, 0xb1, 0x9d, 0x05, 0x18,
	0x13, 0x76, 0x4b, 0x68, 0xfc, 0x48, 0x85, 0xb7, 0x60, 0x4a, 0xcf, 0x24, 0x0d, 0x89, 0x7c, 0xce,
	0x66, 0xef, 0xff, 0x52, 0x89, 0xc2, 0xd5, 0x87, 0x7c, 0x43, 0x0e, 0x7a, 0xb8, 0xcc, 0x40, 0x4f,
	0x60, 0x55, 0x82, 0xec, 0xbb, 0x50, 0x60, 0xef, 0x5d, 0xe5, 0x4f, 0xd1, 0x06, 0x98, 0x17, 0x23,
	0x67, 0xf0, 0x7e, 0x38, 0x1a, 0x38, 0x5b, 0xff, 0xa1, 0x4d, 0x68, 0xb8, 0xf8, 0xcc, 0xf9, 0x74,
	0x78, 0x74, 0x34, 0x18, 0x8f, 0xb7, 0x34, 0x84, 0xa0, 0x39, 0x3e, 0x1c, 0x39, 0xfd, 0xb3, 0x8f,
	0x39, 0x57, 0xeb, 0x7d, 0x83, 0x7a, 0xf6, 0x91, 0xc6, 0xe8, 0x25, 0xe8, 0xe2, 0x74, 0xa1, 0x75,
	0x3b, 0xbb, 0x82, 0x97, 0x2c, 0xf0, 0x5b, 0x3b, 0x65, 0x93, 0x4b, 0x87, 0xad, 0x0f, 0xdb, 0xc7,
	0x1e, 0xf5, 0xe7, 0x44, 0x9c, 0xb0, 0xfc, 0x04, 0xed, 0x96, 0xc1, 0x0f, 0x2e, 0x5b, 0x0b, 0x55,
	0x5d, 0xea, 0x0e, 0xf5, 0x5b, 0x60, 0x91, 0xa4, 0x38, 0xe4, 0xe2, 0xae, 0x16, 0x41, 0x57, 0x86,
	0xbc, 0xa7, 0x07, 0x7f, 0x02, 0x00, 0x00, 0xff, 0xff, 0x91, 0x27, 0x8b, 0x6a, 0xef, 0x05, 0x00,
	0x00,
}