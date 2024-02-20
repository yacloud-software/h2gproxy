package srv

import (
	"golang.conradwood.net/apis/h2gproxy"
	"testing"
)

func TestHTTPForwarder_TooBusy_ReturnsFalseIfMaxInFlightsIsZero(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 0,
		},
		currentInFlights: 7,
		currentlyBusy:    false,
	}

	res := hf.TooBusy()
	if res != false {
		t.Errorf("Expected hf.TooBusy to return false, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenNotCurrentlyBusyReturnsFalseIfFewerRequestsInFlightThanAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 7,
		currentlyBusy:    false,
	}

	res := hf.TooBusy()
	if res != false {
		t.Errorf("Expected hf.TooBusy to return false, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenNotCurrentlyBusyReturnsTrueIfEqualNumberOfRequestsInFlightComparedToAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 10,
		currentlyBusy:    false,
	}

	res := hf.TooBusy()
	if res != true {
		t.Errorf("Expected hf.TooBusy to return true, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenNotCurrentlyBusyReturnsTrueIfMoreRequestsInFlightThanAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 15,
		currentlyBusy:    false,
	}

	res := hf.TooBusy()
	if res != true {
		t.Errorf("Expected hf.TooBusy to return true, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenCurrentlyBusyReturnsFalseIfFewerRequestsInFlightThanAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 7,
		currentlyBusy:    true,
	}

	res := hf.TooBusy()
	if res != false {
		t.Errorf("Expected hf.TooBusy to return false, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenCurrentlyBusyReturnsTrueIfEqualNumberOfRequestsInFlightComparedToAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 10,
		currentlyBusy:    true,
	}

	res := hf.TooBusy()
	if res != true {
		t.Errorf("Expected hf.TooBusy to return true, returned %v", res)
	}
}

func TestHTTPForwarder_TooBusy_WhenCurrentlyBusyReturnsTrueIfMoreRequestsInFlightThanAllowed(t *testing.T) {
	hf := HTTPForwarder{
		def: &h2gproxy.AddConfigHTTPRequest{
			MaxInFlights: 10,
		},
		currentInFlights: 15,
		currentlyBusy:    true,
	}

	res := hf.TooBusy()
	if res != true {
		t.Errorf("Expected hf.TooBusy to return true, returned %v", res)
	}
}

func TestHTTPForwarder_BusyDec(t *testing.T) {

}

func TestHTTPForwarder_BusyInc(t *testing.T) {

}
