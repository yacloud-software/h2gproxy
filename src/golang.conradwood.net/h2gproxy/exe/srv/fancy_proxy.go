package srv

import (
	"fmt"
)

/*****************************
* fancy proxy ;)
*****************************/
func FancyProxy(f *FProxy) {
	f.SetError(fmt.Errorf("fancy proxy not implemented"))
}
