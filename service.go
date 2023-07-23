package ytmauth

import (
	"fmt"
)

func wrapErrStr(err string) error {
	return fmt.Errorf(_errPrefix+"%s", err)
}
