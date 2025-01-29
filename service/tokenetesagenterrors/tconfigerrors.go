package tokenetesagenterrors

import (
	"errors"
)

var ErrNotFound = errors.New("not found")

var ErrInvalidKeyID = errors.New("invalid key id")

var ErrTraTExpired = errors.New("expired trat")
