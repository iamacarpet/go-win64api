package winapi

import (
	"errors"
	"log"
)

// UTF8PtrFromString returns pointer to the UTF-16 encoding of
// the UTF-8 string s, with a terminating NUL added. If s
// contains a NUL byte at any location, it returns (nil, EINVAL).
func UTF8PtrFromString(s string) (*uint8, error) {
	a, err := UTF8FromString(s)
	if err != nil {
		return nil, err
	}
	log.Printf("%v", a)
	return &a[0], nil
}

// UTF8FromString returns the UTF-16 encoding of the UTF-8 string
// s, with a terminating NUL added. If s contains a NUL byte at any
// location, it returns (nil, EINVAL).
func UTF8FromString(s string) ([]uint8, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return nil, errors.New("Invalid parameter")
		}
	}
	return []byte(s + "\x00"), nil
}
