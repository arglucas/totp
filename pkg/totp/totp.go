package totp

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// TODO: Support other algorithms and extend digit support properly.
func TOTP(key []byte, t int64, period int, digitsCount int, mode Mode) (string, error) {
	if mode == SHA512 {
		return "", errors.New("unsupported mode")
	}
	if mode.KeySize() != len(key) {
		return "", fmt.Errorf("key length incorrect for mode %q", mode)
	}
	mac := hmac.New(mode.GetHash(), key)
	unixT := time.Unix(t, 0).Unix() // TODO: Prob not needed...
	t0 := unixT / int64(period)

	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(t0))

	mac.Write(message)
	hm := mac.Sum(nil)

	offset := hm[len(hm)-1] & 0xf
	binCode := []byte{
		hm[offset] & 0x7f,
		hm[offset+1] & 0xff,
		hm[offset+2] & 0xff,
		hm[offset+3] & 0xff}
	code := binary.BigEndian.Uint32(binCode)

	scode := strconv.FormatUint(uint64(code), 10)
	return scode[len(scode)-digitsCount:], nil
}
