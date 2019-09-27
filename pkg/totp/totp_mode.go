package totp

type Mode int

const (
	SHA1 Mode = iota
	SHA256
	SHA512
)

func (m Mode) String() string {
	return [...]string{"SHA1", "SHA256", "SHA512"}[m]
}