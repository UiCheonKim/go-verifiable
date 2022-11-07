package signer

type Signer interface {
	Sign(msg []byte, key interface{}) (signature []byte, err error)
	Verify(msg, signature []byte, key interface{}) bool
	Name() string
	Type() string
}
