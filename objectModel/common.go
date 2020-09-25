package objectModel

import (
	"bytes"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
)

type Common struct {
	Revision           typedef.Uint
	MaxInstance        typedef.Uint
	NumberOfInstances  typedef.Uint
	NumberOfAttributes typedef.Uint
}

func (c *Common) Decode(data []byte) {
	dataReader := bytes.NewReader(data)

	eip.ReadByte(dataReader, &c.Revision)
	eip.ReadByte(dataReader, &c.MaxInstance)
	eip.ReadByte(dataReader, &c.NumberOfInstances)
	eip.ReadByte(dataReader, &c.NumberOfAttributes)
}
