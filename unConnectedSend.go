package go_cip

import (
	"bytes"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
)

type UnConnectedSend struct {
	TimeTick           typedef.Usint
	TimeOutTicks       typedef.Usint
	MessageRequestSize typedef.Uint
	MessageRequest     *eip.MessageRouterRequest
	Pad                typedef.Usint
	RouterPathSize     typedef.Usint
	Reserved           typedef.Usint
	RouterPath         []byte
}

func (u *UnConnectedSend) Encode() []byte {
	mr := u.MessageRequest.Encode()

	buffer := new(bytes.Buffer)

	eip.WriteByte(buffer, u.TimeTick)
	eip.WriteByte(buffer, u.TimeOutTicks)
	eip.WriteByte(buffer, typedef.Uint(len(mr)))
	eip.WriteByte(buffer, mr)

	if len(mr)%2 == 1 {
		eip.WriteByte(buffer, uint8(0))
	}

	eip.WriteByte(buffer, typedef.Usint(len(u.RouterPath)/2))
	eip.WriteByte(buffer, uint8(0))
	eip.WriteByte(buffer, u.RouterPath)

	return buffer.Bytes()
}
