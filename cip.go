package go_cip

import (
	"bytes"
	"errors"
	"fmt"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
)

type Controller struct {
	device       *eip.Device
	timeTicks    typedef.Usint
	timeoutTicks typedef.Usint

	slot       uint8
	controller *eip.Device
}

func NewControllerFromClient(device *eip.Device, slot uint8) *Controller {
	_client := &Controller{
		device:       device,
		slot:         slot,
		timeTicks:    3,
		timeoutTicks: 250,
	}
	return _client
}

func NewControllerFromIP(addr string, slot uint8, config *eip.Config) (*Controller, error) {
	device, err := eip.NewDevice(addr)
	if err != nil {
		return nil, err
	}

	err2 := device.Connect(config)
	if err2 != nil {
		return nil, err2
	}

	_device := &Controller{
		device:       device,
		slot:         slot,
		timeTicks:    3,
		timeoutTicks: 250,
	}
	return _device, nil
}

func (c *Controller) SetTimeout(timeTicks typedef.Usint, timeoutTicks typedef.Usint) {
	c.timeTicks = timeTicks
	c.timeoutTicks = timeoutTicks
}

func (c *Controller) UCMM(mrr *eip.MessageRouterRequest) (*eip.SendDataSpecificData, error) {
	ucs := UnConnectedSend{
		TimeTick:       c.timeTicks,
		TimeOutTicks:   c.timeoutTicks,
		MessageRequest: mrr,
		RouterPath:     PortBuild([]byte{c.slot}, 1, true),
	}

	_mrr := &eip.MessageRouterRequest{}
	_mrr.New(0x52, Paths(
		LogicalBuild(LogicalTypeClassID, 06, true),
		LogicalBuild(LogicalTypeInstanceID, 01, true),
	), ucs.Encode())

	cpf := &eip.CommonPacketFormat{}
	cpf.New([]eip.CommonPacketFormatItem{
		eip.CommonPacketFormatItem{
			TypeID: eip.ItemIDUCMM,
			Data:   nil,
		},
		eip.CommonPacketFormatItem{
			TypeID: eip.ItemIDUnconnectedMessage,
			Data:   _mrr.Encode(),
		},
	})

	return c.device.SendRRData(cpf, 10)
}

func (c *Controller) GetAttributeAll() error {
	paths := Paths(
		LogicalBuild(LogicalTypeClassID, 01, true),
		LogicalBuild(LogicalTypeInstanceID, 01, true),
	)

	mrreq := &eip.MessageRouterRequest{}
	mrreq.New(0x01, paths, nil)

	res, err := c.UCMM(mrreq)
	if err != nil {
		return err
	}

	mrres := &eip.MessageRouterResponse{}
	mrres.Decode(res.Packet.Items[1].Data)

	if mrres.GeneralStatus != 0 {
		return errors.New(fmt.Sprintf("target error => Service Code: %#x | Status: %#x | Addtional: %s", mrres.ReplyService, mrres.GeneralStatus, mrres.AdditionalStatus))
	}

	dataReader := bytes.NewReader(mrres.ResponseData)

	c.controller = &eip.Device{}
	eip.ReadByte(dataReader, &c.controller.VendorID)
	eip.ReadByte(dataReader, &c.controller.DeviceType)
	eip.ReadByte(dataReader, &c.controller.ProductCode)
	eip.ReadByte(dataReader, &c.controller.Major)
	eip.ReadByte(dataReader, &c.controller.Minor)
	eip.ReadByte(dataReader, &c.controller.Status)
	eip.ReadByte(dataReader, &c.controller.SerialNumber)
	nameLength := uint8(0)
	eip.ReadByte(dataReader, &nameLength)
	productName := make([]byte, nameLength)
	eip.ReadByte(dataReader, &productName)
	c.controller.ProductName = string(productName)

	return nil
}
