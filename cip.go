package go_cip

import (
	"bytes"
	"errors"
	"fmt"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
)

type Device struct {
	eipDevice *eip.Device
}

type Channel struct {
	ucmm         bool
	slot         uint8
	timeTicks    typedef.Usint
	timeoutTicks typedef.Usint
	Device       *Device
	SlotDevice   *eip.Device
}

func NewDeviceFromClient(device *eip.Device) *Device {
	_client := &Device{eipDevice: device}
	return _client
}

func NewDeviceFromIP(addr string, config *eip.Config) (*Device, error) {
	device, err := eip.NewDevice(addr)
	if err != nil {
		return nil, err
	}

	err2 := device.Connect(config)
	if err2 != nil {
		return nil, err2
	}

	_device := &Device{eipDevice: device}
	return _device, nil
}

func (d *Device) Ucmm(slot uint8) *Channel {
	_channel := &Channel{
		ucmm:         true,
		slot:         slot,
		Device:       d,
		timeTicks:    3,
		timeoutTicks: 250,
	}

	return _channel
}

func (c *Channel) SetTimeout(timeTicks typedef.Usint, timeoutTicks typedef.Usint) {
	c.timeTicks = timeTicks
	c.timeoutTicks = timeoutTicks
}

func (c *Channel) CommonPackage(mr *eip.MessageRouterRequest) (*eip.SendDataSpecificData, error) {
	if c.ucmm {
		ucs := UnConnectedSend{
			TimeTick:       c.timeTicks,
			TimeOutTicks:   c.timeoutTicks,
			MessageRequest: mr,
			RouterPath:     PortBuild([]byte{c.slot}, 1, true),
		}

		mr2 := &eip.MessageRouterRequest{}
		mr2.New(0x52, Paths(
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
				Data:   mr2.Encode(),
			},
		})

		return c.Device.eipDevice.SendRRData(cpf, 10)
	} else {
		//todo

		return nil, nil
	}
}

func (c *Channel) GetAttributeAll() error {
	paths := Paths(
		LogicalBuild(LogicalTypeClassID, 01, true),
		LogicalBuild(LogicalTypeInstanceID, 01, true),
	)

	mr := &eip.MessageRouterRequest{}
	mr.New(0x01, paths, nil)

	res, err := c.CommonPackage(mr)
	if err != nil {
		return err
	}

	mrres := &eip.MessageRouterResponse{}
	mrres.Decode(res.Packet.Items[1].Data)

	if mrres.GeneralStatus != 0 {
		return errors.New(fmt.Sprintf("target error => Service Code: %#x | Status: %#x | Addtional: %s", mrres.ReplyService, mrres.GeneralStatus, mrres.AdditionalStatus))
	}

	dataReader := bytes.NewReader(mrres.ResponseData)

	c.SlotDevice = &eip.Device{}
	eip.ReadByte(dataReader, &c.SlotDevice.VendorID)
	eip.ReadByte(dataReader, &c.SlotDevice.DeviceType)
	eip.ReadByte(dataReader, &c.SlotDevice.ProductCode)
	eip.ReadByte(dataReader, &c.SlotDevice.Major)
	eip.ReadByte(dataReader, &c.SlotDevice.Minor)
	eip.ReadByte(dataReader, &c.SlotDevice.Status)
	eip.ReadByte(dataReader, &c.SlotDevice.SerialNumber)
	nameLength := uint8(0)
	eip.ReadByte(dataReader, &nameLength)
	productName := make([]byte, nameLength)
	eip.ReadByte(dataReader, &productName)
	c.SlotDevice.ProductName = string(productName)

	return nil
}
