package go_cip

import (
	"bytes"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
)

type SegmentType typedef.Usint

const (
	SegmentTypePort      SegmentType = 0 << 5
	SegmentTypeLogical   SegmentType = 1 << 5
	SegmentTypeNetwork   SegmentType = 2 << 5
	SegmentTypeSymbolic  SegmentType = 3 << 5
	SegmentTypeData      SegmentType = 4 << 5
	SegmentTypeDataType1 SegmentType = 5 << 5
	SegmentTypeDataType2 SegmentType = 6 << 5
)

func Paths(arg ...[]byte) []byte {
	buffer := new(bytes.Buffer)
	for i := 0; i < len(arg); i++ {
		eip.WriteByte(buffer, arg[i])
	}
	return buffer.Bytes()
}

type DataTypes typedef.Usint

const (
	DataTypeSimple DataTypes = 0x0
	DataTypeANSI   DataTypes = 0x11
)

type LogicalType typedef.Usint

const (
	LogicalTypeClassID     LogicalType = 0 << 2
	LogicalTypeInstanceID  LogicalType = 1 << 2
	LogicalTypeMemberID    LogicalType = 2 << 2
	LogicalTypeConnPoint   LogicalType = 3 << 2
	LogicalTypeAttributeID LogicalType = 4 << 2
	LogicalTypeSpecial     LogicalType = 5 << 2
	LogicalTypeServiceID   LogicalType = 6 << 2
)

func DataBuild(tp DataTypes, data []byte, padded bool) []byte {
	buffer := new(bytes.Buffer)

	firstByte := uint8(SegmentTypeData) | uint8(tp)
	eip.WriteByte(buffer, firstByte)

	length := uint8(len(data))
	eip.WriteByte(buffer, length)

	eip.WriteByte(buffer, data)

	if padded && buffer.Len()%2 == 1 {
		eip.WriteByte(buffer, uint8(0))
	}

	return buffer.Bytes()
}

func LogicalBuild(tp LogicalType, address uint32, padded bool) []byte {
	format := uint8(0)

	if address <= 255 {
		format = 0
	} else if address > 255 && address <= 65535 {
		format = 1
	} else {
		format = 2
	}

	buffer := new(bytes.Buffer)
	firstByte := uint8(SegmentTypeLogical) | uint8(tp) | format
	eip.WriteByte(buffer, firstByte)

	if address > 255 && address <= 65535 && padded {
		eip.WriteByte(buffer, uint8(0))
	}

	if address <= 255 {
		eip.WriteByte(buffer, uint8(address))
	} else if address > 255 && address <= 65535 {
		eip.WriteByte(buffer, uint16(address))
	} else {
		eip.WriteByte(buffer, address)
	}

	return buffer.Bytes()
}

func PortBuild(link []byte, portID uint16, padded bool) []byte {
	extendedLinkTag := len(link) > 1
	extendedPortTag := !(portID < 15)

	buffer := new(bytes.Buffer)

	firstByte := uint8(SegmentTypePort)
	if extendedLinkTag {
		firstByte = firstByte | 0x10
	}

	if !extendedPortTag {
		firstByte = firstByte | uint8(portID)
	} else {
		firstByte = firstByte | 0xf
	}

	eip.WriteByte(buffer, firstByte)

	if extendedLinkTag {
		eip.WriteByte(buffer, uint8(len(link)))
	}

	if extendedPortTag {
		eip.WriteByte(buffer, portID)
	}

	eip.WriteByte(buffer, link)

	if padded && buffer.Len()%2 == 1 {
		eip.WriteByte(buffer, uint8(0))
	}

	return buffer.Bytes()
}
