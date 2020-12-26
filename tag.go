package go_cip

import (
	"bytes"
	"fmt"
	eip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/typedef"
	"log"
	"reflect"
)

const ServiceReadTag = 0x4c
const ServiceReadFragmentedTag = 0x52
const ServiceWriteTag = 0x4d

type DataType uint16

const (
	NULL   DataType = 0x00
	BOOL   DataType = 0xc1
	SINT   DataType = 0xc2
	INT    DataType = 0xc3
	DINT   DataType = 0xc4
	LINT   DataType = 0xc5
	USINT  DataType = 0xc6
	UINT   DataType = 0xc7
	UDINT  DataType = 0xc8
	ULINT  DataType = 0xc9
	REAL   DataType = 0xca
	LREAL  DataType = 0xcb
	STRING DataType = 0xfce
)

var TypeMap map[DataType]reflect.Kind

func init() {
	TypeMap = make(map[DataType]reflect.Kind)
	TypeMap[NULL] = reflect.Invalid
	TypeMap[BOOL] = reflect.Bool
	TypeMap[SINT] = reflect.Int8
	TypeMap[INT] = reflect.Int16
	TypeMap[DINT] = reflect.Int32
	TypeMap[LINT] = reflect.Int64
	TypeMap[USINT] = reflect.Uint8
	TypeMap[UINT] = reflect.Uint16
	TypeMap[UDINT] = reflect.Uint32
	TypeMap[ULINT] = reflect.Uint64
	TypeMap[REAL] = reflect.Float32
	TypeMap[LREAL] = reflect.Float64
	TypeMap[STRING] = reflect.String
}

func (n DataType) String() string {
	var _type string
	if 0x8000&n == 0 {
		_type = "atomic"
	} else {
		_type = "struct"
	}

	return fmt.Sprintf("%#04x(%6s) | %s | %d dims", uint16(n), TypeMap[0xFFF&n], _type, (0x6000&n)>>13)
}

func (n DataType) GetDims() uint8 {
	return uint8((0x6000 & n) >> 13)
}

func (n DataType) checkValid() bool {
	b12 := 0x1000 & n
	if b12 != 0 {
		return false
	}

	b15 := 0x8000 & n
	_type := 0xFFF & n
	if b15 != 0 {
		if _type <= 0xEFF && _type >= 0x100 {
			return true
		}

		// string supported
		if _type == 0xFCE {
			return true
		}
	} else {
		if _type <= 0x0FF && _type >= 0x001 {
			return true
		}
	}

	return false
}

type Tag struct {
	InstanceID uint32
	dim1Len    typedef.Udint
	dim2Len    typedef.Udint
	dim3Len    typedef.Udint
	Name       string
	Type       DataType
	readCount  uint16
	controller *Controller
	value      []byte
	dims       uint8
	Onchange   func()
}

func (t *Tag) Read() error {
	data := new(bytes.Buffer)
	eip.WriteByte(data, t.readCount)
	mr := &eip.MessageRouterRequest{}
	mr.New(ServiceReadTag, Paths(
		LogicalBuild(LogicalTypeClassID, 0x6B, true),
		LogicalBuild(LogicalTypeInstanceID, t.InstanceID, true),
	), data.Bytes())

	res, err := t.controller.UCMM(mr)
	if err != nil {
		return err
	}

	mrres := &eip.MessageRouterResponse{}
	mrres.Decode(res.Packet.Items[1].Data)

	t.ReadParser(mrres)
	return nil
}

func (t *Tag) Write() error {
	mr := &eip.MessageRouterRequest{}
	data := new(bytes.Buffer)
	eip.WriteByte(data, t.Type)
	eip.WriteByte(data, t.readCount)
	eip.WriteByte(data, t.value)
	mr.New(ServiceWriteTag, Paths(
		LogicalBuild(LogicalTypeClassID, 0x6B, true),
		LogicalBuild(LogicalTypeInstanceID, t.InstanceID, true),
	), data.Bytes())

	_, err := t.controller.UCMM(mr)
	return err
}

func (t *Tag) ReadParser(mr *eip.MessageRouterResponse) {
	dataReader := bytes.NewReader(mr.ResponseData)
	_t := uint16(0)
	eip.ReadByte(dataReader, &_t)

	if _t == 0x2a0 {
		eip.ReadByte(dataReader, &_t)
	}

	payload := make([]byte, dataReader.Len())
	eip.ReadByte(dataReader, payload)

	if bytes.Compare(t.value, payload) != 0 {
		t.value = payload
		if t.Onchange != nil {
			t.Onchange()
		}
	}
}

func (t *Tag) Value() interface{} {
	reader := bytes.NewReader(t.value)
	xtp := t.Type & 0xFFF

	switch t.dims {
	case 0:
		if _tp, ok := TypeMap[xtp]; ok {
			// atomic
			if xtp <= 0xFF && xtp >= 0x01 {
				switch _tp {
				case reflect.Int8:
					var val int8
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int16:
					var val int16
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int32:
					var val int32
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int64:
					var val int64
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint:
					var val uint8
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint16:
					var val uint16
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint32:
					var val uint32
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint64:
					var val uint8
					eip.ReadByte(reader, &val)
					return val
				case reflect.Float32:
					var val float32
					eip.ReadByte(reader, &val)
					return val
				case reflect.Float64:
					var val float64
					eip.ReadByte(reader, &val)
					return val
				default:
					return nil
				}
			}

			// string
			if xtp == 0xFCE {
				_len := uint32(0)
				eip.ReadByte(reader, &_len)
				val := make([]byte, _len)
				eip.ReadByte(reader, &val)
				return string(val)
			}
		}
	case 1:
		if _tp, ok := TypeMap[xtp]; ok {
			// atomic
			if xtp <= 0xFF && xtp >= 0x01 {
				switch _tp {
				case reflect.Int8:
					val := make([]int8, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int16:
					val := make([]int16, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int32:
					val := make([]int32, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Int64:
					val := make([]int64, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint:
					val := make([]uint8, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint16:
					val := make([]uint16, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint32:
					val := make([]uint32, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Uint64:
					val := make([]uint64, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Float32:
					val := make([]float32, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				case reflect.Float64:
					val := make([]float64, t.dim1Len)
					eip.ReadByte(reader, &val)
					return val
				default:
					return nil
				}
			}

			// string
			if xtp == 0xFCE {
				val := make([]string, t.dim1Len)

				for i := range val {
					_len := uint32(0)
					eip.ReadByte(reader, &_len)
					_val := make([]byte, 84)
					eip.ReadByte(reader, &_val)
					val[i] = string(_val[:_len])
				}
				return val
			}
		}
	case 2:
		if _tp, ok := TypeMap[xtp]; ok {
			// atomic
			if xtp <= 0xFF && xtp >= 0x01 {
				switch _tp {
				case reflect.Int8:
					val := make([][]int8, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]int8, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Int16:
					val := make([][]int16, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]int16, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Int32:
					val := make([][]int32, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]int32, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Int64:
					val := make([][]int64, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]int64, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Uint:
					val := make([][]uint8, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]uint8, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Uint16:
					val := make([][]uint16, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]uint16, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Uint32:
					val := make([][]uint32, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]uint32, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Uint64:
					val := make([][]uint64, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]uint64, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Float32:
					val := make([][]float32, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]float32, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				case reflect.Float64:
					val := make([][]float64, t.dim2Len)
					for i := 0; i < len(val); i++ {
						val[i] = make([]float64, t.dim1Len)
						eip.ReadByte(reader, &val[i])
					}
					return val
				default:
					return nil
				}
			}

			// string
			//if xtp == 0xFCE {
			//	val := make([]string, t.dim1Len)
			//
			//	for i, _ := range val {
			//		_len := uint32(0)
			//		eip.ReadByte(reader, &_len)
			//		_val := make([]byte, 84)
			//		eip.ReadByte(reader, &_val)
			//		val[i] = string(_val[:_len])
			//	}
			//	return val
			//}
		}
	}

	log.Println("string dim2 dim3 | anytype dim3 is not supported now")
	return nil
}

type TagMap map[string]*Tag

func (c *Controller) AllTags() (TagMap, error) {
	return c.getTags(nil, 0)
}

func (c *Controller) getTags(cTagMap TagMap, instanceID uint32) (TagMap, error) {
	paths := Paths(
		LogicalBuild(LogicalTypeClassID, 0x6B, true),
		LogicalBuild(LogicalTypeInstanceID, instanceID, true),
	)

	data := new(bytes.Buffer)
	eip.WriteByte(data, uint16(3))
	eip.WriteByte(data, uint16(1))
	eip.WriteByte(data, uint16(2))
	eip.WriteByte(data, uint16(8))

	mrreq := &eip.MessageRouterRequest{}
	mrreq.New(0x55, paths, data.Bytes())

	res, err := c.UCMM(mrreq)
	if err != nil {
		return nil, err
	}

	mrres := &eip.MessageRouterResponse{}
	mrres.Decode(res.Packet.Items[1].Data)

	//log.Println(mrres.ResponseData)
	//return nil, nil

	reader := bytes.NewReader(mrres.ResponseData)
	insId := uint32(0)

	var _tagMap TagMap

	if cTagMap == nil {
		_tagMap = make(TagMap)
	} else {
		_tagMap = cTagMap
	}

	for reader.Len() > 0 {
		_tag := &Tag{}
		eip.ReadByte(reader, &_tag.InstanceID)
		namelen := uint16(0)

		eip.ReadByte(reader, &namelen)
		name := make([]byte, namelen)
		eip.ReadByte(reader, name)
		_tag.Name = string(name)

		eip.ReadByte(reader, &_tag.Type)
		eip.ReadByte(reader, &_tag.dim1Len)
		eip.ReadByte(reader, &_tag.dim2Len)
		eip.ReadByte(reader, &_tag.dim3Len)
		_tag.controller = c
		_tag.dims = _tag.Type.GetDims()

		_d1 := _tag.dim1Len
		_d2 := _tag.dim2Len
		_d3 := _tag.dim3Len

		if _d1 == 0 {
			_d1 = 1
		}
		if _d2 == 0 {
			_d2 = 1
		}
		if _d3 == 0 {
			_d3 = 1
		}

		_tag.readCount = uint16(_d1 * _d2 * _d3)

		if _tag.Type.checkValid() {
			_tagMap[_tag.Name] = _tag
		}

		insId = _tag.InstanceID
	}

	if mrres.GeneralStatus == 0x06 {
		return c.getTags(_tagMap, insId+1)
	}

	return _tagMap, nil
}
