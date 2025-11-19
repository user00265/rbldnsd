// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package dns implements DNS protocol message parsing and encoding.
// It supports query parsing, response building, and encoding of
// common resource record types (A, AAAA, NS, SOA, TXT, MX).
package dns

import (
	"fmt"
	"net"
	"strings"
)

const (
	QueryTypeA    = 1
	QueryTypeNS   = 2
	QueryTypeSOA  = 6
	QueryTypeMX   = 15
	QueryTypeTXT  = 16
	QueryTypeAAAA = 28

	ClassIN = 1

	RCodeNoError  = 0
	RCodeNameErr  = 3
	RCodeRefused  = 5
	RCodeServFail = 2
)

// Header represents a DNS message header
type Header struct {
	ID      uint16
	QR      bool   // 0 = question, 1 = response
	OpCode  uint8  // 0 = query
	AA      bool   // authoritative answer
	TC      bool   // truncated
	RD      bool   // recursion desired
	RA      bool   // recursion available
	RCode   uint8  // response code
	QDCount uint16 // question count
	ANCount uint16 // answer count
	NSCount uint16 // nameserver count
	ARCount uint16 // additional records count
}

// Question represents a DNS question
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS resource record
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Message represents a complete DNS message
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// ParseMessage parses a DNS wire format message
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("message too short")
	}

	msg := &Message{}
	offset := 0

	// Parse header
	msg.Header.ID = (uint16(data[0]) << 8) | uint16(data[1])
	offset += 2

	flags := (uint16(data[2]) << 8) | uint16(data[3])
	offset += 2
	msg.Header.QR = (flags & 0x8000) != 0
	msg.Header.OpCode = uint8((flags & 0x7800) >> 11)
	msg.Header.AA = (flags & 0x0400) != 0
	msg.Header.TC = (flags & 0x0200) != 0
	msg.Header.RD = (flags & 0x0100) != 0
	msg.Header.RA = (flags & 0x0080) != 0
	msg.Header.RCode = uint8(flags & 0x000F)

	msg.Header.QDCount = (uint16(data[4]) << 8) | uint16(data[5])
	msg.Header.ANCount = (uint16(data[6]) << 8) | uint16(data[7])
	msg.Header.NSCount = (uint16(data[8]) << 8) | uint16(data[9])
	msg.Header.ARCount = (uint16(data[10]) << 8) | uint16(data[11])
	offset += 8

	// Parse questions
	for i := 0; i < int(msg.Header.QDCount); i++ {
		name, newOffset, err := parseName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = newOffset

		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated question")
		}

		q := Question{
			Name:  name,
			Type:  (uint16(data[offset]) << 8) | uint16(data[offset+1]),
			Class: (uint16(data[offset+2]) << 8) | uint16(data[offset+3]),
		}
		msg.Questions = append(msg.Questions, q)
		offset += 4
	}

	return msg, nil
}

// BuildResponse builds a DNS response message
func BuildResponse(id uint16, questions []Question, answers []ResourceRecord, rcode uint8) []byte {
	buf := make([]byte, 0, 512)

	// Header
	buf = append(buf, byte(id>>8), byte(id))
	flags := uint16(0x8400) // QR=1, AA=1, RD=1
	flags |= uint16(rcode)
	buf = append(buf, byte(flags>>8), byte(flags))

	// Counts
	buf = append(buf, byte(len(questions)>>8), byte(len(questions)))
	buf = append(buf, byte(len(answers)>>8), byte(len(answers)))
	buf = append(buf, 0, 0) // NS count
	buf = append(buf, 0, 0) // AR count

	// Questions
	for _, q := range questions {
		encoded, _ := encodeName(q.Name)
		buf = append(buf, encoded...)
		buf = append(buf, byte(q.Type>>8), byte(q.Type))
		buf = append(buf, byte(ClassIN>>8), byte(ClassIN))
	}

	// Answers
	for _, rr := range answers {
		encoded, _ := encodeName(rr.Name)
		buf = append(buf, encoded...)
		buf = append(buf, byte(rr.Type>>8), byte(rr.Type))
		buf = append(buf, byte(rr.Class>>8), byte(rr.Class))
		buf = append(buf, byte(rr.TTL>>24), byte(rr.TTL>>16), byte(rr.TTL>>8), byte(rr.TTL))
		buf = append(buf, byte(len(rr.Data)>>8), byte(len(rr.Data)))
		buf = append(buf, rr.Data...)
	}

	return buf
}

// parseName parses a DNS domain name from wire format (handles label compression)
func parseName(data []byte, offset int) (string, int, error) {
	var labels []string
	startOffset := offset

	for offset < len(data) {
		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		if (length & 0xc0) == 0xc0 {
			// Pointer
			if offset >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			ptr := ((length & 0x3f) << 8) | int(data[offset])
			offset++

			ptrName, _, err := parseName(data, ptr)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, strings.Split(strings.TrimSuffix(ptrName, "."), ".")...)
			break
		}

		if (length & 0xc0) != 0 {
			return "", 0, fmt.Errorf("invalid label")
		}

		if offset+length > len(data) {
			return "", 0, fmt.Errorf("truncated label")
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	name := ""
	for i, label := range labels {
		if i > 0 {
			name += "."
		}
		name += label
	}
	if name != "" {
		name += "."
	}

	_ = startOffset
	return name, offset, nil
}

// encodeName encodes a domain name to wire format
func encodeName(name string) ([]byte, error) {
	buf := make([]byte, 0, len(name)+2)

	if name == "" || name == "." {
		return []byte{0}, nil
	}

	labels := splitName(name)
	for _, label := range labels {
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)

	return buf, nil
}

// splitName splits a domain name into labels
func splitName(name string) []string {
	if name == "" || name == "." {
		return []string{}
	}

	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return strings.Split(name, ".")
}

// EncodeA encodes an A record (IPv4 address)
func EncodeA(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return nil
}

// EncodeAAAA encodes an AAAA record (IPv6 address)
func EncodeAAAA(ip net.IP) []byte {
	if ip16 := ip.To16(); ip16 != nil {
		// Make sure it's actually IPv6, not IPv4-mapped
		if ip.To4() == nil {
			return ip16
		}
	}
	return nil
}

// EncodeTXT encodes a TXT record
func EncodeTXT(text string) []byte {
	if len(text) > 255 {
		text = text[:255]
	}
	buf := make([]byte, len(text)+1)
	buf[0] = byte(len(text))
	copy(buf[1:], text)
	return buf
}

// EncodeMX encodes an MX record
func EncodeMX(preference uint16, exchange string) ([]byte, error) {
	encoded, err := encodeName(exchange)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2+len(encoded))
	buf[0] = byte(preference >> 8)
	buf[1] = byte(preference)
	copy(buf[2:], encoded)

	return buf, nil
}

// EncodeNS encodes an NS record
func EncodeNS(nameserver string) ([]byte, error) {
	return encodeName(nameserver)
}

// EncodeSOA encodes an SOA record
func EncodeSOA(mname, rname string, serial, refresh, retry, expire, minimum uint32) ([]byte, error) {
	mnameEnc, err := encodeName(mname)
	if err != nil {
		return nil, err
	}

	rnameEnc, err := encodeName(rname)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, len(mnameEnc)+len(rnameEnc)+20)
	pos := 0
	
	copy(buf[pos:], mnameEnc)
	pos += len(mnameEnc)
	
	copy(buf[pos:], rnameEnc)
	pos += len(rnameEnc)

	// Serial
	buf[pos] = byte(serial >> 24)
	buf[pos+1] = byte(serial >> 16)
	buf[pos+2] = byte(serial >> 8)
	buf[pos+3] = byte(serial)
	pos += 4

	// Refresh
	buf[pos] = byte(refresh >> 24)
	buf[pos+1] = byte(refresh >> 16)
	buf[pos+2] = byte(refresh >> 8)
	buf[pos+3] = byte(refresh)
	pos += 4

	// Retry
	buf[pos] = byte(retry >> 24)
	buf[pos+1] = byte(retry >> 16)
	buf[pos+2] = byte(retry >> 8)
	buf[pos+3] = byte(retry)
	pos += 4

	// Expire
	buf[pos] = byte(expire >> 24)
	buf[pos+1] = byte(expire >> 16)
	buf[pos+2] = byte(expire >> 8)
	buf[pos+3] = byte(expire)
	pos += 4

	// Minimum
	buf[pos] = byte(minimum >> 24)
	buf[pos+1] = byte(minimum >> 16)
	buf[pos+2] = byte(minimum >> 8)
	buf[pos+3] = byte(minimum)

	return buf, nil
}
