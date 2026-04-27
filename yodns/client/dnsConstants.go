package client

// Copied from https://github.com/miekg/dns/blob/master/types.go
//
// BSD 3-Clause License
//
// Copyright (c) 2009, The Go Authors. Extensions copyright (c) 2011, Miek Gieben.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Wire constants and supported types.
const (
	// valid RR_Header.Rrtype and OriginalQuestion.qtype

	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41 // EDNS
	TypeAPL        uint16 = 42
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeCSYNC      uint16 = 62
	TypeZONEMD     uint16 = 63
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
	TypeAVC        uint16 = 258

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// valid OriginalQuestion.Qtype only
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeReserved uint16 = 65535

	// valid OriginalQuestion.Qclass
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
	RcodeSuccess        = 0  // NoError   - No Error                          [DNS]
	RcodeFormatError    = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure  = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError      = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused        = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain       = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset        = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset        = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth        = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone        = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeBadSig         = 16 // BADSIG    - TSIG Signature Failure            [TSIG]
	RcodeBadVers        = 16 // BADVERS   - Bad OPT Version                   [EDNS0]
	RcodeBadKey         = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime        = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode        = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName        = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg         = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc       = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie      = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

	// Message Opcodes. There is no 3.
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
	OpcodeNotify = 4
	OpcodeUpdate = 5
)

var rtypeToString = map[uint16]string{
	TypeNone:       "None",
	TypeA:          "A",
	TypeNS:         "NS",
	TypeMD:         "MD",
	TypeMF:         "MF",
	TypeCNAME:      "CNAME",
	TypeSOA:        "SOA",
	TypeMB:         "MB",
	TypeMG:         "MG",
	TypeMR:         "MR",
	TypeNULL:       "NULL",
	TypePTR:        "PTR",
	TypeHINFO:      "HINFO",
	TypeMINFO:      "MINFO",
	TypeMX:         "MX",
	TypeTXT:        "TXT",
	TypeRP:         "RP",
	TypeAFSDB:      "AFSDB",
	TypeX25:        "X25",
	TypeISDN:       "ISDN",
	TypeRT:         "RT",
	TypeNSAPPTR:    "NSAPPTR",
	TypeSIG:        "SIG",
	TypeKEY:        "KEY",
	TypePX:         "PX",
	TypeGPOS:       "GPOS",
	TypeAAAA:       "AAAA",
	TypeLOC:        "LOC",
	TypeNXT:        "NXT",
	TypeEID:        "EID",
	TypeNIMLOC:     "NIMLOC",
	TypeSRV:        "SRV",
	TypeATMA:       "ATMA",
	TypeNAPTR:      "NAPTR",
	TypeKX:         "KX",
	TypeCERT:       "CERT",
	TypeDNAME:      "DNAME",
	TypeOPT:        "OPT",
	TypeAPL:        "APL",
	TypeDS:         "DS",
	TypeSSHFP:      "SSHFP",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeDHCID:      "DHCID",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTLSA:       "TLSA",
	TypeSMIMEA:     "SMIMEA",
	TypeHIP:        "HIP",
	TypeNINFO:      "NINFO",
	TypeRKEY:       "RKEY",
	TypeTALINK:     "TALINK",
	TypeCDS:        "CDS",
	TypeCDNSKEY:    "CDNSKEY",
	TypeOPENPGPKEY: "OPENPGPKEY",
	TypeCSYNC:      "CSYNC",
	TypeZONEMD:     "ZONEMD",
	TypeSVCB:       "SVCB",
	TypeHTTPS:      "HTTPS",
	TypeSPF:        "SPF",
	TypeUINFO:      "UINFO",
	TypeUID:        "UID",
	TypeGID:        "GID",
	TypeUNSPEC:     "UNSPEC",
	TypeNID:        "NID",
	TypeL32:        "L32",
	TypeL64:        "L64",
	TypeLP:         "LP",
	TypeEUI48:      "EUI48",
	TypeEUI64:      "EUI64",
	TypeURI:        "URI",
	TypeCAA:        "CAA",
	TypeAVC:        "AVC",
	TypeTKEY:       "TKEY",
	TypeTSIG:       "TSIG",
	TypeIXFR:       "IXFR",
	TypeAXFR:       "AXFR",
	TypeMAILB:      "MAILB",
	TypeMAILA:      "MAILA",
	TypeANY:        "ANY",
}
