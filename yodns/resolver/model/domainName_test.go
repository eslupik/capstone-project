package model

import (
	"fmt"
	"reflect"
	"testing"
)

func Test_TrimWWW(t *testing.T) {
	n, _ := NewDomainName("www.example.com.")

	if n.TrimWWW() != "example.com." {
		t.Errorf("Expected www. to be removed.")
	}
}

func TestZone_IsTopLevelDomain(t *testing.T) {
	tests := []struct {
		name string
		dn   DomainName
		want bool
	}{
		{
			name: "IsRoot_ExpectFalse",
			dn:   ".",
			want: false,
		},
		{
			name: "IsTld_ExpectTrue",
			dn:   "com.",
			want: true,
		},
		{
			name: "IsRoot_ExpectFalse",
			dn:   "example.com.",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dn.IsTopLevelDomain(); got != tt.want {
				t.Errorf("DomainName.IsTopLevelDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainName_IsSubDomainOf(t *testing.T) {
	tests := []struct {
		name  string
		dn    DomainName
		other DomainName
		want  bool
	}{
		{
			name:  "IsProperSubDomain",
			dn:    "example.com",
			other: "com",
			want:  true,
		},
		{
			name:  "IsProperSubDomainWithCasing",
			dn:    "example.com",
			other: "CoM",
			want:  true,
		},
		{
			name:  "OtherIsRoot",
			dn:    "example.com",
			other: ".",
			want:  true,
		},
		{
			name:  "DomainsAreEqual",
			dn:    "a.example.com",
			other: "a.example.com",
			want:  true,
		},
		{
			name:  "DomainsAreNotEqualSameLength",
			dn:    "a.example.com",
			other: "b.example.com",
			want:  false,
		},
		{
			name:  "DomainsAreNotEqualDifferentLength",
			dn:    "example.com",
			other: "b.example.com",
			want:  false,
		},
		{
			name:  "NonAsciiCharactersAreCaseSensitive",
			dn:    "a.Ñexample.com",
			other: "ñexample.com",
			want:  false,
		},
		{
			name:  "DomainIsSubstringButNotSubdomain",
			dn:    "ab.example.com",
			other: "b.example.com",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dn.IsSubDomainOf(tt.other); got != tt.want {
				t.Errorf("DomainName.IsSubDomainOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainName_GetLabelCount(t *testing.T) {
	tests := []struct {
		name string
		dn   DomainName
		want int
	}{
		{
			name: "Root_ExpectOne",
			dn:   ".",
			want: 1,
		},
		{
			name: "TLD_ExpecdTwo",
			dn:   "com.",
			want: 2,
		},
		{
			name: "LongName",
			dn:   "a.b.c.d.e.",
			want: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dn.GetLabelCount(); got != tt.want {
				t.Errorf("DomainName.GetLabelCount() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainName_GetAncestor_GetLabelCount_Consistent(t *testing.T) {
	tests := []struct {
		name string
		dn   DomainName
	}{
		{
			name: "Root",
			dn:   ".",
		},
		{
			name: "TLD",
			dn:   "com.",
		},
		{
			name: "SLD",
			dn:   "example.com.",
		},
		{
			name: "LongName",
			dn:   "a.b.c.d.e.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dn.GetAncestor(tt.dn.GetLabelCount()); got != tt.dn {
				t.Errorf("DomaiName.GetAncestor(DomainName.GetLabelCount()) = %v, want %v", got, tt.dn)
			}
		})
	}
}

func TestDomainName_GetAncestor(t *testing.T) {
	tests := []struct {
		name   string
		dn     DomainName
		length int
		want   DomainName
	}{
		{
			name:   "GetAncestorOfLengthZero_ExpectRoot",
			dn:     "test.x.com.",
			length: 0,
			want:   ".",
		},
		{
			name:   "GetAncestorOfLengthOne_ExpectRoot",
			dn:     "test.x.com.",
			length: 1,
			want:   ".",
		},
		{
			name:   "GetAncestorOfLengthTwo_ExpectTld",
			dn:     "test.x.com.",
			length: 2,
			want:   "com.",
		},
		{
			name:   "GetAncestorOfLengthThree",
			dn:     "test.x.com.",
			length: 3,
			want:   "x.com.",
		},
		{
			name:   "GetAncestorOfLengthFour",
			dn:     "test.x.com.",
			length: 4,
			want:   "test.x.com.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dn.GetAncestor(tt.length); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DomainName.GetAncestor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainName_GetAncestor_ExpectOutOfBounds(t *testing.T) {
	tests := []struct {
		name   string
		dn     DomainName
		length int
		want   DomainName
	}{
		{
			name:   "NegativeLength_ExpectOutOfBounds",
			dn:     "test.x.com.",
			length: -1,
		},
		{
			name:   "TooLong_ExpectOutOfBounds",
			dn:     "test.x.com.",
			length: 7,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("(%v).GetAncestor(%v) expected panic", tt.dn, tt.length)
				}
			}()
			tt.dn.GetAncestor(tt.length)
		})
	}
}

func TestNewDomainName_CanCompare(t *testing.T) {
	tests := []struct {
		name1     string
		name2     string
		wantEqual bool
	}{
		{
			name1:     "a.example.com.",
			name2:     "a.example.com.",
			wantEqual: true,
		},
		{
			name1:     "a.example.com.",
			name2:     "A.eXamPLE.com.",
			wantEqual: true,
		},
		{
			name1:     "a.example.com.",
			name2:     "b.example.com.",
			wantEqual: false,
		},
		{
			name1:     "ü.com.",
			name2:     "xn--tda.com.",
			wantEqual: true,
		},
		// Do we want these to be equal?
		//{
		//	name1:     "Ü.com.",
		//	name2:     "xn--tda.com.",
		//	wantEqual: true,
		//},
		//{
		//	name1:     "ü.com.",
		//	name2:     "Ü.com.",
		//	wantEqual: true,
		//},
		{
			name1:     "a.com.",
			name2:     "a.com",
			wantEqual: true,
		},
		{
			name1:     "",
			name2:     ".",
			wantEqual: true,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("equal(%v, %v)", tt.name1, tt.name2), func(t *testing.T) {
			eq := MustNewDomainName(tt.name1) == MustNewDomainName(tt.name2)
			if eq != tt.wantEqual {
				t.Errorf("equal got = %v, want %v", eq, tt.wantEqual)
			}
		})
	}
}
