package model

import (
	"testing"
)

func Test_ToSLD_Error(t *testing.T) {
	var psl PSL
	psl.public.Store(MustNewDomainName("com."), nil)

	dn := MustNewDomainName("com.")

	_, err := psl.ToPLD(dn)
	if err == nil {
		t.Errorf("Expected error")
	}
}

func Test_ToPLD(t *testing.T) {
	var psl PSL
	psl.public.Store(MustNewDomainName("."), nil)
	psl.public.Store(MustNewDomainName("com."), nil)
	psl.public.Store(MustNewDomainName("uk."), nil)
	psl.public.Store(MustNewDomainName("co.uk."), nil)
	psl.public.Store(MustNewDomainName("c."), nil)
	psl.public.Store(MustNewDomainName("b.c."), nil)
	psl.public.Store(MustNewDomainName("a.b.c."), nil)

	tests := []struct {
		dn   DomainName
		want DomainName
	}{
		{
			dn:   "example.com.",
			want: "example.com.",
		},
		{
			dn:   "www.example.com.",
			want: "example.com.",
		},
		{
			dn:   "example.co.uk.",
			want: "example.co.uk.",
		},
		{
			dn:   "zone.zone.example.co.uk.",
			want: "example.co.uk.",
		},
		{
			dn:   "d.a.b.c.",
			want: "d.a.b.c.",
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.dn), func(t *testing.T) {
			got, err := psl.ToPLD(tt.dn)
			if err != nil {
				t.Errorf("DomainName.ToPLD() got error %v", err)
			}
			if got != tt.want {
				t.Errorf("DomainName.ToPLD() = %v, want %v", got, tt.want)
			}
		})
	}
}
