package model

import (
	"fmt"
	"golang.org/x/net/idna"
	"strings"
	"unicode"
)

var (
	ErrNameTooLong = fmt.Errorf("domain name is too long")
)

// DomainName represents a domain name.
type DomainName string

// GetLabelCount returns the number of labels in the domain name.
// The root label (empty string) will be counted. Examples:
//
// "." => 1
//
// "com." => 2
func (dn DomainName) GetLabelCount() int {
	if dn == "." {
		return 1 // The root label aka "empty string"
	}

	return strings.Count(string(dn), ".") + 1
}

func (dn DomainName) GetLabels() []string {
	return strings.Split(string(dn), ".")
}

// MustNewDomainName is like NewDomainName, but panics on error.
func MustNewDomainName(value string) DomainName {
	dn, err := NewDomainName(value)
	if err != nil {
		panic(err)
	}
	return dn
}

// NewDomainName creates a domain name based on the string. The will be rooted and casing will be normalized.
func NewDomainName(value string) (DomainName, error) {
	// Very simplistic checks, but we can be lenient here
	// Most important is, that the representation is unified for comparisons.
	if len(value) > 255 {
		return "", ErrNameTooLong
	}

	dn, err := canonicalName(value)
	return DomainName(dn), err
}

// IsTopLevelDomain is a convenience function that returns true if the label count is equal to 2 (counting the empty label)
func (dn DomainName) IsTopLevelDomain() bool {
	return dn.GetLabelCount() == 2 //nolint:gomnd
}

// WithWWW returns the domain name with a prepended "www."
// If the name already starts with "www.", the function will return the original domain name.
func (dn DomainName) WithWWW() DomainName {
	if strings.HasPrefix(string(dn), "www.") {
		return dn
	}
	r, _ := dn.PrependLabel("www")
	return r
}

// TrimWWW returns the domain name without a prepended "www."
// If the name does not start with "www.", the function will return the original domain name.
func (dn DomainName) TrimWWW() DomainName {
	if strings.HasPrefix(string(dn), "www.") {
		return dn.GetAncestor(dn.GetLabelCount() - 1)
	}
	return dn
}

// GetParents returns all parents of the domain name, starting from "." ending with the domain name itself
func (dn DomainName) GetParents() []DomainName {
	var result []DomainName
	for i := 1; i <= dn.GetLabelCount(); i++ {
		result = append(result, dn.GetAncestor(i))
	}
	return result
}

func (dn DomainName) Equal(other DomainName) bool {
	return string(dn) == string(other)
}

func (dn DomainName) EqualString(other string) bool {
	c, err := canonicalName(other)
	if err != nil {
		return false
	}
	return string(dn) == c
}

// GetAncestor returns an ancestor of the domain name that has the specified numbers of labels (counting the root label)
// If the length is negative or greater than the labels in the domain name, the function will cause a panic.
func (dn DomainName) GetAncestor(length int) DomainName {
	if length < 0 {
		panic("length must be positive")
	}

	if length <= 1 {
		return "."
	}

	var labels = strings.Split(string(dn), ".")

	var total = len(labels)

	var s = labels[total-length : total]
	return DomainName(strings.Join(s, "."))
}

// PrependLabel prepends a label to the domain name.
func (dn DomainName) PrependLabel(label string) (DomainName, error) {
	return NewDomainName(label + "." + string(dn))
}

// IsSubDomainOf returns true if the specified domain name is a subdomain of (or equal to) the domain name.
func (dn DomainName) IsSubDomainOf(parent DomainName) bool {
	return CompareDomainName(string(parent), string(dn)) == CountLabel(string(parent))
}

// CanonicalName returns the domain name in canonical form. A name in canonical
// form is lowercase and fully qualified. See Section 6.2 in RFC 4034.
// According to the RFC all uppercase US-ASCII letters in the owner name of the
// RR are replaced by the corresponding lowercase US-ASCII letters.
// From https://github.com/miekg/dns/blob/master/labels
func canonicalName(s string) (string, error) {
	var result strings.Builder
	for _, ch := range toFqdn(s) {
		if unicode.IsUpper(ch) && (ch >= 0x00 && ch <= 0x7F) {
			result.WriteRune(unicode.ToLower(ch))
		} else {
			result.WriteRune(ch)
		}
	}

	return idna.ToASCII(result.String())
}

func toFqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
