package model

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type PSL struct {
	// public part of the PSL - everything before the line "===BEGIN PRIVATE DOMAINS==="
	public sync.Map

	// private part of the PSL - everything after the line "===BEGIN PRIVATE DOMAINS==="
	private sync.Map
}

func LoadPSL(pslPath string) (*PSL, error) {
	if pslPath == "" {
		return nil, fmt.Errorf("no PSL path provided")
	}

	f, err := os.Open(pslPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	psl := PSL{}

	scanner := bufio.NewScanner(f)

	private := false
	for scanner.Scan() {
		line := scanner.Text()

		if strings.EqualFold(line, "// ===BEGIN PRIVATE DOMAINS===") {
			private = true
		}

		if strings.HasPrefix(line, "//") {
			continue
		}

		// Some names in the PSL start with "*." - for the purpose of clustering and batching, we can just trim it.
		line = strings.TrimPrefix(line, "*.")

		// Everything above a public suffix should also be treated as a public suffix
		// (e.g. co.za. is in the list, but .za is missing)
		dn := MustNewDomainName(line)
		if private {
			psl.StorePrivate(dn)
		} else {
			psl.StorePublic(dn)
		}
	}

	return &psl, nil
}

func (psl *PSL) StorePrivate(publicSuffix DomainName) {
	for i := 1; i <= publicSuffix.GetLabelCount(); i++ {
		psl.private.Store(publicSuffix.GetAncestor(i), nil)
	}
}

func (psl *PSL) StorePublic(publicSuffix DomainName) {
	for i := 1; i <= publicSuffix.GetLabelCount(); i++ {
		psl.public.Store(publicSuffix.GetAncestor(i), nil)
	}
}

// NoPrivate returns a copy of the PSL with the private part removed, i.e. the part after "===BEGIN PRIVATE DOMAINS==="
func (psl *PSL) NoPrivate() *PSL {
	return &PSL{
		public: psl.public,
	}
}

func (psl *PSL) contains(dn DomainName) bool {
	if _, ok := psl.public.Load(dn); ok {
		return true
	}

	if _, ok := psl.private.Load(dn); ok {
		return true
	}

	return false
}

// PublicSuffix uses a public suffix list to return the public suffix of this name
func (psl *PSL) PublicSuffix(dn DomainName) DomainName {
	if psl.contains(dn) {
		return dn
	}

	labels := dn.GetLabelCount()
	last := MustNewDomainName(".")
	for i := 1; i < labels+1; i++ {
		next := dn.GetAncestor(i)
		if !psl.contains(next) {
			return last
		}
		last = next
	}

	return "."
}

func (psl *PSL) IsPublixSuffix(dn DomainName) bool {
	return psl.contains(dn)
}

// ToPLD uses a public suffix list to return the "pay-level-domain", that is the public suffix of this name plus one label.
func (psl *PSL) ToPLD(dn DomainName) (DomainName, error) {
	if psl.contains(dn) {
		return dn, fmt.Errorf("domain name itself is a public suffix")
	}

	labels := dn.GetLabelCount()
	publicSuffix := psl.PublicSuffix(dn)
	psLabels := publicSuffix.GetLabelCount()

	if labels < psLabels {
		// Should never happen
		panic("public suffix has more labels than domain name")
	}
	if labels == psLabels {
		// This should never happen as we do the lookup above...
		panic(fmt.Sprintf("domain name %v (%v labels) is a public suffix", dn, labels))
	}

	return dn.GetAncestor(psLabels + 1), nil
}

// ToPLDNoPrivate is like ToPLD, but will not consider the "private" part of the PSL (i.e. the part after "===BEGIN PRIVATE DOMAINS===")
func (psl *PSL) ToPLDNoPrivate(dn DomainName) (DomainName, error) {
	if psl.contains(dn) {
		return dn, fmt.Errorf("domain name itself is a public suffix")
	}

	labels := dn.GetLabelCount()
	publicSuffix := psl.PublicSuffix(dn)
	psLabels := publicSuffix.GetLabelCount()

	if labels < psLabels {
		// Should never happen
		panic("public suffix has more labels than domain name")
	}
	if labels == psLabels {
		// This should never happen as we do the lookup above...
		panic(fmt.Sprintf("domain name %v (%v labels) is a public suffix", dn, labels))
	}

	return dn.GetAncestor(psLabels + 1), nil
}

// GetPrivateParents returns all parents of the domain name, starting from the first private label to the domain name itself.
// The second value returned, is the longest public suffix that was identified.
func (psl *PSL) GetPrivateParents(dn DomainName) ([]DomainName, DomainName) {
	var result []DomainName

	ps := psl.PublicSuffix(dn)
	for i := ps.GetLabelCount() + 1; i <= dn.GetLabelCount(); i++ {
		result = append(result, dn.GetAncestor(i))
	}
	return result, ps
}

func (psl *PSL) IsSLD(dn DomainName) bool {
	sld, err := psl.ToPLD(dn)
	return err == nil && sld == dn
}

func (psl *PSL) GetDepthBelowPublicSuffix(zone *Zone) int {
	if psl.IsPublixSuffix(zone.Name) {
		return 0
	}

	return psl.GetDepthBelowPublicSuffix(zone.Parent) + 1
}
