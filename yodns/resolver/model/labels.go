package model

// This code is copied from https://github.com/miekg/dns/blob/5d3f81bc34811c5596b71d1ff73a9e30321694f5/labels.go#L4
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

// Holds a bunch of helper functions for dealing with labels.

// CompareDomainName compares the names s1 and s2 and
// returns how many labels they have in common starting from the *right*.
// The comparison stops at the first inequality. The names are downcased
// before the comparison.
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
//
// s1 and s2 must be syntactically valid domain names.
func CompareDomainName(s1, s2 string) (n int) {
	// the first check: root label
	if s1 == "." || s2 == "." {
		return 0
	}

	l1 := Split(s1)
	l2 := Split(s2)

	j1 := len(l1) - 1 // end
	i1 := len(l1) - 2 // start
	j2 := len(l2) - 1
	i2 := len(l2) - 2
	// the second check can be done here: last/only label
	// before we fall through into the for-loop below
	if equal(s1[l1[j1]:], s2[l2[j2]:]) {
		n++
	} else {
		return
	}
	for {
		if i1 < 0 || i2 < 0 {
			break
		}
		if equal(s1[l1[i1]:l1[j1]], s2[l2[i2]:l2[j2]]) {
			n++
		} else {
			break
		}
		j1--
		i1--
		j2--
		i2--
	}
	return
}

// CountLabel counts the number of labels in the string s.
// s must be a syntactically valid domain name.
func CountLabel(s string) (labels int) {
	if s == "." {
		return
	}
	off := 0
	end := false
	for {
		off, end = NextLabel(s, off)
		labels++
		if end {
			return
		}
	}
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}, www.miek.nl also returns []int{0, 4, 9}.
// The root name (.) returns nil. Also see SplitDomainName.
// s must be a syntactically valid domain name.
func Split(s string) []int {
	if s == "." {
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

// NextLabel returns the index of the start of the next label in the
// string s starting at offset. A negative offset will cause a panic.
// The bool end is true when the end of the string has been reached.
// Also see PrevLabel.
func NextLabel(s string, offset int) (i int, end bool) {
	if s == "" {
		return 0, true
	}
	for i = offset; i < len(s)-1; i++ {
		if s[i] != '.' {
			continue
		}
		j := i - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-i)%2 == 0 {
			continue
		}

		return i + 1, false
	}
	return i + 1, true
}

// PrevLabel returns the index of the label when starting from the right and
// jumping n labels to the left.
// The bool start is true when the start of the string has been overshot.
// Also see NextLabel.
func PrevLabel(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}

// equal compares a and b while ignoring case. It returns true when equal otherwise false.
func equal(a, b string) bool {
	// might be lifted into API function.
	la := len(a)
	lb := len(b)
	if la != lb {
		return false
	}

	for i := la - 1; i >= 0; i-- {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}
