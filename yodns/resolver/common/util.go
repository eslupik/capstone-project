package common

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// TODO - there should be some build in mechanism for this. E.g. there is errros.Unwrap. Can we use that without this method?
func ChainErr(err1 error, err2 error) error {
	if err1 == nil && err2 == nil {
		return nil
	}
	if err1 == nil && err2 != nil {
		return err2
	}
	if err1 != nil && err2 == nil {
		return err1
	}
	return fmt.Errorf("inner: %v %v", err1, err2)
}

func ReadCsvFile(filePath string) ([][]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	return csvReader.ReadAll()
}

func Filter[T any](records []T, predicate func(item T) bool) (ret []T) {
	for _, rr := range records {
		if predicate(rr) {
			ret = append(ret, rr)
		}
	}
	return
}

func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

func Values[K comparable, V any](m map[K]V) []V {
	vals := make([]V, len(m))
	i := 0
	for k := range m {
		vals[i] = m[k]
		i++
	}
	return vals
}

func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MinUInt32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func MaxUInt32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func Must[T any](obj T, err error) T {
	if err != nil {
		panic(err)
	}
	return obj //nolint:ireturn
}

func SplitNoEmpty(s string, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}

func ToMap[T comparable](items ...T) map[T]any {
	result := make(map[T]any, len(items))
	for _, t := range items {
		result[t] = nil
	}
	return result
}

func Apply[T any, K any](items []T, f func(in T) K) []K {
	result := make([]K, 0, len(items))
	for _, t := range items {
		result = append(result, f(t))
	}
	return result
}

func AddKeysToMap[T comparable](m map[T]any, items ...T) {
	for _, t := range items {
		m[t] = nil
	}
}

func MergeInto[T comparable, V any](m1 map[T]V, m2 map[T]V) {
	for k, v := range m2 {
		m1[k] = v
	}
}
