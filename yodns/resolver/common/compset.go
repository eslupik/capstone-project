package common

import (
	"encoding/json"
	"sync"
)

type CompSet[T comparable] struct {
	mu    *sync.RWMutex
	inner map[T]any
}

// NewCompSet initializes a new set
func NewCompSet[T comparable](items ...T) CompSet[T] {
	result := CompSet[T]{
		mu:    new(sync.RWMutex),
		inner: make(map[T]any, len(items)),
	}
	for _, item := range items {
		result.inner[item] = nil
	}
	return result
}

// Add adds the items one or more to the set.
func (set CompSet[T]) Add(items ...T) {
	set.mu.Lock()
	defer set.mu.Unlock()
	for _, item := range items {
		set.inner[item] = nil
	}
}

// Items returns the all items in the set in a slice
func (set CompSet[T]) Items() (res []T) {
	set.mu.RLock()
	defer set.mu.RUnlock()
	return Keys(set.inner)
}

// Any returns true if this set contains any item.
func (set CompSet[T]) Any() bool {
	return len(set.inner) > 0
}

// Contains returns true if the item is contained in the set.
// Equality is determined using the hashCode() and equals() functions.
func (set CompSet[T]) Contains(item T) bool {
	set.mu.RLock()
	defer set.mu.RUnlock()
	_, exists := set.inner[item]
	return exists
}

// Len returns the number of items in the set.
func (set CompSet[T]) Len() int {
	set.mu.RLock()
	defer set.mu.RUnlock()
	return len(set.inner)
}

// MarshalJSON converts the set to an array-like json representation
func (set CompSet[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(set.Items())
}

// UnmarshalJSON initializes a set from an array-like json representation
func (set *CompSet[T]) UnmarshalJSON(bytes []byte) error {
	var elements []T
	if err := json.Unmarshal(bytes, &elements); err != nil {
		return err
	}

	set.inner = make(map[T]any, len(elements))
	set.mu = new(sync.RWMutex)
	set.Add(elements...)
	return nil
}
