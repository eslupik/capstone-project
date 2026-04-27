package internal

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestMessageIdGenerator_GetMessageID(t *testing.T) {
	NewId = func() uint16 { return 3 }
	idGen := NewIdGen()

	msgID := idGen.GetFreeMessageID()
	if msgID != 3 {
		t.Errorf("Expected 3, got %v", msgID)
	}
}

func TestMessageIdGenerator_CooldownThenReuse(t *testing.T) {
	idsToReturns := []uint16{3, 3, 4, 3}
	idx := -1
	NewId = func() uint16 {
		idx++
		return idsToReturns[idx]
	}
	idGen := NewIdGen()
	idGen.coolDownPeriod = 10 * time.Millisecond

	msgID1 := idGen.GetFreeMessageID()
	idGen.ReleaseMessageID(msgID1)

	// should not be 3, because 3 is still in cooldown
	msgID2 := idGen.GetFreeMessageID()

	time.Sleep(10 * time.Millisecond)

	msgID3 := idGen.GetFreeMessageID()

	if msgID1 != 3 {
		t.Errorf("Expected msgId to be 3")
	}
	if msgID2 != 4 {
		t.Errorf("Expected msgId to be 4 because 3 is in cooldown")
	}
	if msgID3 != 3 {
		t.Errorf("Expected msgId to be 3")
	}
}

func TestMessageIdGenerator_GetMessageID_NoDuplicates(t *testing.T) {
	idsToReturns := []uint16{3, 3, 4}
	idx := 0
	NewId = func() uint16 {
		idx++
		return idsToReturns[idx]
	}
	idGen := NewIdGen()

	msgID1 := idGen.GetFreeMessageID()
	msgID2 := idGen.GetFreeMessageID()

	if msgID2 != 4 {
		t.Errorf("Expected msgId2 to be 4")
	}

	if msgID1 == msgID2 {
		t.Errorf("Expected msgId to be different")
	}
}

func TestMessageIdGenerator_InflightIDs(t *testing.T) {
	NewId = func() uint16 { return uint16(rand.Int() % math.MaxUint16) }

	idGen := NewIdGen()

	msgID1 := idGen.GetFreeMessageID()
	msgID2 := idGen.GetFreeMessageID()
	msgID3 := idGen.GetFreeMessageID()
	idGen.ReleaseMessageID(msgID3)

	inflight := idGen.InflightIDs()

	if len(inflight) != 2 {
		t.Errorf("Expected inflight ids to contain two items")
	}

	if inflight[0] != msgID1 && inflight[1] != msgID1 {
		t.Errorf("Expected inflight ids to contain %v", msgID1)
	}

	if inflight[0] != msgID2 && inflight[1] != msgID2 {
		t.Errorf("Expected inflight ids to contain %v", msgID2)
	}
}
