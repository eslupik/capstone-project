package resolver

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"golang.org/x/exp/slices"
	"testing"
)

var _ Strategy = new(mockStrategy)

type mockStrategy struct {
	OnInitCallback             func(job *ResolutionJob)
	OnStartResolveNameCallback func(job *ResolutionJob, sname model.DomainName)
	OnResponseCallback         func(job *ResolutionJob, response model.MessageExchange, ns *model.NameServer, args any)
}

func (m mockStrategy) OnInit(job *ResolutionJob) {
	m.OnInitCallback(job)
}

func (m mockStrategy) OnStartResolveName(job *ResolutionJob, sname model.DomainName) {
	m.OnStartResolveNameCallback(job, sname)
}

func (m mockStrategy) OnResponse(job *ResolutionJob, response model.MessageExchange, ns *model.NameServer, args any) {
	m.OnResponseCallback(job, response, ns, args)
}

func TestResolutionJob_IsCNameOf(t *testing.T) {
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {},
		},
	}

	resolver.ResolveName("a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")
	resolver.ResolveCName("d.example.com.", "b.example.com.")

	if !resolver.IsCNAMEOrSelf("c.example.com.", "a.example.com.") {
		t.Errorf("Expected true, got false")
	}
	if !resolver.IsCNAMEOrSelf("b.example.com.", "a.example.com.") {
		t.Errorf("Expected true, got false")
	}
	if !resolver.IsCNAMEOrSelf("a.example.com.", "a.example.com.") {
		t.Errorf("Expected true, got false")
	}

	if resolver.IsCNAMEOrSelf("d.example.com.", "a.example.com.") {
		t.Errorf("Expected false, got true")
	}
	if resolver.IsCNAMEOrSelf("d.example.com.", "c.example.com.") {
		t.Errorf("Expected false, got true")
	}

	if resolver.IsCNAMEOrSelf("nonexisting.example.com.", "a.example.com.") {
		t.Errorf("Expected false, got true")
	}
	if resolver.IsCNAMEOrSelf("a.example.com.", "nonexisting.example.com.") {
		t.Errorf("Expected false, got true")
	}
}

func TestResolutionJob_ResolveCName_MaxCNAMEDepth(t *testing.T) {
	var calledNames []model.DomainName
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				calledNames = append(calledNames, sname)
			},
		},
		settings: Settings{
			MaxCNameDepth: 2,
		},
	}

	resolver.ResolveName("a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")

	// Not resolved because max depth
	resolver.ResolveCName("c.example.com.", "d.example.com.")
	// Not resolved because b is already being resolved
	resolver.ResolveCName("q.example.com.", "b.example.com.")

	expected := []model.DomainName{"a.example.com.", "b.example.com.", "c.example.com."}
	if !slices.Equal(calledNames, expected) {
		t.Errorf("Expected %v, got %v", expected, calledNames)
	}
}

// Tests that ResolveCName can handle a cycle.
func TestResolutionJob_ResolveCName_Cycle(t *testing.T) {
	var calledNames []model.DomainName
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				calledNames = append(calledNames, sname)
			},
		},
		settings: Settings{
			MaxCNameDepth: 3,
		},
	}

	resolver.ResolveName("a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")
	resolver.ResolveCName("c.example.com.", "a.example.com.")
	resolver.ResolveCName("c.example.com.", "b.example.com.")

	if !slices.Contains(calledNames, "a.example.com.") {
		t.Errorf("a.example.com. to be called")
	}
	if !slices.Contains(calledNames, "b.example.com.") {
		t.Errorf("b.example.com. to be called")
	}
	if !slices.Contains(calledNames, "c.example.com.") {
		t.Errorf("b.example.com. to be called")
	}
	if len(calledNames) != 3 {
		t.Errorf("Expected each name to be called only once.")
	}

}

// It tests that if there is a CNAME cycle, and the CNAME depth have to be reevaluated
// because a shorter chain was found, the reevaluation is actually terminating.
// Test exists because of real issue.
func TestResolutionJob_ResolveCName_Cycle_With_Reevaluation(t *testing.T) {
	var calledNames []model.DomainName
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				calledNames = append(calledNames, sname)
			},
		},
		settings: Settings{
			MaxCNameDepth: 2,
		},
	}

	resolver.ResolveName("a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")
	resolver.ResolveCName("c.example.com.", "d.example.com.") // Not resolved because max depth
	resolver.ResolveCName("d.example.com.", "b.example.com.")

	if slices.Contains(calledNames, "d.example.com.") {
		t.Errorf("Expected d.example.com. not to be called yet")
	}

	resolver.ResolveCName("x.example.com.", "c.example.com.") // Now d is only depth two - should be resolved

	if !slices.Contains(calledNames, "d.example.com.") {
		t.Errorf("d.example.com. to be called")
	}
}

func TestResolutionJob_ResolveCName_ShorterChainIsFound(t *testing.T) {
	var calledNames []model.DomainName
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				calledNames = append(calledNames, sname)
			},
		},
		settings: Settings{
			MaxCNameDepth: 2,
		},
	}

	resolver.ResolveName("a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")
	resolver.ResolveCName("c.example.com.", "d.example.com.") // Not resolved because max depth

	if slices.Contains(calledNames, "d.example.com.") {
		t.Errorf("Expected d.example.com. not to be called yet")
	}

	resolver.ResolveCName("x.example.com.", "c.example.com.") // Now d is only depth two - should be resolved

	if !slices.Contains(calledNames, "d.example.com.") {
		t.Errorf("d.example.com. to be called")
	}
}

func TestResolutionJob_GetCNAMEOrigins(t *testing.T) {
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {},
		},
	}

	resolver.ResolveName("x.example.com.")
	resolver.ResolveName("somethingelse.example.com.")
	resolver.ResolveCName("x.example.com.", "a.example.com.")
	resolver.ResolveCName("a.example.com.", "b.example.com.")
	resolver.ResolveCName("b.example.com.", "c.example.com.")
	resolver.ResolveCName("d.example.com.", "b.example.com.")
	resolver.ResolveCName("e.example.com.", "d.example.com.")
	resolver.ResolveCName("somethingelse.example.com.", "f.example.com.")
	resolver.ResolveCName("w.example.com.", "a.example.com.")

	origins := resolver.GetCNAMEOrigins("b.example.com.")

	if len(origins) != 6 {
		t.Errorf("Expected 6 origins, got %v", origins)
	}
	if _, exists := origins["x.example.com."]; !exists {
		t.Errorf("Expected x.example.com., got %v", origins)
	}
	if _, exists := origins["a.example.com."]; !exists {
		t.Errorf("Expected a.example.com., got %v", origins)
	}
	if _, exists := origins["b.example.com."]; !exists {
		t.Errorf("Expected b.example.com., got %v", origins)
	}
	if _, exists := origins["d.example.com."]; !exists {
		t.Errorf("Expected d.example.com., got %v", origins)
	}
	if _, exists := origins["e.example.com."]; !exists {
		t.Errorf("Expected e.example.com., got %v", origins)
	}
	if _, exists := origins["w.example.com."]; !exists {
		t.Errorf("Expected w.example.com., got %v", origins)
	}
}

func TestResolutionJob_ResolveCName_MaxCNameDepthZero(t *testing.T) {
	lastReceivedSname := ""
	nrOfCalls := 0
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		settings: Settings{
			MaxCNameDepth: 0,
		},
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				nrOfCalls++
				lastReceivedSname = string(sname)
			},
		},
	}

	resolver.ResolveName("initial.example.com")
	if lastReceivedSname != "initial.example.com" {
		t.Errorf("OnStartResolveNameCallback was not invoked correctly")
	}

	resolver.ResolveCName("initial.example.com", "cname.example.com")
	if lastReceivedSname != "initial.example.com" || nrOfCalls != 1 {
		t.Errorf("OnStartResolveNameCallback was not invoked for CNAME even though MaxCNameDepth is 0")
	}
}

func TestResolutionJob_ResolveCName_MaxCNameDepthIsRespected(t *testing.T) {
	lastReceivedSname := ""
	nrOfCalls := 0
	resolver := ResolutionJob{
		names:  make(map[model.DomainName]uint),
		cNames: make(map[model.DomainName]map[model.DomainName]any),
		settings: Settings{
			MaxCNameDepth: 2,
		},
		strategy: mockStrategy{
			OnStartResolveNameCallback: func(job *ResolutionJob, sname model.DomainName) {
				nrOfCalls++
				lastReceivedSname = string(sname)
			},
		},
	}

	resolver.ResolveName("initial.example.com")
	if lastReceivedSname != "initial.example.com" {
		t.Errorf("OnStartResolveNameCallback was not invoked correctly")
	}

	resolver.ResolveCName("initial.example.com", "cname1.example.com")
	if lastReceivedSname != "cname1.example.com" || nrOfCalls != 2 {
		t.Errorf("OnStartResolveNameCallback was not invoked for cname1.example.com")
	}

	resolver.ResolveCName("cname1.example.com", "cname2.example.com")
	if lastReceivedSname != "cname2.example.com" || nrOfCalls != 3 {
		t.Errorf("OnStartResolveNameCallback was not invoked for cname2.example.com")
	}

	resolver.ResolveCName("cname2.example.com", "cname3.example.com")
	if nrOfCalls != 3 {
		t.Errorf("OnStartResolveNameCallback was invoked for cname3.example.com even though MaxCNameDepth is %v", resolver.settings.MaxCNameDepth)
	}

	// Another CNAME for cname 1 - should be allowed
	resolver.ResolveCName("cname1.example.com", "cnameX.example.com")
	if lastReceivedSname != "cnameX.example.com" || nrOfCalls != 4 {
		t.Errorf("OnStartResolveNameCallback was not invoked for cnameX.example.com")
	}
}
