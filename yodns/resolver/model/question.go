package model

// A Question is asked by clients to name servers in search for a response
type Question struct {
	Name  DomainName
	Type  uint16
	Class uint16
}

// Ask creates a question with the specified parameters.
// Ask is an alternative way of creating the question struct (less lines needed)
func Ask(name DomainName, qType uint16) Question {
	return Question{
		Name:  name,
		Type:  qType,
		Class: 1, // Class IN
	}
}
