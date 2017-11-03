package saml

// AttributesMap is a type that provides methods for working with SAML
// attributes.
type AttributesMap map[string][]string

// NewAttributesMap creates an attribute map given a third party assertion.
func NewAttributesMap(assertion *Assertion) *AttributesMap {
	props := make(AttributesMap)
	if assertion == nil {
		return &props
	}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		props[assertion.Subject.NameID.Format] = []string{assertion.Subject.NameID.Value}
	}

	if assertion.AttributeStatement != nil {
		for _, attr := range assertion.AttributeStatement.Attributes {
			values := []string{}
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}
			key := attr.Name
			if key == "" {
				key = attr.FriendlyName
			}
			props[key] = values
		}
		return &props
	}

	return &props
}

// Get returns the first value of the given attribute, if any.
func (a *AttributesMap) Get(name string) string {
	if v, ok := (map[string][]string)(*a)[name]; ok {
		if len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
