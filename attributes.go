// MIT License
//
// Copyright (c) 2017 Pressly Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package saml

// AttributesMap is a type that provides methods for working with SAML
// attributes.
type AttributesMap map[string][]string

// NewAttributesMap creates an attribute map given a third party assertion.
func NewAttributesMap(assertion *Assertion) *AttributesMap {
	props := make(AttributesMap)
	if assertion != nil && assertion.AttributeStatement != nil {
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
	}
	return &props
}

// Get returns the first value of the given attribute, if any.
func (a *AttributesMap) Get(name string) string {
	if v, ok := (map[string][]string)(*a)[name]; ok {
		return v[0]
	}
	return ""
}
