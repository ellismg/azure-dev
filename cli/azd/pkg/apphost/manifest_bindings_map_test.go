package apphost

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBindingsMap(t *testing.T) {
	m := &bindingsMap{}
	err := json.Unmarshal([]byte(`{ "a": {}, "c": {}, "b": {} }`), &m)
	assert.NoError(t, err)

	assert.Len(t, m.bindings, 3)
	assert.Contains(t, m.bindings, "a")
	assert.Contains(t, m.bindings, "b")
	assert.Contains(t, m.bindings, "c")
	assert.Equal(t, []string{"a", "c", "b"}, m.keys)
}
