package apphost

import (
	"bytes"
	"encoding/json"
)

// bindingsMap is like map[string]*Binding, but also retains information about the order the keys of the object where in
// when it was unmarshalled from JSON.
type bindingsMap struct {
	bindings map[string]*Binding
	keys     []string
}

func (b *bindingsMap) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &b.bindings); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))

	// read the start of the object
	_, err := dec.Token()
	if err != nil {
		return err
	}

	for {
		// read key or end
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if tok == json.Delim('}') {
			return nil
		} else {
			b.keys = append(b.keys, tok.(string))
		}

		// read binding value (and discard it, we already unmarshalled it into b.bindings)
		var b Binding
		if err := dec.Decode(&b); err != nil {
			return err
		}
	}
}
