// Package option provides a minimal, JSON-preserving model of a sing-box
// configuration: only the fields be3600 manipulates (outbounds and their
// selector/urltest members) are typed, everything else is carried through
// untouched as raw JSON.
package option

import (
	"encoding/json"
)

type SelectorOutboundOptions struct {
	Outbounds []string `json:"outbounds"`
}

type URLTestOutboundOptions struct {
	Outbounds []string `json:"outbounds"`
}

// Outbound keeps every field of the original JSON object in `fields` and
// mirrors the few fields callers need into typed members. MarshalJSON writes
// the typed members back over the preserved raw fields.
type Outbound struct {
	Type            string
	Tag             string
	SelectorOptions SelectorOutboundOptions
	URLTestOptions  URLTestOutboundOptions

	fields map[string]json.RawMessage
}

func (o *Outbound) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	o.fields = fields
	if raw, ok := fields["type"]; ok {
		if err := json.Unmarshal(raw, &o.Type); err != nil {
			return err
		}
	}
	if raw, ok := fields["tag"]; ok {
		if err := json.Unmarshal(raw, &o.Tag); err != nil {
			return err
		}
	}
	switch o.Type {
	case "selector":
		return json.Unmarshal(data, &o.SelectorOptions)
	case "urltest":
		return json.Unmarshal(data, &o.URLTestOptions)
	}
	return nil
}

func (o Outbound) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(o.fields)+3)
	for k, v := range o.fields {
		fields[k] = v
	}
	set := func(key string, value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		fields[key] = raw
		return nil
	}
	if o.Type != "" {
		if err := set("type", o.Type); err != nil {
			return nil, err
		}
	}
	if o.Tag != "" {
		if err := set("tag", o.Tag); err != nil {
			return nil, err
		}
	}
	switch o.Type {
	case "selector":
		if err := set("outbounds", o.SelectorOptions.Outbounds); err != nil {
			return nil, err
		}
	case "urltest":
		if err := set("outbounds", o.URLTestOptions.Outbounds); err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

// FromMap builds an Outbound from a plain map (used by the link converter).
func FromMap(m map[string]any) (Outbound, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return Outbound{}, err
	}
	var o Outbound
	if err := json.Unmarshal(data, &o); err != nil {
		return Outbound{}, err
	}
	return o, nil
}

// Options is a whole sing-box configuration. Sections other than "outbounds"
// are preserved verbatim.
type Options struct {
	Outbounds []Outbound

	fields map[string]json.RawMessage
}

func (o *Options) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	o.fields = fields
	if raw, ok := fields["outbounds"]; ok {
		return json.Unmarshal(raw, &o.Outbounds)
	}
	return nil
}

func (o Options) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(o.fields)+1)
	for k, v := range o.fields {
		fields[k] = v
	}
	raw, err := json.Marshal(o.Outbounds)
	if err != nil {
		return nil, err
	}
	fields["outbounds"] = raw
	return json.Marshal(fields)
}
