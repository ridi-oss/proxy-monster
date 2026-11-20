package httpdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type fieldSpan struct {
	start int
	end   int
}

// Envelope is one JSON object kept as its original bytes. Fields the proxy never touches keep their exact
// representation (numbers, ordering, unknown future fields), and only the named field a rewrite replaces
// changes, so a forwarded body is byte-identical to what the client sent except where a decision applied.
type Envelope struct {
	body   []byte
	fields map[string]fieldSpan
}

func DecodeEnvelope(body []byte) (*Envelope, error) {
	body = bytes.Clone(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, errors.New("httpdb: request must be a JSON object")
	}
	envelope := &Envelope{body: body, fields: make(map[string]fieldSpan)}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string)
		if _, exists := envelope.fields[name]; exists {
			return nil, fmt.Errorf("httpdb: duplicate field %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		end := int(decoder.InputOffset())
		envelope.fields[name] = fieldSpan{start: end - len(value), end: end}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("httpdb: trailing JSON data")
	}
	return envelope, nil
}

func (e *Envelope) Bytes() []byte { return bytes.Clone(e.body) }

func (e *Envelope) Field(name string) json.RawMessage {
	span, ok := e.fields[name]
	if !ok {
		return nil
	}
	return bytes.Clone(e.body[span.start:span.end])
}

// Replace returns the body with a present field's value replaced, or an error when the field is absent.
func (e *Envelope) Replace(name string, value any) ([]byte, error) {
	span, present := e.fields[name]
	if !present {
		return nil, fmt.Errorf("httpdb: missing field %s", name)
	}
	replacement, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(e.body)+len(replacement))
	result = append(result, e.body[:span.start]...)
	result = append(result, replacement...)
	result = append(result, e.body[span.end:]...)
	return result, nil
}

// WithField replaces the named field's value, appending the field when absent.
func (e *Envelope) WithField(name string, value any) (*Envelope, error) {
	replacement, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if span, present := e.fields[name]; present {
		if bytes.Equal(e.body[span.start:span.end], replacement) {
			return e, nil
		}
		body := make([]byte, 0, len(e.body)-(span.end-span.start)+len(replacement))
		body = append(body, e.body[:span.start]...)
		body = append(body, replacement...)
		body = append(body, e.body[span.end:]...)
		return DecodeEnvelope(body)
	}
	key, err := json.Marshal(name)
	if err != nil {
		return nil, err
	}
	closing := bytes.LastIndexByte(e.body, '}')
	if closing < 0 {
		return nil, errors.New("httpdb: request is not a JSON object")
	}
	body := make([]byte, 0, len(e.body)+len(key)+len(replacement)+2)
	body = append(body, e.body[:closing]...)
	if len(e.fields) > 0 {
		body = append(body, ',')
	}
	body = append(body, key...)
	body = append(body, ':')
	body = append(body, replacement...)
	body = append(body, e.body[closing:]...)
	return DecodeEnvelope(body)
}

// WithoutField removes the named field; an absent field leaves the envelope unchanged.
func (e *Envelope) WithoutField(name string) (*Envelope, error) {
	if _, present := e.fields[name]; !present {
		return e, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(e.body, &fields); err != nil {
		return nil, err
	}
	delete(fields, name)
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return DecodeEnvelope(body)
}
