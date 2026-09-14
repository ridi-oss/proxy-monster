package athena

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

// Envelope retains unknown AWS JSON fields and their original representation.
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
		return nil, errors.New("athena: request must be a JSON object")
	}
	envelope := &Envelope{body: body, fields: make(map[string]fieldSpan)}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string)
		if _, exists := envelope.fields[name]; exists {
			return nil, fmt.Errorf("athena: duplicate field %q", name)
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
		return nil, errors.New("athena: trailing JSON data")
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

func (e *Envelope) QueryString() (string, bool, error) {
	value := e.Field("QueryString")
	if value == nil {
		return "", false, nil
	}
	if len(value) == 0 || value[0] != '"' {
		return "", true, errors.New("athena: QueryString must be a string")
	}
	var query string
	err := json.Unmarshal(value, &query)
	return query, true, err
}

func (e *Envelope) ExecutionParameters() ([]string, bool, error) {
	value := e.Field("ExecutionParameters")
	if value == nil {
		return nil, false, nil
	}
	if len(value) == 0 || value[0] != '[' {
		return nil, true, errors.New("athena: ExecutionParameters must be a string array")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(value, &values); err != nil {
		return nil, true, err
	}
	parameters := make([]string, len(values))
	for i, value := range values {
		if len(value) == 0 || value[0] != '"' {
			return nil, true, errors.New("athena: ExecutionParameters must be a string array")
		}
		if err := json.Unmarshal(value, &parameters[i]); err != nil {
			return nil, true, err
		}
	}
	return parameters, true, nil
}

func (e *Envelope) WithQueryString(query string) (*Envelope, error) {
	original, present, err := e.QueryString()
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, errors.New("athena: QueryString is missing")
	}
	if query == original {
		return e, nil
	}
	replacement, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	span := e.fields["QueryString"]
	body := make([]byte, 0, len(e.body)-(span.end-span.start)+len(replacement))
	body = append(body, e.body[:span.start]...)
	body = append(body, replacement...)
	body = append(body, e.body[span.end:]...)
	return DecodeEnvelope(body)
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
		return nil, errors.New("athena: request is not a JSON object")
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
