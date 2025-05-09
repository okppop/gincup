package gincup

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSONArray is a custom type for handling string arrays in JSON
type JSONArray []string

// Value implements the driver.Valuer interface
func (a JSONArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return "[]", nil
	}
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface
func (a *JSONArray) Scan(value interface{}) error {
	if value == nil {
		*a = JSONArray{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("failed to unmarshal StringArray value")
	}

	return json.Unmarshal(bytes, a)
}
