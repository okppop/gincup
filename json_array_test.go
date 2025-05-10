package gincup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONArray(t *testing.T) {
	t.Run("Value method", func(t *testing.T) {
		t.Run("empty array", func(t *testing.T) {
			arr := JSONArray{}
			value, err := arr.Value()
			assert.NoError(t, err)
			assert.Equal(t, "[]", value)
		})

		t.Run("non-empty array", func(t *testing.T) {
			arr := JSONArray{"test1", "test2", "test3"}
			value, err := arr.Value()
			assert.NoError(t, err)
			assert.Equal(t, []byte(`["test1","test2","test3"]`), value)
		})
	})

	t.Run("Scan method", func(t *testing.T) {
		t.Run("nil value", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan(nil)
			assert.NoError(t, err)
			assert.Empty(t, arr)
		})

		t.Run("empty array string", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan("[]")
			assert.NoError(t, err)
			assert.Empty(t, arr)
		})

		t.Run("valid array string", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan(`["test1","test2","test3"]`)
			assert.NoError(t, err)
			assert.Equal(t, JSONArray{"test1", "test2", "test3"}, arr)
		})

		t.Run("valid array bytes", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan([]byte(`["test1","test2","test3"]`))
			assert.NoError(t, err)
			assert.Equal(t, JSONArray{"test1", "test2", "test3"}, arr)
		})

		t.Run("invalid json", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan(`["test1","test2","test3`) // Missing closing bracket
			assert.Error(t, err)
		})

		t.Run("invalid type", func(t *testing.T) {
			var arr JSONArray
			err := arr.Scan(123) // Invalid type
			assert.Error(t, err)
			assert.Equal(t, "failed to unmarshal StringArray value", err.Error())
		})
	})

	t.Run("database integration", func(t *testing.T) {
		// Test the full cycle of Value() and Scan()
		original := JSONArray{"test1", "test2", "test3"}

		// Convert to database value
		value, err := original.Value()
		assert.NoError(t, err)

		// Convert back from database value
		var scanned JSONArray
		err = scanned.Scan(value)
		assert.NoError(t, err)

		// Compare original and scanned values
		assert.Equal(t, original, scanned)
	})
}
