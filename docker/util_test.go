package main

import (
	"testing"
)

func Test_between(t *testing.T) {
	value := "aaabbbccc"
	a := "aaa"
	b := "ccc"
	result := between(value, a, b)
	if result != "bbb" {
		t.Error("between failed")
	}

	a = "aaa"
	b = "eeee"
	result = between(value, a, b)
	if result != "" {
		t.Error("between failed")
	}

	a = "ccc"
	b = "bbb"
	result = between(value, a, b)
	if result != "" {
		t.Error("between failed")
	}

	a = "eee"
	b = "bbb"
	result = between(value, a, b)
	if result != "" {
		t.Error("between failed")
	}

}

func Test_before(t *testing.T) {
	value := "aaabbbccc"
	a := "bbb"
	result := before(value, a)
	if result != "aaa" {
		t.Error("before failed")
	}

	a = "abc"
	result = before(value, a)
	if result != "" {
		t.Error("before failed")
	}
}

func Test_after(t *testing.T) {
	value := "aaabbbccc"
	a := "bbb"
	result := after(value, a)
	if result != "ccc" {
		t.Error("after failed")
	}

	a = "dddd"
	result = after(value, a)
	if result != "" {
		t.Error("after failed")
	}

	a = "ccc"
	result = after(value, a)
	if result != "" {
		t.Error("after failed")
	}

}

func TestString(t *testing.T) {
	s := "testString"

	if *String(s) != s {
		t.Error("Expected :", s, "but got :", *String(s))
	}
}

func TestCopyMap(t *testing.T) {
	original := map[string]interface{}{
		"onefield": "value1",
		"twofield": "value2",
		"nestedmap": map[string]string{
			"nestedprop": "nestedval",
		},
	}
	copy := CopyMap(original)

	if &copy == &original {
		t.Error("Expected copy to be separate object")
	}
	if copy["onefield"] != original["onefield"] {
		t.Error("Expected copy to have 'onefield' value same")
	}
	if copy["twofield"] != original["twofield"] {
		t.Error("Expected copy to have 'twofield' value same")
	}
	copyNestedmap := copy["nestedmap"]
	originalNestedmap := original["nestedmap"]
	if &copyNestedmap == &originalNestedmap {
		t.Error("Expected copy to be separate object")
	}
	if copy["nestedmap"].(map[string]string)["nestedprop"] != original["nestedmap"].(map[string]string)["nestedprop"] {
		t.Error("Expected copy to have 'nestedprop' value same")
	}
}
