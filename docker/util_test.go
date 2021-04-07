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
