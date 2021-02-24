package main

import (
	"testing"
)

func Test_between(t *testing.T) {
	value := "aaabbbccc"
	a := "aaa"
	b := "ccc"
	between := between(value, a, b)
	if between != "bbb" {
		t.Error("between failed")
	}
}

func Test_before(t *testing.T) {
	value := "aaabbbccc"
	a := "bbb"
	before := before(value, a)
	if before != "aaa" {
		t.Error("before failed")
	}
}

func Test_after(t *testing.T) {
	value := "aaabbbccc"
	a := "bbb"
	after := after(value, a)
	if after != "ccc" {
		t.Error("after failed")
	}

}
