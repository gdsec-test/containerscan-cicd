package main

import (
	"strings"
)

func between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.LastIndex(value, a)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.LastIndex(value, b)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

func before(value string, a string) string {
	// Get substring before a string.
	pos := strings.Index(value, a)
	if pos == -1 {
		return ""
	}
	return value[0:pos]
}

func after(value string, a string) string {
	// Get substring after a string.
	pos := strings.LastIndex(value, a)
	if pos == -1 {
		return ""
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return ""
	}
	return value[adjustedPos:len(value)]
}

// String creates pointer to string based on literal string.
func String(v string) *string { return &v }
