package main

import "testing"

func TestGreeting(t *testing.T) {
	if Greeting() != "hello" {
		t.Fatalf("unexpected greeting")
	}
}
