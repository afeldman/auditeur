// Package main is a small program used as an audit fixture.
package main

import "fmt"

// Greeting returns a fixed greeting.
func Greeting() string {
	return "hello"
}

func main() {
	fmt.Println(Greeting())
}
