/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package obfs is a STUB censorship-resistant obfuscation transport for servion.
//
// It does no real obfuscation yet — it exists to lock down the integration
// surface that servion expects, so a servion application can already wire it in
// (via ObfsServerScanner) and so the real shaping/mimicry logic can be filled in
// later without changing the public API.
//
// The shape mirrors servion's other transport modules (grpc, vrpc): a server is
// exposed as a servion.Server so the standard servion runtime binds, serves and
// shuts it down, and the pluggable obfuscation layer is expressed as an
// Obfuscator bean. The bundled Nop() Obfuscator is a pass-through.
package obfs

import (
	"net"
	"reflect"
)

// ObfuscatorClass is the reflect.Type of the Obfuscator interface.
var ObfuscatorClass = reflect.TypeOf((*Obfuscator)(nil)).Elem()

/*
Obfuscator wraps a network connection with a censorship-resistant obfuscation
layer (length/timing/entropy shaping, protocol mimicry, ...). It is symmetric:
the same interface wraps both accepted server connections and dialed client
connections.

This is the seam where real obfuscation will live. The stub Nop() implementation
returns the connection unchanged.
*/
type Obfuscator interface {

	// Obfuscate wraps conn with the obfuscation layer and returns the wrapped
	// connection. The stub returns conn unchanged.
	Obfuscate(conn net.Conn) (net.Conn, error)

	// Name returns the obfuscation scheme name ("nop" for the stub).
	Name() string
}
