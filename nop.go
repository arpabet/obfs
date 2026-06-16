/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import "net"

// nopObfuscator is a pass-through Obfuscator that performs no obfuscation.
type nopObfuscator struct{}

// Nop returns a pass-through Obfuscator. It is the default used by the stub
// server when no Obfuscator bean is provided.
func Nop() Obfuscator { return nopObfuscator{} }

func (nopObfuscator) Obfuscate(conn net.Conn) (net.Conn, error) { return conn, nil }

func (nopObfuscator) Name() string { return "nop" }
