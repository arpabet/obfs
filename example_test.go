/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"fmt"
	"io"
	"net"
	"time"

	"go.arpabet.com/obfs"
)

// ExampleWrap shapes a connection into fixed-size cells. Both peers must Wrap with the
// same CellSize; the framing is transparent to the protocol running over it.
func ExampleWrap() {
	c1, c2 := net.Pipe()
	client := obfs.Wrap(c1, obfs.Policy{CellSize: 512})
	server := obfs.Wrap(c2, obfs.Policy{CellSize: 512})
	defer client.Close()
	defer server.Close()

	go func() { client.Write([]byte("every wire frame is 512 bytes")) }()

	buf := make([]byte, len("every wire frame is 512 bytes"))
	io.ReadFull(server, buf)
	fmt.Println(string(buf))
	// Output: every wire frame is 512 bytes
}

// ExampleWrap_morpher draws cell sizes from a distribution instead of a fixed size, so
// the on-wire size profile can resemble a cover protocol. Both peers must set a
// SizeSampler. FRONT padding and RegulaTor-style pacing are additional Policy options.
func ExampleWrap_morpher() {
	policy := obfs.Policy{
		SizeSampler:  obfs.SampledSize(map[int]float64{1300: 6, 600: 2, 120: 1}),
		DelaySampler: obfs.PoissonDelay(2 * time.Millisecond),
		// Front: &obfs.FrontConfig{Window: time.Second, MaxCount: 20}, // adaptive padding
		// Paced: &obfs.PacedConfig{Rate: 1000, Decay: 0.94},           // burst smoothing
	}
	c1, c2 := net.Pipe()
	client := obfs.Wrap(c1, policy)
	server := obfs.Wrap(c2, policy)
	defer client.Close()
	defer server.Close()

	go func() { client.Write([]byte("morphed payload")) }()
	buf := make([]byte, len("morphed payload"))
	io.ReadFull(server, buf)
	fmt.Println(string(buf))
	// Output: morphed payload
}

// ExampleWrapPacket obfuscates each UDP datagram (Salamander-style: per-packet salt +
// AES-256-GCM under a PSK), so a passive observer sees only pseudo-random packets. Pair
// it with a QUIC transport by wrapping the UDP socket. Both peers use the same Key.
func ExampleWrapPacket() {
	key := []byte("a-shared-pre-shared-key-32-bytes")
	a, _ := net.ListenPacket("udp", "127.0.0.1:0")
	b, _ := net.ListenPacket("udp", "127.0.0.1:0")
	pa := obfs.WrapPacket(a, obfs.PacketPolicy{Key: key, Pad: obfs.UniformSize(1200, 1400)})
	pb := obfs.WrapPacket(b, obfs.PacketPolicy{Key: key})
	defer pa.Close()
	defer pb.Close()

	pa.WriteTo([]byte("hidden datagram"), pb.LocalAddr())
	buf := make([]byte, 1500)
	pb.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, _ := pb.ReadFrom(buf)
	fmt.Println(string(buf[:n]))
	// Output: hidden datagram
}
