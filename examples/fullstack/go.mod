module go.arpabet.com/obfs/examples/fullstack

go 1.25.0

require (
	go.arpabet.com/obfs v0.1.0
	go.arpabet.com/obfs/tlscamo v0.1.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

// Examples are their own module so the uTLS dependency (via tlscamo) never enters the
// zero-dependency obfs core. The unreleased features used here (morpher/FRONT) are
// resolved from the working tree; on release, drop these replaces and pin tagged versions.
replace go.arpabet.com/obfs => ../..

replace go.arpabet.com/obfs/tlscamo => ../../tlscamo
