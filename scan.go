/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import (
	"go.arpabet.com/glue"
	"go.arpabet.com/servion"
)

type obfsServerScanner struct {
	beanName string
	scan     []interface{}
}

/*
ObfsServerScanner registers the stub obfs server named beanName (as a
servion.Server that binds and serves it) and forwards the extra beans — for
example an Obfuscator implementation. It is the obfs counterpart of
servion.HttpServerScanner / serviongrpc.GrpcServerScanner and is passed to
servion.RunCommand.

	servion.RunCommand(
		obfs.ObfsServerScanner("obfs-server"),
	)
*/
func ObfsServerScanner(beanName string, scan ...interface{}) glue.Scanner {
	return &obfsServerScanner{
		beanName: beanName,
		scan:     scan,
	}
}

func (t *obfsServerScanner) ScannerBeans() []interface{} {
	beans := []interface{}{
		ObfsServer(t.beanName),
		&struct {
			// make them visible / force construction
			Servers []servion.Server `inject:"optional"`
		}{},
	}
	return append(beans, t.scan...)
}
