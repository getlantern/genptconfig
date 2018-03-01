// genptconfig creates new pluggable transport server configurations. Just
// specify the pluggable transport name (e.g. obfs4) on the command line and it
// will return a json structure with randomized server settings.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please specify a pluggable transport (i.e. obfs4)")
	}

	pt := os.Args[1]
	var result map[string]interface{}
	var err error
	switch pt {
	case "obfs4":
		result, err = obfs4()
	default:
		log.Fatalf("Unknown pluggable transport: %v\n", pt)
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
	bytes, err := json.Marshal(result)
	if err != nil {
		log.Fatalf("Error marshalling result to JSON: %v", err)
	}

	os.Stdout.Write(bytes)
}

func obfs4() (result map[string]interface{}, err error) {
	// Generate everything a server needs, using the cryptographic PRNG.
	rawID := make([]byte, ntor.NodeIDLength)
	err = csrand.Bytes(rawID)
	if err != nil {
		return
	}
	nodeID, err := ntor.NewNodeID(rawID)
	if err != nil {
		return
	}
	identityKey, err := ntor.NewKeypair(false)
	if err != nil {
		return
	}
	drbgSeed, err := drbg.NewSeed()
	if err != nil {
		return
	}
	certRaw := append(nodeID.Bytes()[:], identityKey.Public().Bytes()[:]...)
	cert := strings.TrimSuffix(base64.StdEncoding.EncodeToString(certRaw), "==")

	result = map[string]interface{}{
		"node_id":     nodeID.Hex(),
		"private_key": identityKey.Private().Hex(),
		"public_key":  identityKey.Public().Hex(),
		"cert":        cert,
		"drbg_seed":   drbgSeed.Hex(),
		"iat_mode":    0,
	}

	return
}
