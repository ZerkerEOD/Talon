package auth

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TestASReqHasNoPreauth is the load-bearing safety guarantee: the safe-enum
// AS-REQ must carry NO pre-authentication data (no PA-ENC-TIMESTAMP), so it can
// never submit a password or increment the target's badPwdCount. A regression
// that routed safe enum through a pre-auth exchange would fail here.
func TestASReqHasNoPreauth(t *testing.T) {
	cfg, err := config.NewFromString(minimalKrb5Conf("TEST.LOCAL", "127.0.0.1"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"victim"}}
	asReq, err := messages.NewASReqForTGT("TEST.LOCAL", cfg, cname)
	if err != nil {
		t.Fatalf("NewASReqForTGT: %v", err)
	}
	if len(asReq.PAData) != 0 {
		t.Fatalf("safe AS-REQ carries %d PAData entries, want 0", len(asReq.PAData))
	}
	for _, pa := range asReq.PAData {
		if pa.PADataType == patype.PA_ENC_TIMESTAMP {
			t.Fatalf("safe AS-REQ contains PA_ENC_TIMESTAMP — it would burn a password attempt")
		}
	}
}

// TestExchangeKDCFraming verifies the 4-byte big-endian length framing round-trip.
func TestExchangeKDCFraming(t *testing.T) {
	payload := []byte("canned-kdc-reply-bytes")
	addr := startFramingStub(t, payload, false)

	got, err := exchangeKDC(addr, []byte("my-as-req"))
	if err != nil {
		t.Fatalf("exchangeKDC: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

// TestExchangeKDCRejectsOversized ensures an attacker-controlled length header
// cannot drive a huge allocation.
func TestExchangeKDCRejectsOversized(t *testing.T) {
	addr := startFramingStub(t, nil, true) // advertises a > 1 MiB length
	if _, err := exchangeKDC(addr, []byte("my-as-req")); err == nil {
		t.Fatal("expected error for oversized response length, got nil")
	}
}

// startFramingStub listens on a loopback port, reads one length-prefixed request,
// and replies either with a correctly framed payload or (oversized=true) a bogus
// huge length header followed by no body.
func startFramingStub(t *testing.T, reply []byte, oversized bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		reqLen := binary.BigEndian.Uint32(hdr)
		_, _ = io.CopyN(io.Discard, conn, int64(reqLen))

		out := make([]byte, 4)
		if oversized {
			binary.BigEndian.PutUint32(out, maxKDCResponse+1)
			_, _ = conn.Write(out)
			return
		}
		binary.BigEndian.PutUint32(out, uint32(len(reply)))
		_, _ = conn.Write(append(out, reply...))
	}()

	return ln.Addr().String()
}
