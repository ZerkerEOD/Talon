package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// maxKDCResponse caps the KDC reply size we will allocate, so a malicious or
// malformed KDC cannot drive memory exhaustion via the 4-byte length prefix.
const maxKDCResponse = 1 << 20 // 1 MiB

// loginEnumSafe performs pre-auth-less user enumeration. It builds an AS-REQ
// with NO PA-ENC-TIMESTAMP (no password material of any kind), sends it, and
// classifies the KDC's FIRST reply. It never constructs a gokrb5 client and
// never follows the pre-auth retry, so it cannot increment badPwdCount or lock
// an account. (The no-pre-auth invariant is asserted by TestASReqHasNoPreauth.)
func (k KERB) loginEnumSafe() AttemptResult {
	realm := strings.ToUpper(k.Domain)
	cfg, err := config.NewFromString(minimalKrb5Conf(k.Domain, k.Host))
	if err != nil {
		return k.result(OutcomeError, false, err)
	}
	cfg.LibDefaults.NoAddresses = true

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{k.User}}
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return k.result(OutcomeError, false, err)
	}
	b, err := asReq.Marshal()
	if err != nil {
		return k.result(OutcomeError, false, err)
	}

	resp, err := sendASReqRaw(k.Host, b)
	if err != nil {
		return k.result(OutcomeNetworkError, false, err)
	}

	// A KRBError reply reveals existence via its code; an AS-REP means the user
	// exists and does not require pre-auth.
	var krbErr messages.KRBError
	if krbErr.Unmarshal(resp) == nil {
		return k.result(ClassifyKerbCode(krbErr.ErrorCode, false), false, nil)
	}
	var asRep messages.ASRep
	if asRep.Unmarshal(resp) == nil {
		return k.result(ClassifyKerbCode(0, true), false, nil)
	}
	return k.result(OutcomeError, false, errors.New("unparseable KDC reply"))
}

// sendASReqRaw sends a single AS-REQ to host:88 over TCP and returns the raw
// reply body.
func sendASReqRaw(host string, req []byte) ([]byte, error) {
	return exchangeKDC(net.JoinHostPort(host, "88"), req)
}

// exchangeKDC performs the TCP request/response at addr using RFC 4120 §7.2.2
// framing (4-byte big-endian length prefix). It mirrors gokrb5's own TCP framing
// but is self-contained because gokrb5's sendToKDC is unexported, and it caps the
// reply length to prevent a malicious KDC from driving memory exhaustion.
func exchangeKDC(addr string, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(req)))
	if _, err := conn.Write(append(hdr, req...)); err != nil {
		return nil, err
	}

	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(sizeBuf)
	if n == 0 || n > maxKDCResponse {
		return nil, fmt.Errorf("KDC response length %d out of bounds", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}
