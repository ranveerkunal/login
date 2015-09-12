package login

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"

	"bitbucket.org/doggrott/amigosreal/utils"

	"github.com/martini-contrib/sessions"
	"github.com/ranveerkunal/fb"
	"github.com/ranveerkunal/weblogger"
)

type LoginRequest struct {
	User          json.RawMessage `json:"user"`
	SignedRequest string          `json:"sr"`
}

type LoginUserDB interface {
	Parse(json.RawMessage) (interface{}, error)
	Login(interface{})
}

func Login(s sessions.Session, wlog *weblogger.Logger, ldb LoginUserDB, r *http.Request) (int, string) {
	decoder := json.NewDecoder(r.Body)
	lr := &LoginRequest{}
	err := decoder.Decode(lr)
	if err != nil {
		panic(err)
	}

	// Decode the data.
	sigpay := strings.Split(string(lr.SignedRequest), ".")
	sig, err := utils.Base64URLDecodeString(sigpay[0])
	if err != nil {
		return http.StatusBadRequest, "Bad Signature: " + err.Error()
	}

	pay, err := utils.Base64URLDecodeString(sigpay[1])
	if err != nil {
		return http.StatusBadRequest, "Bad Payload: " + err.Error()
	}

	val := &fb.SignedRequest{}
	err = json.Unmarshal(pay, val)
	if err != nil {
		return http.StatusBadRequest, "Bad JSON: " + err.Error()
	}

	mac := hmac.New(sha256.New, []byte(*fb.ClientSecret))
	mac.Write([]byte(sigpay[1]))
	if !bytes.Equal(mac.Sum(nil), sig) {
		return http.StatusBadRequest, "Bad Signed Request"
	}

	// Parse user from request.
	s.Set("user_id", val.UserId) // Set cookie.
	u, err := ldb.Parse(lr.User)
	if err != nil {
		return http.StatusBadRequest, "Parse User failed: " + err.Error()
	}
	wlog.Remotef("User logged IN: %+v", u)
	ldb.Login(u)
	return http.StatusOK, ""
}
