// Copyright 2012 Jason McVetta.  This is Free Software, released under the 
// terms of the GNU Public License version 3.
//
// This code was inspired by Sunil Arora's Python implementation:
// http://sunilarora.org/parsing-signedrequest-parameter-in-python-bas


// Package facebook provides utilities for working with the Facebook API
package facebook

import (
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const defaultMaxMemory = int64(1024 * 1024) // Max memory to use parsing request

var SignedRequestParseError = errors.New("Could not parse Facebook signed_request")

// SignedRequest is a Facebook data transfer structure.  See 
// http://developers.facebook.com/docs/authentication/signed_request/ for crappy documentation.
type SignedRequest struct {
	Code       string      // An OAuth Code which can be exchanged for a valid user access token via a subsequent server-side request
	Algorithm  string      // A JSON string containing the mechanism used to sign the request, normally: HMAC-SHA256.
	IssuedAt   string      // A JSON number containing the Unix timestamp when the request was signed.
	UserId     string      // A JSON string containing the User ID of the current user.
	User       interface{} // A JSON object containing the locale string, country string and the age object (containing the min and max number range of the age) for the current user.
	OauthToken string      // A JSON string that can be used when making requests to the Graph API. This is also known as a user access token.
	Expires    string      // A JSON number containing the Unix timestamp when the oauth_token expires.
	AppData    string      // A JSON string containing the content of the app_data query string parameter which may be passed if the app is being loaded within a Page Tab.
	Page       interface{} // A JSON object containing the page id string, the liked boolean (set to true if the user has liked the page, false if not) and the admin boolean (set to true if the user is an admin of the page, false if they're not). This field is only present if your app is being loaded within a Page Tab.
}


func pad(s string) string {
	padding := (4 - len(s) % 4) % 4
	return s + strings.Repeat("=", padding)
}

func base64UrlDecode(s string) ([]byte, error) {
	s = pad(s)
	b, err := base64.URLEncoding.DecodeString(s)
	return b, err
}


func ParseSignedRequest(req *http.Request, secret string) (SignedRequest, error) {
	var err error
	var result SignedRequest
	err = req.ParseMultipartForm(defaultMaxMemory)
	if err != nil {
		return result, err
	}
	encSignedRequest := req.Form.Get("signed_request")
	log.Println("encSignedRequest:", encSignedRequest)
	l := strings.Split(encSignedRequest, ".")
	if len(l) != 2 {
		msg := fmt.Sprint("Could not split signed request into two parts.  It contains", len(l), "parts.")
		err = errors.New(msg)
		return result, err
	}
	encSig := l[0]
	encPayload := l[1]
	log.Println("encSig:", encSig)
	//
	// Decode signature
	//
	b, err := base64UrlDecode(encSig)
	if err != nil {
		return result, err
	}
	sig := string(b)
	log.Println("encPayload:", encPayload)
	//
	// Decode payload
	//
	b, err = base64UrlDecode(encPayload)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(b, &result)
	if err != nil {
		return result, err
	}
	//
	// Verify Signature
	//
	if strings.ToUpper(result.Algorithm) != "HMAC-SHA256" {
		msg := fmt.Sprint("Unknown algorithm:", result.Algorithm)
		err = errors.New(msg)
		return result, err
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(encPayload))
	expectedSig := string(h.Sum([]byte{}))
	if expectedSig != sig {
		msg := fmt.Sprintf("Bad signature: expected '%v' but got '%v'.", expectedSig, encSig)
		err = errors.New(msg)
		return result, err
	}
	//
	// Signature verified, return valid result
	//
	return result, err
}
