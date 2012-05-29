// Copyright 2012 Jason McVetta.  This is Free Software, released under the 
// terms of the GNU Public License version 3.
//
// This code was inspired by Sunil Arora's Python implementation:
// http://sunilarora.org/parsing-signedrequest-parameter-in-python-bas

// Package facebook provides utilities for working with the Facebook API
package facebook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const defaultMaxMemory = int64(1024 * 1024) // Max memory to use parsing request

var SignedRequestParseError = errors.New("Could not parse Facebook signed_request")

// User contains data about a Facebook user.
type User struct {
	Country string
	Locale  string
	Age     map[string]int
}

// Page contains data about the current Facebook page
type Page struct {
	Id    string
	Liked bool
	Admin bool
}

// SignedRequest is a Facebook data transfer structure.  See 
// http://developers.facebook.com/docs/authentication/signed_request/ for crappy documentation.
type SignedRequest struct {
	Code        string // An OAuth Code which can be exchanged for a valid user access token via a subsequent server-side request
	Algorithm   string // mechanism used to sign the request, normally: HMAC-SHA256.
	Issued_At   int64  // Unix timestamp when the request was signed.
	User_Id     string // User ID of the current user.
	User        User
	Oauth_Token string // used when making requests to the Graph API. This is also known as a user access token.
	Expires     int64  // Unix timestamp when the oauth_token expires.
	App_Data    string // content of the app_data query string parameter which may be passed if the app is being loaded within a Page Tab.
	Page        Page
}

func pad(s string) string {
	padding := (4 - len(s)%4) % 4
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
		log.Println("Request Parse Error:", err)
		return result, err
	}
	encSignedRequest := req.Form.Get("signed_request")
	l := strings.Split(encSignedRequest, ".")
	if len(l) != 2 {
		msg := fmt.Sprint("Could not split signed request into two parts.  It contains", len(l), "parts.")
		log.Println(msg)
		return result, errors.New(msg)
	}
	encSig := l[0]
	encPayload := l[1]
	//
	// Decode signature
	//
	b, err := base64UrlDecode(encSig)
	if err != nil {
		return result, err
	}
	sig := string(b)
	//
	// Decode payload
	//
	b, err = base64UrlDecode(encPayload)
	if err != nil {
		log.Println("Base64 Decode Error:", err)
		return result, err
	}
	err = json.Unmarshal(b, &result)
	if err != nil {
		log.Println("Unmarshal Error:", err)
		return result, err
	}
	//
	// Verify Signature
	//
	if strings.ToUpper(result.Algorithm) != "HMAC-SHA256" {
		msg := fmt.Sprint("Unknown algorithm:", result.Algorithm)
		log.Println(msg)
		return result, errors.New(msg)
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(encPayload))
	expectedSig := string(h.Sum([]byte{}))
	if expectedSig != sig {
		msg := fmt.Sprintf("Bad signature: expected '%v' but got '%v'.", expectedSig, sig)
		log.Println(msg)
		return result, errors.New(msg)
	}
	//
	// Signature verified, return valid result
	//
	log.Println("SignedRequest:", result)
	return result, err
}
