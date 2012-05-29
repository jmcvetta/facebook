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

// SignedRequest is a Facebook data transfer structure.  See 
// http://developers.facebook.com/docs/authentication/signed_request/ for crappy documentation.
type SignedRequest struct {
	Code        string // OAuth Code - can be exchanged for user access token via subsequent request
	Algorithm   string // mechanism used to sign the request
	Issued_At   int64  // Unix timestamp when the request was signed
	User_Id     string // User ID of the current user
	User        User
	Oauth_Token string // user access token - used when making requests to the Graph API
	Expires     int64  // Unix timestamp when the oauth_token expires
	App_Data    string // app_data query parameter - may be passed if app is loaded within Page Tab
	Page        Page
}

// User contains data about a Facebook user.
type User struct {
	Country string
	Locale  string
	Age     Age
}

// Age contains age data about a Facebook user.
type Age struct {
	Min int
	Max int
}

// Page contains data about the current Facebook page
type Page struct {
	Id    string
	Liked bool
	Admin bool
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

// Parses an HTTP request containing a Facebook-style signed_request parameter
//
// secret is the Facebook App Secret for the application receiving this request
func ParseSignedRequest(req *http.Request, secret string) (SignedRequest, error) {
	var err error
	var result SignedRequest
	encSignedRequest := req.FormValue("signed_request")
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
