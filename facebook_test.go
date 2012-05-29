package facebook

import (
	"github.com/bmizerany/assert"
	"net/http"
	"testing"
)

// Credentials used to generate the sample signed_request
const (
	appId     = "281740555255031"
	appSecret = "1ca84b341a334ab02260c32471f51937"
)

// Example signed_request
const (
	signedRequest = "MpUWdfoWdnCfj7SW0rs_b0jKAasq_XUjUtCy68woYo4.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImlzc3VlZF9hdCI6MTMzNzkwNTUzOCwidXNlciI6eyJjb3VudHJ5IjoidXMiLCJsb2NhbGUiOiJlbl9VUyIsImFnZSI6eyJtaW4iOjIxfX19"
	exAlgo        = "HMAC-SHA256"
	exIssuedAt    = int64(1337905538)
	exCountry     = "us"
	exLocale      = "en_US"
)

// Example age can't be a constant because it's a map
var exAge = map[string]int{
	"min": 21,
}

func TestParseSignedRequest(t *testing.T) {
	t.Log("Testing ParseSignedRequest()")
	req, err := http.NewRequest("GET", "http://foobar.com/", nil)
	req.ParseForm() // Initilizes Form map, required for direct access before
	req.Form.Add("signed_request", signedRequest)
	sr, err := ParseSignedRequest(req, appSecret)
	if err != nil {
		t.Fatal("ParseSignedRequest:", err)
	}
	assert.Equal(t, sr.Algorithm, exAlgo)
	assert.Equal(t, sr.Issued_At, exIssuedAt)
	assert.Equal(t, sr.User.Country, exCountry)
	assert.Equal(t, sr.User.Locale, exLocale)
	assert.Equal(t, sr.User.Age, exAge)
}
