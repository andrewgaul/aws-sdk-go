package v2

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
)

const (
	expiresDuration = 1000
)

type signer struct {
	// Values that must be populated from the request
	Request     *http.Request
	Time        time.Time
	Credentials *credentials.Credentials
	Debug       aws.LogLevelType
	Logger      aws.Logger

	Query            url.Values
	stringToSign     string
	signature        string
	S3ForcePathStyle bool
}

// Sign requests with signature version 2.
//
// Will sign the requests with the service config's Credentials object
// Signing is skipped if the credentials is the credentials.AnonymousCredentials
// object.
func Sign(req *request.Request) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Service.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	v2 := signer{
		Request:          req.HTTPRequest,
		Time:             req.Time,
		Credentials:      req.Service.Config.Credentials,
		Debug:            req.Service.Config.LogLevel.Value(),
		Logger:           req.Service.Config.Logger,
		S3ForcePathStyle: aws.BoolValue(req.Service.Config.S3ForcePathStyle),
	}

	req.Error = v2.Sign()

	if req.Error != nil {
		return
	}

	if req.HTTPRequest.Method == "POST" {
		// Set the body of the request based on the modified query parameters
		req.SetStringBody(v2.Query.Encode())

		// Now that the body has changed, remove any Content-Length header,
		// because it will be incorrect
		req.HTTPRequest.ContentLength = 0
		req.HTTPRequest.Header.Del("Content-Length")
	} else {
		req.HTTPRequest.URL.RawQuery = v2.Query.Encode()
	}
}

func (v2 *signer) Sign() error {
	credValue, err := v2.Credentials.Get()
	if err != nil {
		return err
	}

	if v2.Request.Method == "POST" {
		// Parse the HTTP request to obtain the query parameters that will
		// be used to build the string to sign. Note that because the HTTP
		// request will need to be modified, the PostForm and Form properties
		// are reset to nil after parsing.
		v2.Request.ParseForm()
		v2.Query = v2.Request.PostForm
		v2.Request.PostForm = nil
		v2.Request.Form = nil
	} else {
		v2.Query = v2.Request.URL.Query()
	}

	expires := fmt.Sprintf("%d", v2.Time.Unix()+expiresDuration)

	// Set new query parameters
	v2.Query.Set("AWSAccessKeyId", credValue.AccessKeyID)
	v2.Query.Set("Expires", expires)
	if credValue.SessionToken != "" {
		v2.Query.Set("SecurityToken", credValue.SessionToken)
	}

	// in case this is a retry, ensure no signature present
	v2.Query.Del("Signature")

	method := v2.Request.Method
	host := strings.SplitN(v2.Request.URL.Host, ".", 2)[0]
	path := v2.Request.URL.Path
	if path == "" {
		path = "/" + strings.Join(strings.Split(v2.Request.URL.Opaque, "/")[3:], "/")
	}
	if !v2.S3ForcePathStyle {
		path = "/" + host + path
	}

	// obtain all of the query keys and sort them
	queryKeys := make([]string, 0, len(v2.Query))
	for key := range v2.Query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)

	// build the canonical string for the V2 signature
	tmp := []string{
		method,
		"", // TODO: Content-MD5
		"", // TODO: Content-Type
		expires,
	}
	for _, key := range queryKeys {
		if !strings.HasPrefix(key, "x-amz-") {
			continue
		}
		k := strings.Replace(url.QueryEscape(key), "+", "%20", -1)
		v := strings.Replace(url.QueryEscape(v2.Query.Get(key)), "+", "%20", -1)
		tmp = append(tmp, k+": "+v)
	}
	tmp = append(tmp, path)
	v2.stringToSign = strings.Join(tmp, "\n")

	hash := hmac.New(sha1.New, []byte(credValue.SecretAccessKey))
	hash.Write([]byte(v2.stringToSign))
	v2.signature = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	v2.Query.Set("Signature", v2.signature)

	if v2.Debug.Matches(aws.LogDebugWithSigning) {
		v2.logSigningInfo()
	}

	return nil
}

const logSignInfoMsg = `DEBUG: Request Signature:
---[ STRING TO SIGN ]--------------------------------
%s
---[ SIGNATURE ]-------------------------------------
%s
-----------------------------------------------------`

func (v2 *signer) logSigningInfo() {
	msg := fmt.Sprintf(logSignInfoMsg, v2.stringToSign, v2.Query.Get("Signature"))
	v2.Logger.Log(msg)
}
