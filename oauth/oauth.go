package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/gvu0110/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic               = "X-Public"
	headerXClientID             = "X-Client-ID"
	headerXCallerID             = "X-Caller-ID"
	paramAccessToken            = "access_token"
	OauthAccessTokenAPIEndpoint = "https://localhost:8080/oauth/access_token"
)

var (
	restClient = resty.New()
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int    `json:"user_id"`
	ClientID int    `json:"client_id"`
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) rest_errors.RESTError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	return nil
}

func cleanRequest(request *http.Request) {
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, rest_errors.RESTError) {
	response, err := restClient.R().
		SetHeader("Content-Type", "application/json").
		Get(fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenID))

	// Timeout
	if err != nil {
		return nil, rest_errors.NewInternalServerRESTError("Invalid RESTClient response when trying to get access token", err)
	}

	if response.StatusCode() > 299 {
		restErr, err := rest_errors.NewRESTErrorFromBytes(response.Body())
		if err != nil {
			return nil, rest_errors.NewInternalServerRESTError("Invalid error interface then trying to get access token", err)
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, rest_errors.NewInternalServerRESTError("Error when trying to unmarshall access token response", err)
	}
	return &at, nil
}
