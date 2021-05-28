package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-ID", headerXClientID)
	assert.EqualValues(t, "X-Caller-ID", headerXCallerID)
	assert.EqualValues(t, "access_token", paramAccessToken)
	assert.EqualValues(t, "https://localhost:8080/oauth/access_token", OauthAccessTokenAPIEndpoint)
}

func TestIsPublicNilRequest(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))
	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerIDNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetCallerID(nil))
}

func TestGetCallerIDInvalidFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-ID", "123abc")
	assert.EqualValues(t, 0, GetCallerID(&request))
}

func TestGetCallerIDNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-ID", "123456")
	assert.EqualValues(t, 123456, GetCallerID(&request))
}

func TestGetClientIDNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetClientID(nil))
}

func TestGetClientIDInvalidFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Client-ID", "123abc")
	assert.EqualValues(t, 0, GetClientID(&request))
}

func TestGetClientIDNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Client-ID", "123456")
	assert.EqualValues(t, 123456, GetClientID(&request))
}

func TestAuthenticateRequestNilRequest(t *testing.T) {
	assert.Nil(t, AuthenticateRequest(nil))
}

func TestAuthenticateRequestEmptyAccessTokenID(t *testing.T) {
	request, _ := http.NewRequest("GET", "locahost", nil)
	q := request.URL.Query()
	q.Add(paramAccessToken, "")
	request.URL.RawQuery = q.Encode()

	err := AuthenticateRequest(request)
	assert.Nil(t, err)
}

func TestAuthenticateRequestGetAccessTokenError(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"id": "123", "user_id": "123abc", "client_id": 123}`
	responder := httpmock.NewStringResponder(http.StatusOK, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	request, _ := http.NewRequest("GET", mockURL, nil)
	q := request.URL.Query()
	q.Add(paramAccessToken, "abc123")
	request.URL.RawQuery = q.Encode()

	err := AuthenticateRequest(request)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.StatusCode())
	assert.EqualValues(t, "Error when trying to unmarshall access token response", err.Message())
	assert.EqualValues(t, "internal_server_error", err.Error())
	assert.NotNil(t, err.Causes())
	assert.EqualValues(t, 1, len(err.Causes()))
	assert.EqualValues(t, "json: cannot unmarshal string into Go struct field accessToken.user_id of type int", err.Causes()[0])
}

func TestAuthenticateRequestNoError(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"id": "123", "user_id": 123, "client_id": 123}`
	responder := httpmock.NewStringResponder(http.StatusOK, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	request, _ := http.NewRequest("GET", mockURL, nil)
	q := request.URL.Query()
	q.Add(paramAccessToken, "abc123")
	request.URL.RawQuery = q.Encode()

	err := AuthenticateRequest(request)
	assert.Nil(t, err)
}

func TestGetAccessTokenTimeoutFromAPI(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	mockURL := OauthAccessTokenAPIEndpoint
	httpmock.RegisterResponder("POST", mockURL, nil)
	at, err := getAccessToken("abc123")
	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.StatusCode())
	assert.EqualValues(t, "Invalid RESTClient response when trying to get access token", err.Message())
	assert.EqualValues(t, "internal_server_error", err.Error())
	assert.NotNil(t, err.Causes())
	assert.EqualValues(t, 1, len(err.Causes()))
	assert.EqualValues(t, "Post \"https://localhost:8080/oauth/access_token/abc123\": no responder found", err.Causes()[0])
}

func TestGetAccessTokenInvalidErrorInterface(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"status_code":"404","message":"Invalid access token","error":"not_found"}`
	responder := httpmock.NewStringResponder(http.StatusNotFound, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	at, err := getAccessToken("abc123")
	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.StatusCode())
	assert.EqualValues(t, "Invalid error interface then trying to get access token", err.Message())
	assert.EqualValues(t, "internal_server_error", err.Error())
	assert.NotNil(t, err.Causes())
	assert.EqualValues(t, 1, len(err.Causes()))
	assert.EqualValues(t, "invalid JSON bytes", err.Causes()[0])
}

func TestGetAccessTokenValidRESTErrorJSONResponse(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"status_code":404,"message":"No access token found","error":"not_found"}`
	responder := httpmock.NewStringResponder(http.StatusNotFound, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	at, err := getAccessToken("abc123")
	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusNotFound, err.StatusCode())
	assert.EqualValues(t, "No access token found", err.Message())
	assert.EqualValues(t, "not_found", err.Error())
	assert.Nil(t, err.Causes())
}

func TestGetAccessTokenInvalidJSONResponse(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"id": "123", "user_id": "123abc", "client_id": 123}`
	responder := httpmock.NewStringResponder(http.StatusOK, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	at, err := getAccessToken("abc123")
	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.StatusCode())
	assert.EqualValues(t, "Error when trying to unmarshall access token response", err.Message())
	assert.EqualValues(t, "internal_server_error", err.Error())
	assert.NotNil(t, err.Causes())
	assert.EqualValues(t, 1, len(err.Causes()))
	assert.EqualValues(t, "json: cannot unmarshal string into Go struct field accessToken.user_id of type int", err.Causes()[0])
}

func TestGetAccessTokenNoError(t *testing.T) {
	httpmock.ActivateNonDefault(restClient.GetClient())
	defer httpmock.DeactivateAndReset()
	responseBody := `{"id": "123", "user_id": 123, "client_id": 123}`
	responder := httpmock.NewStringResponder(http.StatusOK, responseBody)
	mockURL := fmt.Sprintf("%s/%s", OauthAccessTokenAPIEndpoint, "abc123")
	httpmock.RegisterResponder("POST", mockURL, responder)

	at, err := getAccessToken("abc123")
	assert.Nil(t, err)
	assert.NotNil(t, at)
	assert.EqualValues(t, "123", at.ID)
	assert.EqualValues(t, 123, at.UserID)
	assert.EqualValues(t, 123, at.ClientID)
}
