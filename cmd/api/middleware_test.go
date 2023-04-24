go test -coverprofile=coverage.out && go tool cover -html=coverage.outpackage main

import (
	"errors"
	"expvar"
	"greenlight.bcc/internal/assert"
	"greenlight.bcc/internal/data"
	"greenlight.bcc/internal/jsonlog"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestRecoverPanicMiddleware(t *testing.T) {
	app := newTestApplication(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("oops")
	})

	rr := httptest.NewRecorder()
	app.recoverPanic(handler).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	expectedError := `"the server encountered a problem and could not process your request"`
	assert.StringContains(t, rr.Body.String(), expectedError)
}

func TestMetrics(t *testing.T) {
	app := newTestApplication(t)
	timeout := 500 * time.Millisecond

	handler := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(timeout)
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name          string
		handler       http.Handler
		expectedCode  int
		expectedCount int
	}{
		{
			name:          "200 OK",
			handler:       http.HandlerFunc(handler),
			expectedCount: 1,
			expectedCode:  http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			res := httptest.NewRecorder()

			middleware := app.metrics(tc.handler)
			middleware.ServeHTTP(res, req)

			assert.Equal(t, tc.expectedCode, res.Code)

			statusStr := strconv.Itoa(tc.expectedCode)
			expvarVal := expvar.Get("total_responses_sent_by_status").(*expvar.Map).Get(statusStr)
			if expvarVal == nil {
				t.Fatal("expected expvar value to be not nil")
			}

			responseCount, _ := strconv.ParseInt(expvarVal.String(), 10, 64)
			assert.Equal(t, tc.expectedCount, int(responseCount))

			totalRequestsReceived := expvar.Get("total_requests_received").(*expvar.Int)
			if totalRequestsReceived == nil {
				t.Fatal("expected expvar value to be not nil")
			}
			assert.Equal(t, int64(1), totalRequestsReceived.Value())

			totalResponsesSent := expvar.Get("total_responses_sent").(*expvar.Int)
			if totalResponsesSent == nil {
				t.Fatal("expected expvar value to be not nil")
			}
			assert.Equal(t, int64(1), totalResponsesSent.Value())

			totalProcessingTimeMicroseconds := expvar.Get("total_processing_time_μs").(*expvar.Int)
			if totalProcessingTimeMicroseconds == nil {
				t.Fatal("expected expvar value to be not nil")
			}
			if totalProcessingTimeMicroseconds.Value() <= int64(500) {
				t.Fatalf("expected total processing time to be greater than %d, got %d", 500, totalProcessingTimeMicroseconds.Value())
			}
		})
	}
}

func TestEnableCORS(t *testing.T) {
	app := newTestApplication(t)

	app.config.cors.trustedOrigins = []string{"https://trusted.example.com"}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name          string
		requestOrigin string
		requestMethod string
		expectedCORS  bool
	}{
		{
			name:          "TrustedOrigin",
			requestOrigin: "https://trusted.example.com",
			requestMethod: http.MethodGet,
			expectedCORS:  true,
		},
		{
			name:          "UntrustedOrigin",
			requestOrigin: "https://untrusted.example.com",
			requestMethod: http.MethodGet,
			expectedCORS:  false,
		},
		{
			name:          "OptionsRequest",
			requestOrigin: "https://trusted.example.com",
			requestMethod: http.MethodOptions,
			expectedCORS:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.requestMethod, "/", nil)
			req.Header.Set("Origin", tc.requestOrigin)
			if tc.requestMethod == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "PUT")
			}

			res := httptest.NewRecorder()

			middleware := app.enableCORS(http.HandlerFunc(handler))
			middleware.ServeHTTP(res, req)

			if tc.expectedCORS {
				assert.Equal(t, res.Header().Get("Access-Control-Allow-Origin"), tc.requestOrigin)
				if tc.requestMethod == http.MethodOptions {
					assert.Equal(t, res.Header().Get("Access-Control-Allow-Methods"), "OPTIONS, PUT, PATCH, DELETE")
					assert.Equal(t, res.Header().Get("Access-Control-Allow-Headers"), "Authorization, Content-Type")
				}
			} else {
				assert.Empty(t, res.Header().Get("Access-Control-Allow-Origin"))
				assert.Empty(t, res.Header().Get("Access-Control-Allow-Methods"))
				assert.Empty(t, res.Header().Get("Access-Control-Allow-Headers"))
			}

			assert.StringContains(t, res.Header().Get("Vary"), "Origin")
		})
	}
}

type MockedPermissionsModel struct {
}

func (m *MockedPermissionsModel) GetAllForUser(userID int64) (data.Permissions, error) {
	switch userID {
	case 1:
		return data.Permissions{"example.permission"}, nil
	case 2:
		return data.Permissions{}, nil
	default:
		return nil, errors.New("error")
	}
}

func (m *MockedPermissionsModel) AddForUser(userID int64, codes ...string) error {
	return nil
}

func TestRequirePermission(t *testing.T) {
	app := newTestApplication(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name           string
		userID         int
		permissions    data.Permissions
		permissionsErr error
		expectedStatus int
	}{
		{
			name:           "UserWithPermission",
			userID:         1,
			permissions:    data.Permissions{"example.permission"},
			permissionsErr: nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "UserWithoutPermission",
			userID:         2,
			permissions:    data.Permissions{},
			permissionsErr: nil,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "ServerError",
			userID:         3,
			permissions:    data.Permissions{},
			permissionsErr: errors.New("permissions retrieval error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req = app.contextSetUser(req, &data.User{ID: int64(tc.userID), Activated: true})
			res := httptest.NewRecorder()
			app.models.Permissions = &MockedPermissionsModel{}

			middleware := app.requirePermission("example.permission", handler)
			middleware.ServeHTTP(res, req)

			assert.Equal(t, tc.expectedStatus, res.Code)
		})
	}
}

func TestRequireActivatedUser(t *testing.T) {
	app := newTestApplication(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name           string
		user           *data.User
		expectedStatus int
	}{
		{
			name:           "ActivatedUser",
			user:           &data.User{ID: 1, Activated: true},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "NonActivatedUser",
			user:           &data.User{ID: 2, Activated: false},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req = app.contextSetUser(req, tc.user)
			res := httptest.NewRecorder()

			middleware := app.requireActivatedUser(handler)
			middleware.ServeHTTP(res, req)

			if res.Code != tc.expectedStatus {
				t.Errorf("Expected status %d; got %d", tc.expectedStatus, res.Code)
			}
		})
	}
}
func TestRequireAuthenticatedUser(t *testing.T) {
	app := newTestApplication(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name           string
		user           *data.User
		expectedStatus int
	}{
		{
			name:           "AuthenticatedUser",
			user:           &data.User{ID: 1, Activated: true},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "AnonymousUser",
			user:           data.AnonymousUser,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req = app.contextSetUser(req, tc.user)
			res := httptest.NewRecorder()

			middleware := app.requireAuthenticatedUser(handler)
			middleware.ServeHTTP(res, req)

			if res.Code != tc.expectedStatus {
				t.Errorf("Expected status %d; got %d", tc.expectedStatus, res.Code)
			}
		})
	}
}

type MockedUsersModel struct {
}

func (m *MockedUsersModel) Insert(user *data.User) error {
	return nil
}

func (m *MockedUsersModel) GetByEmail(email string) (*data.User, error) {
	return nil, nil
}
func (m *MockedUsersModel) Update(user *data.User) error {
	return nil
}

func (m *MockedUsersModel) GetForToken(tokenScope string, tokenPlaintext string) (*data.User, error) {
	switch tokenPlaintext {
	case "ValidTokenqwerrewwerewqqwe":
		return &data.User{ID: 1, Activated: true}, nil
	case "qInvalidTokenwqerqwerqwerq":
		return nil, data.ErrRecordNotFound
	case "qweqweqweqweqweqweqweqw321":
		return nil, errors.New("error")
	default:
		return nil, data.ErrRecordNotFound
	}
}

func TestAuthenticate(t *testing.T) {
	app := newTestApplication(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	testCases := []struct {
		name            string
		authorization   string
		mockGetForToken func(string, string) (*data.User, error)
		expectedStatus  int
	}{
		{
			name:          "NoAuthorizationHeader",
			authorization: "",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return nil, data.ErrRecordNotFound
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:          "InvalidAuthorizationHeaderFormat",
			authorization: "Invalid Header",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return nil, data.ErrRecordNotFound
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:          "InvalidAuthorizationHeaderFormat",
			authorization: "Bearer TOKEN",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return nil, data.ErrRecordNotFound
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:          "InvalidAuthorizationHeaderFormat",
			authorization: "Bearer qweqweqweqweqweqweqweqw321",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return nil, data.ErrRecordNotFound
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:          "InvalidToken",
			authorization: "Bearer qInvalidTokenwqerqwerqwerq",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return nil, data.ErrRecordNotFound
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:          "ValidToken",
			authorization: "Bearer ValidTokenqwerrewwerewqqwe",
			mockGetForToken: func(scope, token string) (*data.User, error) {
				return &data.User{ID: 1, Activated: true}, nil
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app.models.Users = &MockedUsersModel{}

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tc.authorization)
			res := httptest.NewRecorder()

			middleware := app.authenticate(http.HandlerFunc(handler))
			middleware.ServeHTTP(res, req)

			if res.Code != tc.expectedStatus {
				t.Errorf("Expected status %d; got %d", tc.expectedStatus, res.Code)
			}
		})
	}
}

func newTestApplicationWithLimit(rps float64, burst int, enabled bool) *application {
	return &application{
		config: config{
			limiter: struct {
				rps     float64
				burst   int
				enabled bool
			}{rps: rps, burst: burst, enabled: enabled},
		},
	}
}

func TestRateLimit_Disabled(t *testing.T) {
	app := newTestApplicationWithLimit(1, 1, false)
	ts := httptest.NewServer(app.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got %q", string(body))
	}
}

func TestRateLimit_Enabled_Success(t *testing.T) {
	app := newTestApplicationWithLimit(10, 2, true)
	ts := httptest.NewServer(app.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got %q", string(body))
	}
}

func TestRateLimit_Enabled_Exceeded(t *testing.T) {
	app := newTestApplicationWithLimit(1, 1, true)
	ts := httptest.NewServer(app.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})))
	defer ts.Close()

	// First request should be successful
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Second request should be rate-limited
	resp, err = http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", resp.StatusCode)
	}
}

func TestRateLimit_Enabled_BadRemoteAddr(t *testing.T) {
	app := newTestApplicationWithLimit(1, 1, true)
	app.logger = jsonlog.New(os.Stdout, jsonlog.LevelInfo)
	ts := httptest.NewServer(app.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set an invalid RemoteAddr
	req.RemoteAddr = "bad-address"

	resp := httptest.NewRecorder()
	app.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.Code)
	}
}
