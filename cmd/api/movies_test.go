package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestShowMovie(t *testing.T) {
	app := newTestApplication(t)

	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
		wantBody string
	}{
		{
			name:     "Valid ID",
			urlPath:  "/v1/movies/1",
			wantCode: http.StatusOK,
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/v1/movies/4",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Negative ID",
			urlPath:  "/v1/movies/-1",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Decimal ID",
			urlPath:  "/v1/movies/1.23",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "String ID",
			urlPath:  "/v1/movies/foo",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Unexpected error from Model",
			urlPath:  "/v1/movies/2",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			code, _, body := ts.get(t, tt.urlPath)

			assert.Equal(t, code, tt.wantCode)

			if tt.wantBody != "" {
				assert.StringContains(t, body, tt.wantBody)
			}

		})
	}

}

func TestCreateMovie(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	const (
		validTitle   = "Test Title"
		validYear    = 2021
		validRuntime = "105 mins"
	)

	validGenres := []string{"comedy", "drama"}

	tests := []struct {
		name     string
		Title    string
		Year     int32
		Runtime  string
		Genres   []string
		wantCode int
	}{
		{
			name:     "Valid submission",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusCreated,
		},
		{
			name:     "Empty Title",
			Title:    "",
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "year < 1888",
			Title:    validTitle,
			Year:     1500,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "test for wrong input",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "Unexpected error from Model",
			Title:    "error",
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Title   string   `json:"title"`
				Year    int32    `json:"year"`
				Runtime string   `json:"runtime"`
				Genres  []string `json:"genres"`
			}{
				Title:   tt.Title,
				Year:    tt.Year,
				Runtime: tt.Runtime,
				Genres:  tt.Genres,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}
			if tt.name == "test for wrong input" {
				b = append(b, 'a')
			}

			code, _, _ := ts.postForm(t, "/v1/movies", b)

			assert.Equal(t, code, tt.wantCode)

		})
	}
}

func TestDeleteMovie(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
		wantBody string
	}{
		{
			name:     "Deleting existing movie",
			urlPath:  "/v1/movies/1",
			wantCode: http.StatusOK,
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/v1/movies/4",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Unexpected error from Model",
			urlPath:  "/v1/movies/2",
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "Decimal ID",
			urlPath:  "/v1/movies/1.5",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			code, _, body := ts.deleteReq(t, tt.urlPath)

			assert.Equal(t, code, tt.wantCode)

			if tt.wantBody != "" {
				assert.StringContains(t, body, tt.wantBody)
			}

		})
	}

}

func TestUpdateMovie(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	const (
		validTitle   = "Test Title"
		validYear    = 2021
		validRuntime = "105 mins"

		nilString = "nil"
		nilInt    = -1337
	)

	validGenres := []string{"comedy", "drama"}

	tests := []struct {
		name     string
		urlPath  string
		Title    string
		Year     int32
		Runtime  string
		Genres   []string
		wantCode int
	}{
		{
			name:     "Valid submission",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusOK,
		},
		{
			name:     "Empty request body",
			urlPath:  "/v1/movies/1",
			Title:    nilString,
			Year:     nilInt,
			Runtime:  nilString,
			Genres:   []string{nilString},
			wantCode: http.StatusOK,
		},
		{
			name:     "year < 1888",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     1500,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/v1/movies/4",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Edit conflict",
			urlPath:  "/v1/movies/3",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusConflict,
		},
		{
			name:     "test for wrong input",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "Decimal ID",
			urlPath:  "/v1/movies/1.5",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Unexpected error after Get method from Model",
			urlPath:  "/v1/movies/2",
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "Unexpected error from Update method from Model",
			urlPath:  "/v1/movies/10",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Title   string   `json:"title,omitempty"`
				Year    int32    `json:"year,omitempty"`
				Runtime string   `json:"runtime,omitempty"`
				Genres  []string `json:"genres,omitempty"`
			}{}

			if tt.Title != nilString {
				inputData.Title = tt.Title
			}

			if tt.Year != nilInt {
				inputData.Year = tt.Year
			}

			if tt.Runtime != nilString {
				inputData.Runtime = tt.Runtime
			}

			if reflect.DeepEqual(tt.Genres, []string{nilString}) {
				inputData.Genres = tt.Genres
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}
			if tt.name == "test for wrong input" {
				b = append(b, 'a')
			}

			code, _, _ := ts.patchForm(t, tt.urlPath, b)

			assert.Equal(t, code, tt.wantCode)

		})
	}
}

func TestListMovies(t *testing.T) {
	app := newTestApplication(t)

	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
	}{
		{
			name:     "Valid parameters",
			urlPath:  "/v1/movies?title=Test&genres=comedy,drama&page=1&page_size=10&sort=title",
			wantCode: http.StatusOK,
		},
		{
			name:     "Decimal page",
			urlPath:  "/v1/movies?page=1.23",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Decimal page size",
			urlPath:  "/v1/movies?page_size=2.6",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Invalid sort option",
			urlPath:  "/v1/movies?sort=genres",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Without parameters",
			urlPath:  "/v1/movies",
			wantCode: http.StatusOK,
		},
		{
			name:     "Unexpected error from Model",
			urlPath:  "/v1/movies?title=error",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			code, _, _ := ts.get(t, tt.urlPath)

			assert.Equal(t, code, tt.wantCode)
		})
	}

}
