package data

import (
	"reflect"
	"time"
)
import "database/sql"
import "greenlight.bcc/internal/validator"
import "github.com/lib/pq"
import "errors"
import "context"
import "fmt"

type Movie struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"-"`
	Title     string    `json:"title"`
	Year      int32     `json:"year,omitempty"`
	Runtime   Runtime   `json:"runtime,omitempty"`
	Genres    []string  `json:"genres,omitempty"`
	Version   int32     `json:"version"`
}

func ValidateMovie(v *validator.Validator, movie *Movie) {
	v.Check(movie.Title != "", "title", "must be provided")
	v.Check(len(movie.Title) <= 500, "title", "must not be more than 500 bytes long")
	v.Check(movie.Year != 0, "year", "must be provided")
	v.Check(movie.Year >= 1888, "year", "must be greater than 1888")
	v.Check(movie.Year <= int32(time.Now().Year()), "year", "must not be in the future")
	v.Check(movie.Runtime != 0, "runtime", "must be provided")
	v.Check(movie.Runtime > 0, "runtime", "must be a positive integer")
	v.Check(movie.Genres != nil, "genres", "must be provided")
	v.Check(len(movie.Genres) >= 1, "genres", "must contain at least 1 genre")
	v.Check(len(movie.Genres) <= 5, "genres", "must not contain more than 5 genres")
	v.Check(validator.Unique(movie.Genres), "genres", "must not contain duplicate values")
}

type MovieModel struct {
	DB *sql.DB
}

func (m MovieModel) Insert(movie *Movie) error {
	query := `
INSERT INTO movies (title, year, runtime, genres)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at, version`

	args := []any{movie.Title, movie.Year, movie.Runtime, pq.Array(movie.Genres)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return m.DB.QueryRowContext(ctx, query, args...).Scan(&movie.ID, &movie.CreatedAt, &movie.Version)
}

// Add a placeholder method for fetching a specific record from the movies table.
func (m MovieModel) Get(id int64) (*Movie, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}

	query := `
		SELECT id, created_at, title, year, runtime, genres, version
		FROM movies
		WHERE id = $1`

	var movie Movie

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, id).Scan(
		&movie.ID,
		&movie.CreatedAt,
		&movie.Title,
		&movie.Year,
		&movie.Runtime,
		pq.Array(&movie.Genres),
		&movie.Version,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &movie, nil
}

// Add a placeholder method for updating a specific record in the movies table.
func (m MovieModel) Update(movie *Movie) error {
	query := `
UPDATE movies
SET title = $1, year = $2, runtime = $3, genres = $4, version = version + 1
WHERE id = $5 AND version = $6
RETURNING version`

	args := []any{
		movie.Title,
		movie.Year,
		movie.Runtime,
		pq.Array(movie.Genres),
		movie.ID,
		movie.Version,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&movie.Version)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrEditConflict
		default:
			return err
		}
	}

	return nil
}

// Add a placeholder method for deleting a specific record from the movies table.
func (m MovieModel) Delete(id int64) error {
	if id < 1 {
		return ErrRecordNotFound
	}

	query := `
	DELETE FROM movies
	WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := m.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (m MovieModel) GetAll(title string, genres []string, filters Filters) ([]*Movie, Metadata, error) {
	query := fmt.Sprintf(`
	SELECT count(*) OVER(), id, created_at, title, year, runtime, genres, version
	FROM movies
	WHERE (to_tsvector('simple', title) @@ plainto_tsquery('simple', $1) OR $1 = '')
	AND (genres @> $2 OR $2 = '{}')
	ORDER BY %s %s, id ASC
	LIMIT $3 OFFSET $4`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	args := []any{title, pq.Array(genres), filters.limit(), filters.offset()}

	rows, err := m.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, Metadata{}, err
	}
	defer rows.Close()

	movies := []*Movie{}

	totalRecords := 0

	for rows.Next() {
		var movie Movie

		err := rows.Scan(
			&totalRecords,
			&movie.ID,
			&movie.CreatedAt,
			&movie.Title,
			&movie.Year,
			&movie.Runtime,
			pq.Array(&movie.Genres),
			&movie.Version,
		)
		if err != nil {
			return nil, Metadata{}, err
		}

		movies = append(movies, &movie)
	}

	if err = rows.Err(); err != nil {
		return nil, Metadata{}, err
	}

	metadata := calculateMetadata(totalRecords, filters.Page, filters.PageSize)

	return movies, metadata, nil
}

type MockMovieModel struct{}

func (m MockMovieModel) Insert(movie *Movie) error {
	switch movie.Title {
	case "error":
		return errors.New("any other errors")
	}
	return nil
}

func (m MockMovieModel) Get(id int64) (*Movie, error) {
	switch id {
	case 1:
		return &Movie{
			ID:        1,
			CreatedAt: time.Now(),
			Year:      2023,
			Runtime:   105,
			Title:     "Test Mock",
			Genres:    []string{""},
		}, nil
	case 2:
		return nil, errors.New("any other errors")
	case 3:
		return &Movie{
			ID:        3,
			CreatedAt: time.Now(),
			Year:      2022,
			Runtime:   180,
			Title:     "Test Mock 2",
			Genres:    []string{"drama"},
		}, nil
	case 10:
		return &Movie{
			ID:        10,
			CreatedAt: time.Now(),
			Year:      1966,
			Runtime:   100,
			Title:     "Legends from test mock",
			Genres:    []string{"mystery"},
		}, nil
	default:
		return nil, ErrRecordNotFound
	}
}
func (m MockMovieModel) Update(movie *Movie) error {
	switch movie.ID {
	case 1:
		return nil
	case 10:
		return errors.New("any other errors")
	default:
		return ErrEditConflict
	}
}

func (m MockMovieModel) Delete(id int64) error {
	switch id {
	case 1:
		return nil
	case 2:
		return errors.New("any other errors")
	default:
		return ErrRecordNotFound
	}
}

func (m MockMovieModel) GetAll(title string, genres []string, filters Filters) ([]*Movie, Metadata, error) {
	if title == "Test" && reflect.DeepEqual(genres, []string{"comedy", "drama"}) {
		return []*Movie{
				{
					ID:        1,
					CreatedAt: time.Now(),
					Year:      2023,
					Runtime:   105,
					Title:     "Test Mock",
					Genres:    []string{"drama", "comedy"},
				},
			},
			Metadata{CurrentPage: filters.Page, PageSize: filters.PageSize, FirstPage: 1, LastPage: 1, TotalRecords: 1},
			nil
	} else if title == "" {
		return []*Movie{
				{
					ID:        1,
					CreatedAt: time.Now(),
					Year:      2023,
					Runtime:   105,
					Title:     "Test Mock",
					Genres:    []string{"drama", "comedy"},
				},
				{
					ID:        3,
					CreatedAt: time.Now(),
					Year:      2022,
					Runtime:   180,
					Title:     "Test Mock 2",
					Genres:    []string{"drama"},
				},
				{
					ID:        10,
					CreatedAt: time.Now(),
					Year:      1966,
					Runtime:   100,
					Title:     "Legends from test mock",
					Genres:    []string{"mystery"},
				},
			},
			Metadata{CurrentPage: filters.Page, PageSize: filters.PageSize, FirstPage: 1, LastPage: 1, TotalRecords: 2},
			nil
	} else if title == "error" {
		return nil, Metadata{}, errors.New("any other errors")
	}
	return nil, Metadata{}, nil
}
