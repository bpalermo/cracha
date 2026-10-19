package bundle

import pub "github.com/bpalermo/cracha/common/publication"

// The fetchers live in common/publication, which cracha-access reads the
// same publication with; these names keep the broker's spelling of them.
type (
	// Fetcher is publication.Fetcher.
	Fetcher = pub.Fetcher
	// Fetched is publication.Fetched.
	Fetched = pub.Fetched
	// Location is publication.Location.
	Location = pub.Location
	// Local is publication.Local.
	Local = pub.Local
	// S3 is publication.S3.
	S3 = pub.S3
	// S3API is publication.S3API.
	S3API = pub.S3API
)

// ParseSource is publication.ParseSource.
func ParseSource(source string) (Location, error) { return pub.ParseSource(source) }

// NewS3 is publication.NewS3.
func NewS3(api S3API, bucket, prefix string) *S3 { return pub.NewS3(api, bucket, prefix) }
