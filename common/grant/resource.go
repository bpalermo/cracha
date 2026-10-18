package grant

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Resource kinds a lookup parameter and an Access document may name
// (design 6.4, Level 3). Each is an object type of the authorization store
// with the relations RelationReader and RelationWriter.
const (
	ResourceS3Bucket      = "s3_bucket"
	ResourceDynamoDBTable = "dynamodb_table"
)

// Relations of a resource kind, and the permissions a lookup asks for:
// read is held through either relation, write through writer alone.
const (
	RelationReader  = "reader"
	RelationWriter  = "writer"
	PermissionRead  = "read"
	PermissionWrite = "write"
)

// ResourceKind describes one kind of resource.
type ResourceKind struct {
	Name string
	// MaxNameLen is the longest name of the kind: what the compiler sizes a
	// lookup grant's policy with.
	MaxNameLen int
	// Validate checks a name of the kind.
	Validate func(name string) error
}

var resourceKinds = map[string]ResourceKind{
	ResourceS3Bucket:      {Name: ResourceS3Bucket, MaxNameLen: 63, Validate: validateBucketName},
	ResourceDynamoDBTable: {Name: ResourceDynamoDBTable, MaxNameLen: 255, Validate: validateTableName},
}

// LookupResourceKind returns the kind of that name.
func LookupResourceKind(name string) (ResourceKind, bool) {
	k, ok := resourceKinds[name]
	return k, ok
}

// ResourceKindNames are the known kinds, sorted.
func ResourceKindNames() []string { return sortedKeys(resourceKinds) }

// RelationsOf returns the relations that give a permission: read is reader
// or writer, write is writer.
func RelationsOf(permission string) ([]string, bool) {
	switch permission {
	case PermissionRead:
		return []string{RelationReader, RelationWriter}, true
	case PermissionWrite:
		return []string{RelationWriter}, true
	}
	return nil, false
}

// validRelation reports whether a relation is one of a kind's.
func validRelation(relation string) bool {
	return relation == RelationReader || relation == RelationWriter
}

var (
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	tableRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,255}$`)
	// bucketPrefixes and bucketSuffixes are reserved by S3.
	bucketPrefixes = []string{"xn--", "sthree-", "amzn-s3-demo-"}
	bucketSuffixes = []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"}
)

// validateBucketName checks S3's naming rules for a general purpose
// bucket: 3 to 63 lower-case letters, digits, dots and hyphens, starting
// and ending with a letter or digit, no two dots together, not an IPv4
// address, none of the reserved prefixes and suffixes.
func validateBucketName(name string) error {
	if !bucketRE.MatchString(name) {
		return fmt.Errorf("bucket name %q: 3 to 63 lower-case letters, digits, dots and hyphens, starting and ending with a letter or digit", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("bucket name %q: two dots together", name)
	}
	if addr, err := netip.ParseAddr(name); err == nil && addr.Is4() {
		return fmt.Errorf("bucket name %q: an IP address", name)
	}
	for _, p := range bucketPrefixes {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("bucket name %q: the prefix %q is reserved", name, p)
		}
	}
	for _, s := range bucketSuffixes {
		if strings.HasSuffix(name, s) {
			return fmt.Errorf("bucket name %q: the suffix %q is reserved", name, s)
		}
	}
	return nil
}

// validateTableName checks DynamoDB's table naming rules.
func validateTableName(name string) error {
	if !tableRE.MatchString(name) {
		return fmt.Errorf("table name %q: 3 to 255 letters, digits, underscores, dots and hyphens", name)
	}
	return nil
}

// validateLookup checks a lookup parameter: a known kind and permission.
func validateLookup(l *Lookup) error {
	if _, ok := LookupResourceKind(l.Kind); !ok {
		return fmt.Errorf("lookup kind %q: want one of %s", l.Kind, strings.Join(ResourceKindNames(), ", "))
	}
	if _, ok := RelationsOf(l.Permission); !ok {
		return fmt.Errorf("lookup permission %q: want %s or %s", l.Permission, PermissionRead, PermissionWrite)
	}
	return nil
}

// probeMarker starts every probe name, so that a rendered resource that
// holds one is known to come from the lookup.
const probeMarker = "crachaprobe"

// probeNames are n distinct valid names of a kind, each of its longest
// length: the worst case a lookup grant's policy is sized for.
func probeNames(k ResourceKind, n int) []string {
	out := make([]string, n)
	for i := range out {
		digits := fmt.Sprintf("%d", i)
		out[i] = probeMarker + strings.Repeat("0", k.MaxNameLen-len(probeMarker)-len(digits)) + digits
	}
	return out
}

// lookupParam returns the name and the lookup of a session policy's one
// lookup parameter, or empty and nil when it has none.
func lookupParam(sp *SessionPolicy) (string, *Lookup) {
	if sp == nil {
		return "", nil
	}
	for _, name := range sortedKeys(sp.Params) {
		if l := sp.Params[name].Lookup; l != nil {
			return name, l
		}
	}
	return "", nil
}

// sortedUnique returns the strings sorted, without repeats or empties.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// errNoResources is what rendering a lookup grant for no resources gives:
// the broker leaves such a grant out, or denies no_resources.
var errNoResources = errors.New("no resources to render the lookup parameter with")
