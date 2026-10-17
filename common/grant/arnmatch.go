package grant

import "strings"

// MatchARN reports whether s matches pattern with IAM's wildcard semantics:
// "*" matches any sequence of characters, including none and including ":"
// and "/", and "?" matches exactly one character. Matching is
// case-sensitive, as IAM's is for ARNs.
func MatchARN(pattern, s string) bool {
	// Classic iterative glob: remember the last "*" and where it started
	// matching, and back up to it on mismatch.
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchesEnvelope reports whether the resource ARN matches at least one of
// the envelope's patterns. A resource of "*" matches only an envelope that
// contains "*" itself, as does any resource that is not an ARN.
func MatchesEnvelope(envelope []string, resource string) bool {
	for _, pattern := range envelope {
		if pattern == "*" {
			return true
		}
	}
	if !strings.HasPrefix(resource, "arn:") {
		return false
	}
	for _, pattern := range envelope {
		if MatchARN(pattern, resource) {
			return true
		}
	}
	return false
}

// IsARNPattern reports whether s is shaped like an ARN or an ARN pattern:
// "arn:" followed by partition, service, region, account and resource
// fields, with the partition, service and resource non-empty, and no
// whitespace or control characters anywhere. "*" alone is also accepted, as
// the pattern that matches everything.
func IsARNPattern(s string) bool {
	if s == "*" {
		return true
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	fields := strings.SplitN(s, ":", 6)
	if len(fields) != 6 || fields[0] != "arn" {
		return false
	}
	return fields[1] != "" && fields[2] != "" && fields[5] != ""
}
