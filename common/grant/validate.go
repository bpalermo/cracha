package grant

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const maxNameLen = 63

var (
	// nameRE is the charset of grant, assignment and template names: a DNS
	// label with dots, so a name is safe in a file name, a session tag value
	// and a metrics label.
	nameRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	accountRE = regexp.MustCompile(`^[0-9]{12}$`)
	// roleARNRE captures the account and the role name of an IAM role ARN.
	roleARNRE = regexp.MustCompile(`^arn:(?:aws|aws-cn|aws-us-gov|aws-iso[a-z-]*):iam::([0-9]{12}):role/(?:[\w+=,.@-]+/)*([\w+=,.@-]+)$`)
	// policyARNRE captures the account ("aws" for AWS managed policies) of
	// an IAM managed policy ARN.
	policyARNRE = regexp.MustCompile(`^arn:(?:aws|aws-cn|aws-us-gov|aws-iso[a-z-]*):iam::(aws|[0-9]{12}):policy/(?:[\w+=,.@-]+/)*[\w+=,.@-]+$`)
	// tagRE is STS's session tag key and value charset.
	tagRE = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)
	// subjectRE is the authorization subject charset of design 4.3.
	subjectRE = regexp.MustCompile(`^[a-zA-Z0-9/_|=+-]+$`)
)

// maxSubjectLen is the authorization subject length limit of design 4.3.
const maxSubjectLen = 1024

func validateName(what, name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("%s %q: longer than %d characters", what, name, maxNameLen)
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%s %q: must be lowercase letters, digits, dots and dashes, starting and ending with a letter or digit", what, name)
	}
	return nil
}

// ValidateGrant checks a Grant against the rules of design 6.2 and the STS
// limits, and returns every problem found, joined.
func ValidateGrant(g *Grant) error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if g.Kind != KindGrant {
		fail("kind must be %s", KindGrant)
	}
	if err := validateName("grant name", g.Name()); err != nil {
		errs = append(errs, err)
	}
	s := &g.Spec
	if !accountRE.MatchString(s.Account) {
		fail("account %q: must be 12 digits", s.Account)
	}
	if m := roleARNRE.FindStringSubmatch(s.BaseRole); m == nil {
		fail("baseRole %q: must be an IAM role ARN", s.BaseRole)
	} else {
		if m[1] != s.Account {
			fail("baseRole %q: account %s does not match the grant's account %s", s.BaseRole, m[1], s.Account)
		}
		if len(m[2]) > 64 {
			fail("baseRole %q: role name longer than 64 characters", s.BaseRole)
		}
	}
	if s.SessionPolicy == nil && len(s.ManagedPolicyArns) == 0 {
		fail("a grant needs a sessionPolicy or managedPolicyArns; without either it would hand out the whole base role")
	}
	if s.SessionPolicy != nil {
		if err := validateName("sessionPolicy.template", s.SessionPolicy.Template); err != nil {
			errs = append(errs, err)
		}
		for _, name := range sortedKeys(s.SessionPolicy.Params) {
			if err := validateParamName(name); err != nil {
				errs = append(errs, fmt.Errorf("sessionPolicy.params: %w", err))
			}
		}
		if len(s.Envelope) == 0 {
			fail("envelope is required when a sessionPolicy is set")
		}
	}
	if len(s.ManagedPolicyArns) > MaxManagedPolicyArns {
		fail("managedPolicyArns: %d entries, STS allows at most %d", len(s.ManagedPolicyArns), MaxManagedPolicyArns)
	}
	seen := map[string]bool{}
	for _, arn := range s.ManagedPolicyArns {
		if seen[arn] {
			fail("managedPolicyArns: %q listed twice", arn)
		}
		seen[arn] = true
		m := policyARNRE.FindStringSubmatch(arn)
		if m == nil {
			fail("managedPolicyArns: %q is not an IAM managed policy ARN", arn)
			continue
		}
		if m[1] != "aws" && m[1] != s.Account {
			fail("managedPolicyArns: %q is in account %s, not the grant's account %s", arn, m[1], s.Account)
		}
	}
	if s.Duration != 0 && (s.Duration < MinDuration || s.Duration > MaxDuration) {
		fail("duration %d: must be between %d and %d seconds", s.Duration, MinDuration, MaxDuration)
	}
	seen = map[string]bool{}
	for _, pattern := range s.Envelope {
		if seen[pattern] {
			fail("envelope: %q listed twice", pattern)
		}
		seen[pattern] = true
		if !IsARNPattern(pattern) {
			fail("envelope: %q is not an ARN pattern", pattern)
		}
	}
	errs = append(errs, validateTags(s.SessionTags)...)
	return errors.Join(errs...)
}

// validateTags checks session tags against STS's charset and limits, with
// the broker's own tags reserved.
func validateTags(tags map[string]string) []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if n, limit := len(tags), MaxSessionTags-BrokerTagCount; n > limit {
		fail("sessionTags: %d tags, at most %d allowed once the broker's %d are counted", n, limit, BrokerTagCount)
	}
	chars := 0
	for _, k := range sortedKeys(tags) {
		v := tags[k]
		chars += len(k) + len(v)
		switch {
		case k == "":
			fail("sessionTags: empty key")
		case len(k) > MaxTagKeyChars:
			fail("sessionTags: key %q longer than %d characters", k, MaxTagKeyChars)
		case !tagRE.MatchString(k):
			fail("sessionTags: key %q has characters outside the tag charset", k)
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			fail("sessionTags: key %q: the aws: prefix is reserved", k)
		case isBrokerTagKey(k):
			fail("sessionTags: key %q is set by the broker and cannot be set by a grant", k)
		}
		switch {
		case len(v) > MaxTagValueChars:
			fail("sessionTags: value of %q longer than %d characters", k, MaxTagValueChars)
		case !tagRE.MatchString(v):
			fail("sessionTags: value of %q has characters outside the tag charset", k)
		}
	}
	if limit := TagBudgetChars - BrokerTagChars; chars > limit {
		fail("sessionTags: %d characters of keys and values, at most %d allowed once the broker's are counted", chars, limit)
	}
	return errs
}

func isBrokerTagKey(k string) bool {
	for _, b := range BrokerTagKeys {
		if strings.EqualFold(k, b) {
			return true
		}
	}
	return false
}

// ValidateAssignment checks an Assignment's own fields; whether its grants
// exist is checked by ValidateSource.
func ValidateAssignment(a *Assignment) error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if a.Kind != KindAssignment {
		fail("kind must be %s", KindAssignment)
	}
	if err := validateName("assignment name", a.Name()); err != nil {
		errs = append(errs, err)
	}
	s := &a.Spec
	if !subjectRE.MatchString(s.Subject) || len(s.Subject) > maxSubjectLen {
		fail("subject %q: must be an authorization subject encoding (design 4.3)", s.Subject)
	}
	if len(s.Grants) == 0 {
		fail("grants: at least one grant is required")
	}
	seen := map[string]bool{}
	for _, name := range s.Grants {
		if seen[name] {
			fail("grants: %q listed twice", name)
		}
		seen[name] = true
		if err := validateName("grant name", name); err != nil {
			errs = append(errs, fmt.Errorf("grants: %w", err))
		}
	}
	if _, err := s.Expiry(); err != nil {
		errs = append(errs, err)
	}
	seen = map[string]bool{}
	for _, c := range s.Clusters {
		if c == "" {
			fail("clusters: empty name")
		}
		if seen[c] {
			fail("clusters: %q listed twice", c)
		}
		seen[c] = true
	}
	return errors.Join(errs...)
}

// ValidateSource validates every document of a source tree and the
// references between them: a grant's template must exist, and an
// assignment's grants must exist.
func ValidateSource(src *Source) error {
	var errs []error
	for _, g := range src.Grants {
		if err := ValidateGrant(g); err != nil {
			errs = append(errs, fmt.Errorf("grant %s (%s): %w", g.Name(), g.Path, err))
			continue
		}
		if sp := g.Spec.SessionPolicy; sp != nil {
			if _, ok := src.Templates[sp.Template]; !ok {
				errs = append(errs, fmt.Errorf("grant %s (%s): template %q not found under %s/", g.Name(), g.Path, sp.Template, TemplatesDir))
			}
		}
	}
	for _, a := range src.Assignments {
		if err := ValidateAssignment(a); err != nil {
			errs = append(errs, fmt.Errorf("assignment %s (%s): %w", a.Name(), a.Path, err))
			continue
		}
		for _, name := range a.Spec.Grants {
			if src.Grant(name) == nil {
				errs = append(errs, fmt.Errorf("assignment %s (%s): grant %q not found", a.Name(), a.Path, name))
			}
		}
	}
	return errors.Join(errs...)
}
