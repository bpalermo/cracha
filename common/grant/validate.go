package grant

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const maxNameLen = 63

var (
	// nameRE is the charset of grant, assignment, service, team and template
	// names: a DNS label, so a name is safe in a file name, a session tag
	// value, a metrics label and an authorization-store object ID (SpiceDB's
	// charset has no dot).
	nameRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
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

// errList collects the problems a validation finds, in the order found.
type errList []error

// addf records a new problem; %w wraps as in fmt.Errorf.
func (l *errList) addf(format string, args ...any) {
	*l = append(*l, fmt.Errorf(format, args...))
}

// add records err when it is not nil.
func (l *errList) add(err error) {
	if err != nil {
		*l = append(*l, err)
	}
}

func validateName(what, name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("%s %q: longer than %d characters", what, name, maxNameLen)
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%s %q: must be lowercase letters, digits and dashes, starting and ending with a letter or digit", what, name)
	}
	return nil
}

// grantChecks are the rules ValidateGrant applies, in the order their
// problems are reported.
var grantChecks = []func(g *Grant) errList{
	validateGrantHeader,
	func(g *Grant) errList { return validateAccountAndRole(&g.Spec) },
	func(g *Grant) errList { return validateSessionPolicy(&g.Spec) },
	func(g *Grant) errList { return validateManagedPolicyArns(&g.Spec) },
	func(g *Grant) errList { return validateDuration(&g.Spec) },
	func(g *Grant) errList { return validateEnvelope(&g.Spec) },
	func(g *Grant) errList { return validateTags(g.Spec.SessionTags) },
}

// ValidateGrant checks a Grant against the rules of design 6.2 and the STS
// limits, and returns every problem found, joined.
func ValidateGrant(g *Grant) error {
	var errs errList
	for _, check := range grantChecks {
		errs = append(errs, check(g)...)
	}
	return errors.Join(errs...)
}

// validateGrantHeader checks the kind and the name.
func validateGrantHeader(g *Grant) errList {
	var errs errList
	if g.Kind != KindGrant {
		errs.addf("kind must be %s", KindGrant)
	}
	errs.add(validateName("grant name", g.Name()))
	return errs
}

// validateAccountAndRole checks the account and that the base role is a
// role of that account.
func validateAccountAndRole(s *GrantSpec) errList {
	var errs errList
	if !accountRE.MatchString(s.Account) {
		errs.addf("account %q: must be 12 digits", s.Account)
	}
	m := roleARNRE.FindStringSubmatch(s.BaseRole)
	if m == nil {
		errs.addf("baseRole %q: must be an IAM role ARN", s.BaseRole)
		return errs
	}
	if m[1] != s.Account {
		errs.addf("baseRole %q: account %s does not match the grant's account %s", s.BaseRole, m[1], s.Account)
	}
	if len(m[2]) > 64 {
		errs.addf("baseRole %q: role name longer than 64 characters", s.BaseRole)
	}
	return errs
}

// validateSessionPolicy checks the session policy reference, and that a
// grant without one carries managed policies instead.
func validateSessionPolicy(s *GrantSpec) errList {
	var errs errList
	sp := s.SessionPolicy
	if sp == nil {
		if len(s.ManagedPolicyArns) == 0 {
			errs.addf("a grant needs a sessionPolicy or managedPolicyArns; without either it would hand out the whole base role")
		}
		return errs
	}
	errs.add(validateName("sessionPolicy.template", sp.Template))
	for _, name := range sortedKeys(sp.Params) {
		if err := validateParamName(name); err != nil {
			errs.addf("sessionPolicy.params: %w", err)
		}
	}
	if len(s.Envelope) == 0 {
		errs.addf("envelope is required when a sessionPolicy is set")
	}
	return errs
}

// validateManagedPolicyArns checks the managed policies: at most STS's
// limit, each listed once, each a policy ARN of AWS or the grant's account.
func validateManagedPolicyArns(s *GrantSpec) errList {
	var errs errList
	if len(s.ManagedPolicyArns) > MaxManagedPolicyArns {
		errs.addf("managedPolicyArns: %d entries, STS allows at most %d", len(s.ManagedPolicyArns), MaxManagedPolicyArns)
	}
	seen := map[string]bool{}
	for _, arn := range s.ManagedPolicyArns {
		if seen[arn] {
			errs.addf("managedPolicyArns: %q listed twice", arn)
		}
		seen[arn] = true
		m := policyARNRE.FindStringSubmatch(arn)
		if m == nil {
			errs.addf("managedPolicyArns: %q is not an IAM managed policy ARN", arn)
			continue
		}
		if m[1] != "aws" && m[1] != s.Account {
			errs.addf("managedPolicyArns: %q is in account %s, not the grant's account %s", arn, m[1], s.Account)
		}
	}
	return errs
}

// validateDuration checks a set duration against STS's bounds.
func validateDuration(s *GrantSpec) errList {
	var errs errList
	if s.Duration != 0 && (s.Duration < MinDuration || s.Duration > MaxDuration) {
		errs.addf("duration %d: must be between %d and %d seconds", s.Duration, MinDuration, MaxDuration)
	}
	return errs
}

// validateEnvelope checks that every envelope entry is an ARN pattern
// listed once.
func validateEnvelope(s *GrantSpec) errList {
	var errs errList
	seen := map[string]bool{}
	for _, pattern := range s.Envelope {
		if seen[pattern] {
			errs.addf("envelope: %q listed twice", pattern)
		}
		seen[pattern] = true
		if !IsARNPattern(pattern) {
			errs.addf("envelope: %q is not an ARN pattern", pattern)
		}
	}
	return errs
}

// validateTags checks session tags against STS's charset and limits, with
// the broker's own tags reserved.
func validateTags(tags map[string]string) errList {
	var errs errList
	if n, limit := len(tags), MaxSessionTags-BrokerTagCount; n > limit {
		errs.addf("sessionTags: %d tags, at most %d allowed once the broker's %d are counted", n, limit, BrokerTagCount)
	}
	chars := 0
	for _, k := range sortedKeys(tags) {
		v := tags[k]
		chars += len(k) + len(v)
		switch {
		case k == "":
			errs.addf("sessionTags: empty key")
		case len(k) > MaxTagKeyChars:
			errs.addf("sessionTags: key %q longer than %d characters", k, MaxTagKeyChars)
		case !tagRE.MatchString(k):
			errs.addf("sessionTags: key %q has characters outside the tag charset", k)
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			errs.addf("sessionTags: key %q: the aws: prefix is reserved", k)
		case isBrokerTagKey(k):
			errs.addf("sessionTags: key %q is set by the broker and cannot be set by a grant", k)
		}
		switch {
		case len(v) > MaxTagValueChars:
			errs.addf("sessionTags: value of %q longer than %d characters", k, MaxTagValueChars)
		case !tagRE.MatchString(v):
			errs.addf("sessionTags: value of %q has characters outside the tag charset", k)
		}
	}
	if limit := TagBudgetChars - BrokerTagChars; chars > limit {
		errs.addf("sessionTags: %d characters of keys and values, at most %d allowed once the broker's are counted", chars, limit)
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
	var errs errList
	if a.Kind != KindAssignment {
		errs.addf("kind must be %s", KindAssignment)
	}
	errs.add(validateName("assignment name", a.Name()))
	s := &a.Spec
	errs.add(validateSubject(s.Subject))
	if len(s.Grants) == 0 && !s.Suspended {
		errs.addf("grants: at least one grant is required")
	}
	errs = append(errs, validateGrantNames(s.Grants)...)
	_, err := s.Expiry()
	errs.add(err)
	errs = append(errs, validateClusters(s.Clusters)...)
	return errors.Join(errs...)
}

// validateSubject checks an authorization subject encoding (design 4.3).
func validateSubject(subject string) error {
	if !subjectRE.MatchString(subject) || len(subject) > maxSubjectLen {
		return fmt.Errorf("subject %q: must be an authorization subject encoding (design 4.3)", subject)
	}
	return nil
}

// validateGrantNames checks a list of grant names: each listed once, each a
// valid name.
func validateGrantNames(grants []string) errList {
	var errs errList
	seen := map[string]bool{}
	for _, name := range grants {
		if seen[name] {
			errs.addf("grants: %q listed twice", name)
		}
		seen[name] = true
		if err := validateName("grant name", name); err != nil {
			errs.addf("grants: %w", err)
		}
	}
	return errs
}

// ValidateService checks a Service's own fields; whether its grants exist
// and its members belong to no other service is checked by ValidateSource.
func ValidateService(s *Service) error {
	var errs errList
	if s.Kind != KindService {
		errs.addf("kind must be %s", KindService)
	}
	errs.add(validateName("service name", s.Name()))
	errs.add(validateName("team", s.Spec.Team))
	seen := map[string]bool{}
	for _, member := range s.Spec.Members {
		if seen[member] {
			errs.addf("members: %q listed twice", member)
		}
		seen[member] = true
		if err := validateSubject(member); err != nil {
			errs.addf("members: %w", err)
		}
	}
	names := make([]string, 0, len(s.Spec.Grants))
	for _, g := range s.Spec.Grants {
		names = append(names, g.Name)
		if _, err := g.Expiry(); err != nil {
			errs.addf("grants: %s: %w", g.Name, err)
		}
		for _, cerr := range validateClusters(g.Clusters) {
			errs.addf("grants: %s: %w", g.Name, cerr)
		}
	}
	errs = append(errs, validateGrantNames(names)...)
	return errors.Join(errs...)
}

// validateClusters checks an assignment's cluster names: none empty, each
// listed once.
func validateClusters(clusters []string) errList {
	var errs errList
	seen := map[string]bool{}
	for _, c := range clusters {
		if c == "" {
			errs.addf("clusters: empty name")
		}
		if seen[c] {
			errs.addf("clusters: %q listed twice", c)
		}
		seen[c] = true
	}
	return errs
}

// ValidateSource validates every document of a source tree and the
// references between them: a grant's template must exist, an assignment's
// and a service's grants must exist, and a workload is a member of at most
// one service.
func ValidateSource(src *Source) error {
	var errs errList
	for _, g := range src.Grants {
		errs.add(validateSourceGrant(src, g))
	}
	for _, a := range src.Assignments {
		errs = append(errs, validateSourceAssignment(src, a)...)
	}
	memberOf := map[string]*Service{}
	for _, s := range src.Services {
		errs = append(errs, validateSourceService(src, s, memberOf)...)
	}
	return errors.Join(errs...)
}

// validateSourceService validates one service and, when it is valid, that
// every grant it names exists and that no member belongs to a service seen
// before, which memberOf records.
func validateSourceService(src *Source, s *Service, memberOf map[string]*Service) errList {
	var errs errList
	if err := ValidateService(s); err != nil {
		errs.addf("service %s (%s): %w", s.Name(), s.Path, err)
		return errs
	}
	for _, g := range s.Spec.Grants {
		if src.Grant(g.Name) == nil {
			errs.addf("service %s (%s): grant %q not found", s.Name(), s.Path, g.Name)
		}
	}
	for _, member := range s.Spec.Members {
		if prev, ok := memberOf[member]; ok {
			errs.addf("service %s (%s): %q is already a member of service %s (%s); a workload is a member of at most one service", s.Name(), s.Path, member, prev.Name(), prev.Path)
			continue
		}
		memberOf[member] = s
	}
	return errs
}

// validateSourceGrant validates one grant and, when it is valid, that the
// template it names exists.
func validateSourceGrant(src *Source, g *Grant) error {
	if err := ValidateGrant(g); err != nil {
		return fmt.Errorf("grant %s (%s): %w", g.Name(), g.Path, err)
	}
	sp := g.Spec.SessionPolicy
	if sp == nil {
		return nil
	}
	if _, ok := src.Templates[sp.Template]; !ok {
		return fmt.Errorf("grant %s (%s): template %q not found under %s/", g.Name(), g.Path, sp.Template, TemplatesDir)
	}
	return nil
}

// validateSourceAssignment validates one assignment and, when it is valid,
// that every grant it names exists.
func validateSourceAssignment(src *Source, a *Assignment) errList {
	var errs errList
	if err := ValidateAssignment(a); err != nil {
		errs.addf("assignment %s (%s): %w", a.Name(), a.Path, err)
		return errs
	}
	for _, name := range a.Spec.Grants {
		if src.Grant(name) == nil {
			errs.addf("assignment %s (%s): grant %q not found", a.Name(), a.Path, name)
		}
	}
	return errs
}
