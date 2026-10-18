package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// implicitAccountParam is the parameter every template may reference without
// declaring it: the grant's account.
const implicitAccountParam = "account"

var paramNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func validateParamName(name string) error {
	if !paramNameRE.MatchString(name) {
		return fmt.Errorf("parameter name %q: must match %s", name, paramNameRE)
	}
	return nil
}

// Render substitutes the parameters into the template's policy and returns
// the rendered policy as minified JSON with sorted keys (see the package
// documentation for the template language). account is the grant's account,
// available to the template as ${account}.
func (t *Template) Render(account string, params map[string]Param) (string, error) {
	values, err := t.resolveParams(account, params)
	if err != nil {
		return "", err
	}
	var doc any
	if err := json.Unmarshal(t.Policy, &doc); err != nil {
		return "", fmt.Errorf("template %s: policy: %w", t.Name, err)
	}
	rendered, err := substitute(doc, values)
	if err != nil {
		return "", fmt.Errorf("template %s: %w", t.Name, err)
	}
	out, err := MinifyJSON(rendered)
	if err != nil {
		return "", err
	}
	return out, nil
}

// RenderLookup renders a lookup grant's policy (design 6.2, Level 3):
// params are the grant's parameters, the lookup parameter param among
// them, and resources what the authorization store found for it. The rule:
//
//   - a parameter the template declares as a list is the resources, and
//     the template is rendered once;
//   - a parameter declared as a string is rendered once per resource, and
//     the statements of every rendering are put together in resource order
//     under one Version (ComposePolicies), so a template written for one
//     resource serves any number.
//
// The resources are sorted and their repeats dropped first, so the same
// set renders the same bytes. No resources is an error: there is nothing
// to render.
func (t *Template) RenderLookup(account string, params map[string]Param, param string, resources []string) (string, error) {
	resources = sortedUnique(resources)
	if len(resources) == 0 {
		return "", fmt.Errorf("template %s: parameter %q: %w", t.Name, param, errNoResources)
	}
	spec, ok := t.Params[param]
	if !ok {
		return "", fmt.Errorf("template %s: parameter %q is not declared by the template", t.Name, param)
	}
	with := func(v Param) map[string]Param {
		out := make(map[string]Param, len(params))
		for k, p := range params {
			out[k] = p
		}
		out[param] = v
		return out
	}
	if spec.Type == ParamList {
		return t.Render(account, with(ListParam(resources...)))
	}
	policies := make([]string, 0, len(resources))
	for _, r := range resources {
		policy, err := t.Render(account, with(StringParam(r)))
		if err != nil {
			return "", err
		}
		policies = append(policies, policy)
	}
	return ComposePolicies(policies...)
}

// resolveParams checks the supplied parameters against the declarations and
// returns the values to substitute, defaults and the implicit account
// included.
func (t *Template) resolveParams(account string, params map[string]Param) (map[string]Param, error) {
	var errs []error
	values := map[string]Param{implicitAccountParam: StringParam(account)}
	for _, name := range sortedKeys(params) {
		if name == implicitAccountParam {
			errs = append(errs, fmt.Errorf("template %s: parameter %q is implicit and cannot be supplied", t.Name, name))
			continue
		}
		if _, ok := t.Params[name]; !ok {
			errs = append(errs, fmt.Errorf("template %s: parameter %q is not declared by the template", t.Name, name))
		}
	}
	for _, name := range sortedKeys(t.Params) {
		v, supplied := params[name]
		v, err := t.paramValue(name, v, supplied)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		values[name] = v
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return values, nil
}

// paramValue is the value a declared parameter is rendered with: the one
// supplied, which must match its type and not be a lookup, or its
// default; an empty list is an error.
func (t *Template) paramValue(name string, v Param, supplied bool) (Param, error) {
	spec := t.Params[name]
	switch {
	case supplied && v.Lookup != nil:
		return Param{}, fmt.Errorf("template %s: parameter %q is a lookup, filled at issuance (RenderLookup)", t.Name, name)
	case supplied && v.IsList != (spec.Type == ParamList):
		return Param{}, fmt.Errorf("template %s: parameter %q must be a %s", t.Name, name, spec.Type)
	case supplied:
	case spec.Default != nil:
		v = *spec.Default
	default:
		return Param{}, fmt.Errorf("template %s: parameter %q is required", t.Name, name)
	}
	if v.IsList && len(v.List) == 0 {
		return Param{}, fmt.Errorf("template %s: parameter %q is an empty list", t.Name, name)
	}
	return v, nil
}

// substitute renders one decoded JSON value.
func substitute(v any, values map[string]Param) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		return substituteObject(x, values)
	case []any:
		return substituteArray(x, values)
	case string:
		return substituteString(x, values)
	default:
		return v, nil
	}
}

// substituteObject renders an object's values; a string value that
// references a list becomes an array.
func substituteObject(x map[string]any, values map[string]Param) (map[string]any, error) {
	out := make(map[string]any, len(x))
	for _, k := range sortedKeys(x) {
		r, err := substitute(x[k], values)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out[k] = r
	}
	return out, nil
}

// substituteArray renders an array's elements; a string element that
// references a list is spliced in place.
func substituteArray(x []any, values map[string]Param) ([]any, error) {
	out := make([]any, 0, len(x))
	for i, child := range x {
		elems, err := substituteElement(child, values)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, elems...)
	}
	return out, nil
}

// substituteElement renders one array element as the elements that take
// its place: every expansion of a string, one value for anything else.
func substituteElement(child any, values map[string]Param) ([]any, error) {
	if s, ok := child.(string); ok {
		expanded, _, err := expand(s, values)
		if err != nil {
			return nil, err
		}
		return toAnySlice(expanded), nil
	}
	r, err := substitute(child, values)
	if err != nil {
		return nil, err
	}
	return []any{r}, nil
}

// substituteString renders a string: an array when it references a list,
// a string otherwise.
func substituteString(s string, values map[string]Param) (any, error) {
	expanded, fromList, err := expand(s, values)
	if err != nil {
		return nil, err
	}
	if fromList {
		return toAnySlice(expanded), nil
	}
	return expanded[0], nil
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// expand replaces the ${name} references in s. It returns one string per
// combination of the referenced lists' elements (a single string when no
// list is referenced) and whether a list was referenced.
func expand(s string, values map[string]Param) ([]string, bool, error) {
	e := &expansion{results: []string{""}}
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "$${"):
			e.literal("${")
			i += 3
		case strings.HasPrefix(rest, "${"):
			name, n, err := parseReference(rest, s)
			if err != nil {
				return nil, false, err
			}
			v, ok := values[name]
			if !ok {
				return nil, false, fmt.Errorf("unknown parameter %q in %q (write $${%s} for a literal)", name, s, name)
			}
			e.param(v)
			i += n
		default:
			lit, n := literalPrefix(rest)
			e.literal(lit)
			i += n
		}
	}
	return e.results, e.fromList, nil
}

// expansion accumulates the strings an expand call produces, one per
// combination of the list elements referenced so far.
type expansion struct {
	results  []string
	fromList bool
}

// literal appends lit to every result.
func (e *expansion) literal(lit string) {
	for i := range e.results {
		e.results[i] += lit
	}
}

// param appends a parameter's value: a string to every result, a list as
// the product of the results and its elements.
func (e *expansion) param(v Param) {
	if !v.IsList {
		e.literal(v.String)
		return
	}
	e.fromList = true
	next := make([]string, 0, len(e.results)*len(v.List))
	for _, prefix := range e.results {
		for _, item := range v.List {
			next = append(next, prefix+item)
		}
	}
	e.results = next
}

// parseReference reads the ${name} at the start of rest and returns the
// name and the reference's length. whole is the string being expanded, for
// the message.
func parseReference(rest, whole string) (string, int, error) {
	end := strings.IndexByte(rest, '}')
	if end < 0 {
		return "", 0, fmt.Errorf("unterminated ${ in %q", whole)
	}
	return rest[2:end], end + 1, nil
}

// literalPrefix returns the literal text at the start of rest, up to the
// next "$" (a "$" that starts no reference is itself literal), and its
// length.
func literalPrefix(rest string) (string, int) {
	j := strings.Index(rest, "$")
	switch {
	case j < 0:
		return rest, len(rest)
	case j == 0:
		return "$", 1
	default:
		return rest[:j], j
	}
}

// MinifyJSON encodes a decoded JSON value compactly, keys sorted, without
// HTML escaping.
func MinifyJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// MinifyPolicy re-encodes a JSON policy document compactly with sorted keys.
func MinifyPolicy(policy string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(policy), &v); err != nil {
		return "", fmt.Errorf("policy is not valid JSON: %w", err)
	}
	return MinifyJSON(v)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
