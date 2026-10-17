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
		spec := t.Params[name]
		v, supplied := params[name]
		switch {
		case supplied:
			if v.IsList != (spec.Type == ParamList) {
				errs = append(errs, fmt.Errorf("template %s: parameter %q must be a %s", t.Name, name, spec.Type))
				continue
			}
		case spec.Default != nil:
			v = *spec.Default
		default:
			errs = append(errs, fmt.Errorf("template %s: parameter %q is required", t.Name, name))
			continue
		}
		if v.IsList && len(v.List) == 0 {
			errs = append(errs, fmt.Errorf("template %s: parameter %q is an empty list", t.Name, name))
			continue
		}
		values[name] = v
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return values, nil
}

// substitute renders one decoded JSON value.
func substitute(v any, values map[string]Param) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, k := range sortedKeys(x) {
			child := x[k]
			if s, ok := child.(string); ok {
				expanded, fromList, err := expand(s, values)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", k, err)
				}
				if fromList {
					out[k] = toAnySlice(expanded)
				} else {
					out[k] = expanded[0]
				}
				continue
			}
			r, err := substitute(child, values)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(x))
		for i, child := range x {
			if s, ok := child.(string); ok {
				expanded, _, err := expand(s, values)
				if err != nil {
					return nil, fmt.Errorf("[%d]: %w", i, err)
				}
				out = append(out, toAnySlice(expanded)...)
				continue
			}
			r, err := substitute(child, values)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out = append(out, r)
		}
		return out, nil
	case string:
		expanded, fromList, err := expand(x, values)
		if err != nil {
			return nil, err
		}
		if fromList {
			return toAnySlice(expanded), nil
		}
		return expanded[0], nil
	default:
		return v, nil
	}
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
	results := []string{""}
	fromList := false
	appendLiteral := func(lit string) {
		for i := range results {
			results[i] += lit
		}
	}
	i := 0
	for i < len(s) {
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "$${"):
			appendLiteral("${")
			i += 3
		case strings.HasPrefix(rest, "${"):
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return nil, false, fmt.Errorf("unterminated ${ in %q", s)
			}
			name := rest[2:end]
			v, ok := values[name]
			if !ok {
				return nil, false, fmt.Errorf("unknown parameter %q in %q (write $${%s} for a literal)", name, s, name)
			}
			if v.IsList {
				fromList = true
				next := make([]string, 0, len(results)*len(v.List))
				for _, prefix := range results {
					for _, item := range v.List {
						next = append(next, prefix+item)
					}
				}
				results = next
			} else {
				appendLiteral(v.String)
			}
			i += end + 1
		default:
			j := strings.Index(rest, "$")
			if j < 0 {
				appendLiteral(rest)
				i = len(s)
			} else if j == 0 {
				appendLiteral("$")
				i++
			} else {
				appendLiteral(rest[:j])
				i += j
			}
		}
	}
	return results, fromList, nil
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
