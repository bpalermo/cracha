package grant

import (
	"strings"
	"testing"
)

func mustTemplate(t *testing.T, doc string) *Template {
	t.Helper()
	tmpl, err := ParseTemplate([]byte(doc))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	tmpl.Name = "t"
	return tmpl
}

func TestRender(t *testing.T) {
	const tmpl = `{
	  "params": {
	    "tables": {"type": "list"},
	    "region": {"type": "string", "default": "*"},
	    "prefixes": {"type": "list", "default": ["a", "b"]}
	  },
	  "policy": {
	    "Version": "2012-10-17",
	    "Statement": [
	      {"Effect": "Allow", "Action": "dynamodb:Query",
	       "Resource": ["arn:aws:dynamodb:${region}:${account}:table/${tables}", "arn:aws:s3:::bucket/${prefixes}/${tables}"]},
	      {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/${tables}",
	       "Condition": {"StringEquals": {"aws:username": "$${aws:username}"}}},
	      {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*", "Sid": "cost $5"}
	    ]
	  }
	}`
	tests := []struct {
		name   string
		params map[string]Param
		want   string // the rendered policy, or a substring of the error when wantErr
		err    bool
	}{
		{
			name:   "lists expand in arrays, object values become arrays, defaults apply",
			params: map[string]Param{"tables": ListParam("t1", "t2")},
			want: `{"Statement":[` +
				`{"Action":"dynamodb:Query","Effect":"Allow","Resource":["arn:aws:dynamodb:*:111122223333:table/t1","arn:aws:dynamodb:*:111122223333:table/t2","arn:aws:s3:::bucket/a/t1","arn:aws:s3:::bucket/a/t2","arn:aws:s3:::bucket/b/t1","arn:aws:s3:::bucket/b/t2"]},` +
				`{"Action":["s3:GetObject"],"Condition":{"StringEquals":{"aws:username":"${aws:username}"}},"Effect":"Allow","Resource":["arn:aws:s3:::bucket/t1","arn:aws:s3:::bucket/t2"]},` +
				`{"Action":"sts:GetCallerIdentity","Effect":"Allow","Resource":"*","Sid":"cost $5"}` +
				`],"Version":"2012-10-17"}`,
		},
		{
			name:   "supplied string and one-element list",
			params: map[string]Param{"tables": ListParam("t1"), "region": StringParam("eu-west-1"), "prefixes": ListParam("p")},
			want: `{"Statement":[` +
				`{"Action":"dynamodb:Query","Effect":"Allow","Resource":["arn:aws:dynamodb:eu-west-1:111122223333:table/t1","arn:aws:s3:::bucket/p/t1"]},` +
				`{"Action":["s3:GetObject"],"Condition":{"StringEquals":{"aws:username":"${aws:username}"}},"Effect":"Allow","Resource":["arn:aws:s3:::bucket/t1"]},` +
				`{"Action":"sts:GetCallerIdentity","Effect":"Allow","Resource":"*","Sid":"cost $5"}` +
				`],"Version":"2012-10-17"}`,
		},
		{name: "missing required", params: map[string]Param{}, err: true, want: `parameter "tables" is required`},
		{name: "undeclared", params: map[string]Param{"tables": ListParam("t"), "colour": StringParam("red")}, err: true, want: `parameter "colour" is not declared`},
		{name: "account supplied", params: map[string]Param{"tables": ListParam("t"), "account": StringParam("1")}, err: true, want: "implicit"},
		{name: "type mismatch list", params: map[string]Param{"tables": StringParam("t")}, err: true, want: `parameter "tables" must be a list`},
		{name: "type mismatch string", params: map[string]Param{"tables": ListParam("t"), "region": ListParam("r")}, err: true, want: `parameter "region" must be a string`},
		{name: "empty list", params: map[string]Param{"tables": ListParam()}, err: true, want: "empty list"},
	}
	tmplObj := mustTemplate(t, tmpl)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tmplObj.Render("111122223333", tt.params)
			if tt.err {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Errorf("error = %v, want it to contain %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got != tt.want {
				t.Errorf("Render =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestRenderBadReferences(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string
	}{
		{"unknown", `{"Resource": "${nope}"}`, `unknown parameter "nope"`},
		{"policy variable unescaped", `{"Resource": "${aws:username}"}`, `write $${aws:username} for a literal`},
		{"unterminated", `{"Resource": "${account"}`, "unterminated"},
		{"in array", `{"Resource": ["ok", "${nope}"]}`, "[1]"},
		{"nested", `{"Condition": {"StringEquals": {"k": "${nope}"}}}`, "Condition: StringEquals: k"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := mustTemplate(t, `{"policy": `+tt.policy+`}`)
			_, err := tmpl.Render("111122223333", nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestRenderNeverEscapesJSON(t *testing.T) {
	tmpl := mustTemplate(t, `{"params": {"x": {"type": "string"}}, "policy": {"Resource": "${x}"}}`)
	got, err := tmpl.Render("111122223333", map[string]Param{"x": StringParam(`a"},{"Effect":"Allow`)})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"Resource":"a\"},{\"Effect\":\"Allow"}`; got != want {
		t.Errorf("Render = %s, want %s", got, want)
	}
}

func TestExpand(t *testing.T) {
	values := map[string]Param{"s": StringParam("S"), "l": ListParam("1", "2"), "m": ListParam("x", "y")}
	tests := []struct {
		in       string
		want     []string
		fromList bool
	}{
		{"", []string{""}, false},
		{"plain", []string{"plain"}, false},
		{"$", []string{"$"}, false},
		{"a$b", []string{"a$b"}, false},
		{"$${s}", []string{"${s}"}, false},
		{"${s}-${s}", []string{"S-S"}, false},
		{"${l}", []string{"1", "2"}, true},
		{"${l}/${m}", []string{"1/x", "1/y", "2/x", "2/y"}, true},
		{"${s}${l}$", []string{"S1$", "S2$"}, true},
	}
	for _, tt := range tests {
		got, fromList, err := expand(tt.in, values)
		if err != nil {
			t.Errorf("expand(%q): %v", tt.in, err)
			continue
		}
		if strings.Join(got, "|") != strings.Join(tt.want, "|") || fromList != tt.fromList {
			t.Errorf("expand(%q) = %q, %v; want %q, %v", tt.in, got, fromList, tt.want, tt.fromList)
		}
	}
}

func TestMinifyPolicy(t *testing.T) {
	got, err := MinifyPolicy("{\n \"b\": [1, 2],\n \"a\": \"x&y\"\n}")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"x&y","b":[1,2]}`; got != want {
		t.Errorf("MinifyPolicy = %s, want %s", got, want)
	}
	if _, err := MinifyPolicy("{"); err == nil {
		t.Error("MinifyPolicy accepted broken JSON")
	}
}
