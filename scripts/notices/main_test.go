package main

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"apache", "Apache License\n   Version 2.0, January 2004\n", []string{"Apache-2.0"}},
		{"mpl", "Mozilla Public License Version 2.0\n==================================", []string{"MPL-2.0"}},
		{"mit", "Permission is hereby granted, free of charge, to any person obtaining a copy\nof this software", []string{"MIT"}},
		{"bsd3", "Redistribution and use in source and binary forms, with or without\nmodification ... * Neither the name of Google Inc. nor", []string{"BSD-3-Clause"}},
		{"bsd2", "Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that", []string{"BSD-2-Clause"}},
		{"isc", "Permission to use, copy, modify, and/or distribute this software for any\npurpose with or without fee is hereby granted", []string{"ISC"}},
		{"unlicense", "This is free and unencumbered software released into the public domain.", []string{"Unlicense"}},
		{"composite", "Apache License Version 2.0\n...\nPermission is hereby granted, free of charge, to any person obtaining a copy", []string{"Apache-2.0", "MIT"}},
		{"gpl is unknown", "GNU GENERAL PUBLIC LICENSE Version 3", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		if got := classify(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: classify = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEscapePath(t *testing.T) {
	if got := escapePath("github.com/Azure/go-autorest"); got != "github.com/!azure/go-autorest" {
		t.Fatalf("escapePath = %q", got)
	}
}
