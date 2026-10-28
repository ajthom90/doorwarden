package store

import (
	"context"
	"reflect"
	"testing"
)

func TestListSettingKeysAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for _, k := range []string{"acme/attempt/a", "acme/attempt/b", "acme/attemptX", "acme/fv/le/x", "other"} {
		if err := s.SetSetting(ctx, k, "1"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListSettingKeys(ctx, "acme/attempt/")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"acme/attempt/a", "acme/attempt/b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys %v, want %v", got, want)
	}
	// LIKE wildcards in the prefix are literal.
	if err := s.SetSetting(ctx, "p%x/1", "1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListSettingKeys(ctx, "p%"); len(got) != 1 {
		t.Fatalf("p%% matched %v", got)
	}
	if got, _ := s.ListSettingKeys(ctx, "acme/attempt_"); len(got) != 0 {
		t.Fatalf("underscore is literal, got %v", got)
	}
	if err := s.DeleteSetting(ctx, "acme/attempt/a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSetting(ctx, "acme/attempt/a"); ok {
		t.Fatal("not deleted")
	}
	if err := s.DeleteSetting(ctx, "missing"); err != nil {
		t.Fatal(err)
	}
}
