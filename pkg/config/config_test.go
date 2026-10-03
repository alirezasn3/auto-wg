package config

import (
	"reflect"
	"testing"
)

func TestParsePortSpecs(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []int
		wantErr bool
	}{
		{
			name:  "individual ports",
			specs: []string{"53", "80", "443"},
			want:  []int{53, 80, 443},
		},
		{
			name:  "port range",
			specs: []string{"20000-20003"},
			want:  []int{20000, 20001, 20002, 20003},
		},
		{
			name:  "mixed with duplicates",
			specs: []string{"53", "80", "53", "80-82"},
			want:  []int{53, 80, 81, 82},
		},
		{
			name:    "invalid port",
			specs:   []string{"abc"},
			wantErr: true,
		},
		{
			name:    "invalid range bounds",
			specs:   []string{"500-100"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortSpecs(tt.specs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePortSpecs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePortSpecs() = %v, want %v", got, tt.want)
			}
		})
	}
}
