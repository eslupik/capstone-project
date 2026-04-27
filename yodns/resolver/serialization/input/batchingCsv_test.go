package input

import (
	"bytes"
	"encoding/csv"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"reflect"
	"strings"
	"testing"
)

func TestBatchingCSV_Read_BatchSize(t *testing.T) {
	tests := []struct {
		name      string
		batchSize uint
		input     []string
		want      [][]Item
	}{
		{
			name:      "batch size 1",
			batchSize: 1,
			input: []string{
				"a.",
				"b.",
				"c.",
			},
			want: [][]Item{
				{
					{0, "a.", ""},
				},
				{
					{1, "b.", ""},
				},
				{
					{2, "c.", ""},
				},
			},
		},
		{
			name:      "batching regular",
			batchSize: 3,
			input: []string{
				"a.example.com.",
				"b.example.com.",
				"c.example.com.",
				"a.example.net.",
				"b.example.net.",
				"c.example.net.",
			},
			want: [][]Item{
				{
					{0, "a.example.com.", ""},
					{1, "b.example.com.", ""},
					{2, "c.example.com.", ""},
				},
				{
					{3, "a.example.net.", ""},
					{4, "b.example.net.", ""},
					{5, "c.example.net.", ""},
				},
			},
		},
		{
			name:      "batching irregular",
			batchSize: 3,
			input: []string{
				"a.example.com.",
				"b.example.com.",
				"a.example.net.",
				"b.example.net.",
				"c.example.net.",
				"a.example.org.",
				"b.b.example.org.",
				"c.c.c.example.org.",
				"d.d.d.d.example.org.",
			},
			want: [][]Item{
				{
					{0, "a.example.com.", ""},
					{1, "b.example.com.", ""},
				},
				{
					{2, "a.example.net.", ""},
					{3, "b.example.net.", ""},
					{4, "c.example.net.", ""},
				},
				{
					{5, "a.example.org.", ""},
					{6, "b.b.example.org.", ""},
					{7, "c.c.c.example.org.", ""},
				},
				{
					{8, "d.d.d.d.example.org.", ""},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openCSVReader = func(filePath string, separator rune) (*csv.Reader, func() error, error) {
				return csv.NewReader(bytes.NewReader([]byte(strings.Join(tt.input, "\n")))), func() error { return nil }, nil
			}

			var psl model.PSL
			psl.StorePublic("com.")
			psl.StorePublic("net.")
			psl.StorePublic("org.")

			in := BatchingCSV{
				BatchSize:      tt.batchSize,
				Len:            1000,
				Psl:            &psl,
				TagColumnIndex: 10,
			}

			c := in.Read(common.Background())

			idx := 0
			for batch := range c {
				if !reflect.DeepEqual(batch, tt.want[idx]) {
					t.Errorf("Read() = %v, want %v", batch, tt.want[idx])
				}
				idx++
			}
		})
	}
}
