package features

var numericNames = [...]string{
	"sample_present",
	"non_null_count_log",
	"null_fraction",
	"empty_fraction",
	"mean_length_log",
	"p95_length_log",
	"max_length_log",
	"sample_distinct_fraction",
	"ascii_fraction",
	"alphabetic_fraction",
	"numeric_fraction",
	"whitespace_fraction",
	"at_sign_fraction",
	"email_pattern_fraction",
	"phone_pattern_fraction",
	"uuid_pattern_fraction",
	"ip_pattern_fraction",
	"url_pattern_fraction",
	"iso_date_pattern_fraction",
	"payment_card_pattern_fraction",
	"secret_marker_fraction",
	"high_entropy_fraction",
	"json_object_fraction",
	"json_array_fraction",
	"multiline_fraction",
	"nullable",
	"primary_key",
	"foreign_key",
	"unique_constraint",
	"text_like",
	"numeric_like",
	"structured_like",
}

// NumericOrder returns a copy of the pinned numeric feature order.
func NumericOrder() []string { return append([]string(nil), numericNames[:]...) }
