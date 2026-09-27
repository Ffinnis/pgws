package classify

var labels = [...]string{
	"person_given_name",
	"person_family_name",
	"person_full_name",
	"email_address",
	"phone_number",
	"postal_address",
	"postal_code",
	"precise_location",
	"birth_date",
	"government_id",
	"financial_account",
	"payment_card",
	"credential",
	"network_identifier",
	"device_identifier",
	"person_identifier",
	"organization_name",
	"user_handle",
	"url",
	"free_text",
	"structured_payload",
	"business_identifier",
	"business_value",
	"other",
}

func Labels() []string { return append([]string(nil), labels[:]...) }
