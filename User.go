package client

// User describes the parameters relevant to a creating a User
type User struct {
	BirthDate              string            `json:"birthDate,omitempty"`
	Data                   map[string]string `json:"data,omitempty"`
	Email                  string            `json:"email,omitempty"`
	EncryptionScheme       string            `json:"encryptionScheme,omitempty"`
	Expiry                 int64             `json:"expiry,omitempty"`
	Factor                 string            `json:"factor,omitempty"`
	FirstName              string            `json:"firstName,omitempty"`
	FullName               string            `json:"fullName,omitempty"`
	ImageURL               string            `json:"imageUrl,omitempty"`
	LastName               string            `json:"lastName,omitempty"`
	MiddleName             string            `json:"middleName,omitempty"`
	MobilePhone            string            `json:"mobilePhone,omitempty"`
	Password               string            `json:"password,omitempty"`
	PasswordChangeRequired bool              `json:"passwordChangeRequired,omitempty"`
	PreferredLanguages     []string          `json:"preferredLanguages,omitempty"`
	Timezone               string            `json:"timezone,omitempty"`
	TwoFactorDelivery      string            `json:"twoFactorDelivery,omitempty"`
	TwoFactorEnabled       bool              `json:"twoFactorEnabled,omitempty"`
	TwoFactorSecret        string            `json:"twoFactorSecret,omitempty"`
	Username               string            `json:"username,omitempty"`
	UsernameStatus         string            `json:"usernameStatus,omitempty"`
}

// UserRequest describes the actual API request body to create a User
type UserRequest struct {
	SkipVerification     bool `json:"skipVerification,omitempty"`
	SendSetPasswordEmail bool `json:"sendSetPasswordEmail,omitempty"`
	User                 User `json:"user"`
}
