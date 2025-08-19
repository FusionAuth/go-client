/*
* Copyright (c) 2019-2025, FusionAuth, All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
 */

package fusionauth

import (
	"fmt"
	"strings"
)

type StatusAble interface {
	SetStatus(status int)
}

/**
* Base Response which contains the HTTP status code
*
* @author Matthew Altman
 */
type BaseHTTPResponse struct {
	StatusCode int `json:"statusCode,omitempty"`
}

func (b *BaseHTTPResponse) SetStatus(status int) {
	b.StatusCode = status
}

type LinkedHashMap map[string]interface{}

/**
 * domain POJO to represent AuthenticationKey
 *
 * @author sanjay
 */
type APIKey struct {
	ExpirationInstant     int64             `json:"expirationInstant,omitempty"`
	Id                    string            `json:"id,omitempty"`
	InsertInstant         int64             `json:"insertInstant,omitempty"`
	IpAccessControlListId string            `json:"ipAccessControlListId,omitempty"`
	Key                   string            `json:"key,omitempty"`
	KeyManager            bool              `json:"keyManager"`
	LastUpdateInstant     int64             `json:"lastUpdateInstant,omitempty"`
	MetaData              APIKeyMetaData    `json:"metaData,omitempty"`
	Name                  string            `json:"name,omitempty"`
	Permissions           APIKeyPermissions `json:"permissions,omitempty"`
	Retrievable           bool              `json:"retrievable"`
	TenantId              string            `json:"tenantId,omitempty"`
}

type APIKeyMetaData struct {
	Attributes map[string]string `json:"attributes,omitempty"`
}

type APIKeyPermissions struct {
	Endpoints map[string][]string `json:"endpoints,omitempty"`
}

/**
 * Authentication key request object.
 *
 * @author Sanjay
 */
type APIKeyRequest struct {
	ApiKey      APIKey `json:"apiKey,omitempty"`
	SourceKeyId string `json:"sourceKeyId,omitempty"`
}

/**
 * Authentication key response object.
 *
 * @author Sanjay
 */
type APIKeyResponse struct {
	BaseHTTPResponse
	ApiKey APIKey `json:"apiKey,omitempty"`
}

func (b *APIKeyResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type AccessToken struct {
	BaseHTTPResponse
	AccessToken    string    `json:"access_token,omitempty"`
	ExpiresIn      int       `json:"expires_in,omitempty"`
	IdToken        string    `json:"id_token,omitempty"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
	RefreshTokenId string    `json:"refresh_token_id,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	TokenType      TokenType `json:"token_type,omitempty"`
	UserId         string    `json:"userId,omitempty"`
}

func (b *AccessToken) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The user action request object.
 *
 * @author Brian Pontarelli
 */
type ActionRequest struct {
	BaseEventRequest
	Action    ActionData `json:"action,omitempty"`
	Broadcast bool       `json:"broadcast"`
}

type ActionData struct {
	ActioneeUserId string   `json:"actioneeUserId,omitempty"`
	ActionerUserId string   `json:"actionerUserId,omitempty"`
	ApplicationIds []string `json:"applicationIds,omitempty"`
	Comment        string   `json:"comment,omitempty"`
	EmailUser      bool     `json:"emailUser"`
	Expiry         int64    `json:"expiry,omitempty"`
	NotifyUser     bool     `json:"notifyUser"`
	Option         string   `json:"option,omitempty"`
	ReasonId       string   `json:"reasonId,omitempty"`
	UserActionId   string   `json:"userActionId,omitempty"`
}

/**
 * The user action response object.
 *
 * @author Brian Pontarelli
 */
type ActionResponse struct {
	BaseHTTPResponse
	Action  UserActionLog   `json:"action,omitempty"`
	Actions []UserActionLog `json:"actions,omitempty"`
}

func (b *ActionResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
 *
 * @author Daniel DeGroff
 */
type Algorithm string

func (e Algorithm) String() string {
	return string(e)
}

const (
	Algorithm_ES256 Algorithm = "ES256"
	Algorithm_ES384 Algorithm = "ES384"
	Algorithm_ES512 Algorithm = "ES512"
	Algorithm_HS256 Algorithm = "HS256"
	Algorithm_HS384 Algorithm = "HS384"
	Algorithm_HS512 Algorithm = "HS512"
	Algorithm_PS256 Algorithm = "PS256"
	Algorithm_PS384 Algorithm = "PS384"
	Algorithm_PS512 Algorithm = "PS512"
	Algorithm_RS256 Algorithm = "RS256"
	Algorithm_RS384 Algorithm = "RS384"
	Algorithm_RS512 Algorithm = "RS512"
	Algorithm_None  Algorithm = "none"
)

/**
 * @author Daniel DeGroff
 */
type AppleApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	BundleId   string `json:"bundleId,omitempty"`
	ButtonText string `json:"buttonText,omitempty"`
	KeyId      string `json:"keyId,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ServicesId string `json:"servicesId,omitempty"`
	TeamId     string `json:"teamId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type AppleIdentityProvider struct {
	BaseIdentityProvider
	BundleId   string `json:"bundleId,omitempty"`
	ButtonText string `json:"buttonText,omitempty"`
	KeyId      string `json:"keyId,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ServicesId string `json:"servicesId,omitempty"`
	TeamId     string `json:"teamId,omitempty"`
}

/**
 * @author Seth Musselman
 */
type Application struct {
	AccessControlConfiguration       ApplicationAccessControlConfiguration      `json:"accessControlConfiguration,omitempty"`
	Active                           bool                                       `json:"active"`
	AuthenticationTokenConfiguration AuthenticationTokenConfiguration           `json:"authenticationTokenConfiguration,omitempty"`
	CleanSpeakConfiguration          CleanSpeakConfiguration                    `json:"cleanSpeakConfiguration,omitempty"`
	Data                             map[string]interface{}                     `json:"data,omitempty"`
	EmailConfiguration               ApplicationEmailConfiguration              `json:"emailConfiguration,omitempty"`
	ExternalIdentifierConfiguration  ApplicationExternalIdentifierConfiguration `json:"externalIdentifierConfiguration,omitempty"`
	FormConfiguration                ApplicationFormConfiguration               `json:"formConfiguration,omitempty"`
	Id                               string                                     `json:"id,omitempty"`
	InsertInstant                    int64                                      `json:"insertInstant,omitempty"`
	JwtConfiguration                 JWTConfiguration                           `json:"jwtConfiguration,omitempty"`
	LambdaConfiguration              LambdaConfiguration                        `json:"lambdaConfiguration,omitempty"`
	LastUpdateInstant                int64                                      `json:"lastUpdateInstant,omitempty"`
	LoginConfiguration               LoginConfiguration                         `json:"loginConfiguration,omitempty"`
	MultiFactorConfiguration         ApplicationMultiFactorConfiguration        `json:"multiFactorConfiguration,omitempty"`
	Name                             string                                     `json:"name,omitempty"`
	OauthConfiguration               OAuth2Configuration                        `json:"oauthConfiguration,omitempty"`
	PasswordlessConfiguration        PasswordlessConfiguration                  `json:"passwordlessConfiguration,omitempty"`
	PhoneConfiguration               ApplicationPhoneConfiguration              `json:"phoneConfiguration,omitempty"`
	RegistrationConfiguration        RegistrationConfiguration                  `json:"registrationConfiguration,omitempty"`
	RegistrationDeletePolicy         ApplicationRegistrationDeletePolicy        `json:"registrationDeletePolicy,omitempty"`
	Roles                            []ApplicationRole                          `json:"roles,omitempty"`
	Samlv2Configuration              SAMLv2Configuration                        `json:"samlv2Configuration,omitempty"`
	Scopes                           []ApplicationOAuthScope                    `json:"scopes,omitempty"`
	State                            ObjectState                                `json:"state,omitempty"`
	TenantId                         string                                     `json:"tenantId,omitempty"`
	ThemeId                          string                                     `json:"themeId,omitempty"`
	UniversalConfiguration           UniversalApplicationConfiguration          `json:"universalConfiguration,omitempty"`
	Unverified                       RegistrationUnverifiedOptions              `json:"unverified,omitempty"`
	VerificationEmailTemplateId      string                                     `json:"verificationEmailTemplateId,omitempty"`
	VerificationStrategy             VerificationStrategy                       `json:"verificationStrategy,omitempty"`
	VerifyRegistration               bool                                       `json:"verifyRegistration"`
	WebAuthnConfiguration            ApplicationWebAuthnConfiguration           `json:"webAuthnConfiguration,omitempty"`
}

type ApplicationEmailConfiguration struct {
	EmailUpdateEmailTemplateId           string `json:"emailUpdateEmailTemplateId,omitempty"`
	EmailVerificationEmailTemplateId     string `json:"emailVerificationEmailTemplateId,omitempty"`
	EmailVerifiedEmailTemplateId         string `json:"emailVerifiedEmailTemplateId,omitempty"`
	ForgotPasswordEmailTemplateId        string `json:"forgotPasswordEmailTemplateId,omitempty"`
	LoginIdInUseOnCreateEmailTemplateId  string `json:"loginIdInUseOnCreateEmailTemplateId,omitempty"`
	LoginIdInUseOnUpdateEmailTemplateId  string `json:"loginIdInUseOnUpdateEmailTemplateId,omitempty"`
	LoginNewDeviceEmailTemplateId        string `json:"loginNewDeviceEmailTemplateId,omitempty"`
	LoginSuspiciousEmailTemplateId       string `json:"loginSuspiciousEmailTemplateId,omitempty"`
	PasswordlessEmailTemplateId          string `json:"passwordlessEmailTemplateId,omitempty"`
	PasswordResetSuccessEmailTemplateId  string `json:"passwordResetSuccessEmailTemplateId,omitempty"`
	PasswordUpdateEmailTemplateId        string `json:"passwordUpdateEmailTemplateId,omitempty"`
	SetPasswordEmailTemplateId           string `json:"setPasswordEmailTemplateId,omitempty"`
	TwoFactorMethodAddEmailTemplateId    string `json:"twoFactorMethodAddEmailTemplateId,omitempty"`
	TwoFactorMethodRemoveEmailTemplateId string `json:"twoFactorMethodRemoveEmailTemplateId,omitempty"`
}

type AuthenticationTokenConfiguration struct {
	Enableable
}

type LambdaConfiguration struct {
	AccessTokenPopulateId               string `json:"accessTokenPopulateId,omitempty"`
	IdTokenPopulateId                   string `json:"idTokenPopulateId,omitempty"`
	Samlv2PopulateId                    string `json:"samlv2PopulateId,omitempty"`
	SelfServiceRegistrationValidationId string `json:"selfServiceRegistrationValidationId,omitempty"`
	UserinfoPopulateId                  string `json:"userinfoPopulateId,omitempty"`
}

type LoginConfiguration struct {
	AllowTokenRefresh     bool `json:"allowTokenRefresh"`
	GenerateRefreshTokens bool `json:"generateRefreshTokens"`
	RequireAuthentication bool `json:"requireAuthentication"`
}

type PasswordlessConfiguration struct {
	Enableable
}

type RegistrationConfiguration struct {
	Enableable
	BirthDate          Requirable       `json:"birthDate,omitempty"`
	ConfirmPassword    bool             `json:"confirmPassword"`
	FirstName          Requirable       `json:"firstName,omitempty"`
	FormId             string           `json:"formId,omitempty"`
	FullName           Requirable       `json:"fullName,omitempty"`
	LastName           Requirable       `json:"lastName,omitempty"`
	LoginIdType        LoginIdType      `json:"loginIdType,omitempty"`
	MiddleName         Requirable       `json:"middleName,omitempty"`
	MobilePhone        Requirable       `json:"mobilePhone,omitempty"`
	PreferredLanguages Requirable       `json:"preferredLanguages,omitempty"`
	Type               RegistrationType `json:"type,omitempty"`
}

// This is separate from IdentityType.
type LoginIdType string

func (e LoginIdType) String() string {
	return string(e)
}

const (
	LoginIdType_Email       LoginIdType = "email"
	LoginIdType_PhoneNumber LoginIdType = "phoneNumber"
	LoginIdType_Username    LoginIdType = "username"
)

type RegistrationType string

func (e RegistrationType) String() string {
	return string(e)
}

const (
	RegistrationType_Basic    RegistrationType = "basic"
	RegistrationType_Advanced RegistrationType = "advanced"
)

type SAMLv2Configuration struct {
	Enableable
	AssertionEncryptionConfiguration SAMLv2AssertionEncryptionConfiguration `json:"assertionEncryptionConfiguration,omitempty"`
	Audience                         string                                 `json:"audience,omitempty"`
	AuthorizedRedirectURLs           []string                               `json:"authorizedRedirectURLs,omitempty"`
	CallbackURL                      string                                 `json:"callbackURL,omitempty"`
	Debug                            bool                                   `json:"debug"`
	DefaultVerificationKeyId         string                                 `json:"defaultVerificationKeyId,omitempty"`
	InitiatedLogin                   SAMLv2IdPInitiatedLoginConfiguration   `json:"initiatedLogin,omitempty"`
	Issuer                           string                                 `json:"issuer,omitempty"`
	KeyId                            string                                 `json:"keyId,omitempty"`
	LoginHintConfiguration           LoginHintConfiguration                 `json:"loginHintConfiguration,omitempty"`
	Logout                           SAMLv2Logout                           `json:"logout,omitempty"`
	LogoutURL                        string                                 `json:"logoutURL,omitempty"`
	RequireSignedRequests            bool                                   `json:"requireSignedRequests"`
	XmlSignatureC14nMethod           CanonicalizationMethod                 `json:"xmlSignatureC14nMethod,omitempty"`
	XmlSignatureLocation             XMLSignatureLocation                   `json:"xmlSignatureLocation,omitempty"`
}

type SAMLLogoutBehavior string

func (e SAMLLogoutBehavior) String() string {
	return string(e)
}

const (
	SAMLLogoutBehavior_AllParticipants SAMLLogoutBehavior = "AllParticipants"
	SAMLLogoutBehavior_OnlyOriginator  SAMLLogoutBehavior = "OnlyOriginator"
)

type SAMLv2AssertionEncryptionConfiguration struct {
	Enableable
	DigestAlgorithm             string `json:"digestAlgorithm,omitempty"`
	EncryptionAlgorithm         string `json:"encryptionAlgorithm,omitempty"`
	KeyLocation                 string `json:"keyLocation,omitempty"`
	KeyTransportAlgorithm       string `json:"keyTransportAlgorithm,omitempty"`
	KeyTransportEncryptionKeyId string `json:"keyTransportEncryptionKeyId,omitempty"`
	MaskGenerationFunction      string `json:"maskGenerationFunction,omitempty"`
}

type SAMLv2Logout struct {
	Behavior                 SAMLLogoutBehavior     `json:"behavior,omitempty"`
	DefaultVerificationKeyId string                 `json:"defaultVerificationKeyId,omitempty"`
	KeyId                    string                 `json:"keyId,omitempty"`
	RequireSignedRequests    bool                   `json:"requireSignedRequests"`
	SingleLogout             SAMLv2SingleLogout     `json:"singleLogout,omitempty"`
	XmlSignatureC14nMethod   CanonicalizationMethod `json:"xmlSignatureC14nMethod,omitempty"`
}

type SAMLv2SingleLogout struct {
	Enableable
	KeyId                  string                 `json:"keyId,omitempty"`
	Url                    string                 `json:"url,omitempty"`
	XmlSignatureC14nMethod CanonicalizationMethod `json:"xmlSignatureC14nMethod,omitempty"`
}

type XMLSignatureLocation string

func (e XMLSignatureLocation) String() string {
	return string(e)
}

const (
	XMLSignatureLocation_Assertion XMLSignatureLocation = "Assertion"
	XMLSignatureLocation_Response  XMLSignatureLocation = "Response"
)

/**
 * @author Daniel DeGroff
 */
type ApplicationAccessControlConfiguration struct {
	UiIPAccessControlListId string `json:"uiIPAccessControlListId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ApplicationExternalIdentifierConfiguration struct {
	TwoFactorTrustIdTimeToLiveInSeconds int `json:"twoFactorTrustIdTimeToLiveInSeconds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ApplicationFormConfiguration struct {
	AdminRegistrationFormId      string                       `json:"adminRegistrationFormId,omitempty"`
	SelfServiceFormConfiguration SelfServiceFormConfiguration `json:"selfServiceFormConfiguration,omitempty"`
	SelfServiceFormId            string                       `json:"selfServiceFormId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ApplicationMultiFactorConfiguration struct {
	Email       MultiFactorEmailTemplate          `json:"email,omitempty"`
	LoginPolicy MultiFactorLoginPolicy            `json:"loginPolicy,omitempty"`
	Sms         MultiFactorSMSTemplate            `json:"sms,omitempty"`
	TrustPolicy ApplicationMultiFactorTrustPolicy `json:"trustPolicy,omitempty"`
}

type MultiFactorEmailTemplate struct {
	TemplateId string `json:"templateId,omitempty"`
}

type MultiFactorSMSTemplate struct {
	TemplateId string `json:"templateId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ApplicationMultiFactorTrustPolicy string

func (e ApplicationMultiFactorTrustPolicy) String() string {
	return string(e)
}

const (
	ApplicationMultiFactorTrustPolicy_Any  ApplicationMultiFactorTrustPolicy = "Any"
	ApplicationMultiFactorTrustPolicy_This ApplicationMultiFactorTrustPolicy = "This"
	ApplicationMultiFactorTrustPolicy_None ApplicationMultiFactorTrustPolicy = "None"
)

/**
 * A custom OAuth scope for a specific application.
 *
 * @author Spencer Witt
 */
type ApplicationOAuthScope struct {
	ApplicationId         string                 `json:"applicationId,omitempty"`
	Data                  map[string]interface{} `json:"data,omitempty"`
	DefaultConsentDetail  string                 `json:"defaultConsentDetail,omitempty"`
	DefaultConsentMessage string                 `json:"defaultConsentMessage,omitempty"`
	Description           string                 `json:"description,omitempty"`
	Id                    string                 `json:"id,omitempty"`
	InsertInstant         int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant     int64                  `json:"lastUpdateInstant,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	Required              bool                   `json:"required"`
}

/**
 * The Application Scope API request object.
 *
 * @author Spencer Witt
 */
type ApplicationOAuthScopeRequest struct {
	Scope ApplicationOAuthScope `json:"scope,omitempty"`
}

/**
 * The Application Scope API response.
 *
 * @author Spencer Witt
 */
type ApplicationOAuthScopeResponse struct {
	BaseHTTPResponse
	Scope ApplicationOAuthScope `json:"scope,omitempty"`
}

func (b *ApplicationOAuthScopeResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Hold application phone configuration for template overrides.
 */
type ApplicationPhoneConfiguration struct {
	ForgotPasswordTemplateId        string `json:"forgotPasswordTemplateId,omitempty"`
	IdentityUpdateTemplateId        string `json:"identityUpdateTemplateId,omitempty"`
	LoginIdInUseOnCreateTemplateId  string `json:"loginIdInUseOnCreateTemplateId,omitempty"`
	LoginIdInUseOnUpdateTemplateId  string `json:"loginIdInUseOnUpdateTemplateId,omitempty"`
	LoginNewDeviceTemplateId        string `json:"loginNewDeviceTemplateId,omitempty"`
	LoginSuspiciousTemplateId       string `json:"loginSuspiciousTemplateId,omitempty"`
	PasswordlessTemplateId          string `json:"passwordlessTemplateId,omitempty"`
	PasswordResetSuccessTemplateId  string `json:"passwordResetSuccessTemplateId,omitempty"`
	PasswordUpdateTemplateId        string `json:"passwordUpdateTemplateId,omitempty"`
	SetPasswordTemplateId           string `json:"setPasswordTemplateId,omitempty"`
	TwoFactorMethodAddTemplateId    string `json:"twoFactorMethodAddTemplateId,omitempty"`
	TwoFactorMethodRemoveTemplateId string `json:"twoFactorMethodRemoveTemplateId,omitempty"`
	VerificationCompleteTemplateId  string `json:"verificationCompleteTemplateId,omitempty"`
	VerificationTemplateId          string `json:"verificationTemplateId,omitempty"`
}

/**
 * A Application-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
type ApplicationRegistrationDeletePolicy struct {
	Unverified TimeBasedDeletePolicy `json:"unverified,omitempty"`
}

/**
 * The Application API request object.
 *
 * @author Brian Pontarelli
 */
type ApplicationRequest struct {
	BaseEventRequest
	Application         Application     `json:"application,omitempty"`
	Role                ApplicationRole `json:"role,omitempty"`
	SourceApplicationId string          `json:"sourceApplicationId,omitempty"`
}

/**
 * The Application API response.
 *
 * @author Brian Pontarelli
 */
type ApplicationResponse struct {
	BaseHTTPResponse
	Application  Application     `json:"application,omitempty"`
	Applications []Application   `json:"applications,omitempty"`
	Role         ApplicationRole `json:"role,omitempty"`
}

func (b *ApplicationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * A role given to a user for a specific application.
 *
 * @author Seth Musselman
 */
type ApplicationRole struct {
	Description       string `json:"description,omitempty"`
	Id                string `json:"id,omitempty"`
	InsertInstant     int64  `json:"insertInstant,omitempty"`
	IsDefault         bool   `json:"isDefault"`
	IsSuperRole       bool   `json:"isSuperRole"`
	LastUpdateInstant int64  `json:"lastUpdateInstant,omitempty"`
	Name              string `json:"name,omitempty"`
}

/**
 * Search criteria for Applications
 *
 * @author Spencer Witt
 */
type ApplicationSearchCriteria struct {
	BaseSearchCriteria
	Name     string      `json:"name,omitempty"`
	State    ObjectState `json:"state,omitempty"`
	TenantId string      `json:"tenantId,omitempty"`
}

/**
 * Search request for Applications
 *
 * @author Spencer Witt
 */
type ApplicationSearchRequest struct {
	ExpandableRequest
	Search ApplicationSearchCriteria `json:"search,omitempty"`
}

/**
 * Application search response
 *
 * @author Spencer Witt
 */
type ApplicationSearchResponse struct {
	BaseHTTPResponse
	ExpandableResponse
	Applications []Application `json:"applications,omitempty"`
	Total        int64         `json:"total,omitempty"`
}

func (b *ApplicationSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Application-level configuration for WebAuthn
 *
 * @author Daniel DeGroff
 */
type ApplicationWebAuthnConfiguration struct {
	Enableable
	BootstrapWorkflow        ApplicationWebAuthnWorkflowConfiguration `json:"bootstrapWorkflow,omitempty"`
	ReauthenticationWorkflow ApplicationWebAuthnWorkflowConfiguration `json:"reauthenticationWorkflow,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ApplicationWebAuthnWorkflowConfiguration struct {
	Enableable
}

/**
 * This class is a simple attachment with a byte array, name and MIME type.
 *
 * @author Brian Pontarelli
 */
type Attachment struct {
	Attachment []byte `json:"attachment,omitempty"`
	Mime       string `json:"mime,omitempty"`
	Name       string `json:"name,omitempty"`
}

/**
 * Used to communicate whether and how authenticator attestation should be delivered to the Relying Party
 *
 * @author Spencer Witt
 */
type AttestationConveyancePreference string

func (e AttestationConveyancePreference) String() string {
	return string(e)
}

const (
	AttestationConveyancePreference_None       AttestationConveyancePreference = "none"
	AttestationConveyancePreference_Indirect   AttestationConveyancePreference = "indirect"
	AttestationConveyancePreference_Direct     AttestationConveyancePreference = "direct"
	AttestationConveyancePreference_Enterprise AttestationConveyancePreference = "enterprise"
)

/**
 * Used to indicate what type of attestation was included in the authenticator response for a given WebAuthn credential at the time it was created
 *
 * @author Spencer Witt
 */
type AttestationType string

func (e AttestationType) String() string {
	return string(e)
}

const (
	AttestationType_Basic           AttestationType = "basic"
	AttestationType_Self            AttestationType = "self"
	AttestationType_AttestationCa   AttestationType = "attestationCa"
	AttestationType_AnonymizationCa AttestationType = "anonymizationCa"
	AttestationType_None            AttestationType = "none"
)

/**
 * An audit log.
 *
 * @author Brian Pontarelli
 */
type AuditLog struct {
	Data          map[string]interface{} `json:"data,omitempty"`
	Id            int64                  `json:"id,omitempty"`
	InsertInstant int64                  `json:"insertInstant,omitempty"`
	InsertUser    string                 `json:"insertUser,omitempty"`
	Message       string                 `json:"message,omitempty"`
	NewValue      interface{}            `json:"newValue,omitempty"`
	OldValue      interface{}            `json:"oldValue,omitempty"`
	Reason        string                 `json:"reason,omitempty"`
}

/**
 * Event to indicate an audit log was created.
 *
 * @author Daniel DeGroff
 */
type AuditLogCreateEvent struct {
	BaseEvent
	AuditLog AuditLog `json:"auditLog,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type AuditLogExportRequest struct {
	BaseExportRequest
	Criteria AuditLogSearchCriteria `json:"criteria,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type AuditLogRequest struct {
	BaseEventRequest
	AuditLog AuditLog `json:"auditLog,omitempty"`
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
type AuditLogResponse struct {
	BaseHTTPResponse
	AuditLog AuditLog `json:"auditLog,omitempty"`
}

func (b *AuditLogResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type AuditLogSearchCriteria struct {
	BaseSearchCriteria
	End      int64  `json:"end,omitempty"`
	Message  string `json:"message,omitempty"`
	NewValue string `json:"newValue,omitempty"`
	OldValue string `json:"oldValue,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Start    int64  `json:"start,omitempty"`
	User     string `json:"user,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type AuditLogSearchRequest struct {
	Search AuditLogSearchCriteria `json:"search,omitempty"`
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
type AuditLogSearchResponse struct {
	BaseHTTPResponse
	AuditLogs []AuditLog `json:"auditLogs,omitempty"`
	Total     int64      `json:"total,omitempty"`
}

func (b *AuditLogSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brett Pontarelli
 */
type AuthenticationThreats string

func (e AuthenticationThreats) String() string {
	return string(e)
}

const (
	AuthenticationThreats_ImpossibleTravel AuthenticationThreats = "ImpossibleTravel"
)

/**
 * Describes the <a href="https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality">authenticator attachment modality</a>.
 *
 * @author Spencer Witt
 */
type AuthenticatorAttachment string

func (e AuthenticatorAttachment) String() string {
	return string(e)
}

const (
	AuthenticatorAttachment_Platform      AuthenticatorAttachment = "platform"
	AuthenticatorAttachment_CrossPlatform AuthenticatorAttachment = "crossPlatform"
)

/**
 * Describes the authenticator attachment modality preference for a WebAuthn workflow. See {@link AuthenticatorAttachment}
 *
 * @author Spencer Witt
 */
type AuthenticatorAttachmentPreference string

func (e AuthenticatorAttachmentPreference) String() string {
	return string(e)
}

const (
	AuthenticatorAttachmentPreference_Any           AuthenticatorAttachmentPreference = "any"
	AuthenticatorAttachmentPreference_Platform      AuthenticatorAttachmentPreference = "platform"
	AuthenticatorAttachmentPreference_CrossPlatform AuthenticatorAttachmentPreference = "crossPlatform"
)

/**
 * @author Daniel DeGroff
 */
type AuthenticatorConfiguration struct {
	Algorithm  TOTPAlgorithm `json:"algorithm,omitempty"`
	CodeLength int           `json:"codeLength,omitempty"`
	TimeStep   int           `json:"timeStep,omitempty"`
}

type TOTPAlgorithm string

func (e TOTPAlgorithm) String() string {
	return string(e)
}

const (
	TOTPAlgorithm_HmacSHA1   TOTPAlgorithm = "HmacSHA1"
	TOTPAlgorithm_HmacSHA256 TOTPAlgorithm = "HmacSHA256"
	TOTPAlgorithm_HmacSHA512 TOTPAlgorithm = "HmacSHA512"
)

/**
 * Used by the Relying Party to specify their requirements for authenticator attributes. Fields use the deprecated "resident key" terminology to refer
 * to client-side discoverable credentials to maintain backwards compatibility with WebAuthn Level 1.
 *
 * @author Spencer Witt
 */
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool                        `json:"requireResidentKey"`
	ResidentKey             ResidentKeyRequirement      `json:"residentKey,omitempty"`
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
type BaseConnectorConfiguration struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Debug             bool                   `json:"debug"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Type              ConnectorType          `json:"type,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type BaseElasticSearchCriteria struct {
	BaseSearchCriteria
	AccurateTotal bool        `json:"accurateTotal"`
	Ids           []string    `json:"ids,omitempty"`
	NextResults   string      `json:"nextResults,omitempty"`
	Query         string      `json:"query,omitempty"`
	QueryString   string      `json:"queryString,omitempty"`
	SortFields    []SortField `json:"sortFields,omitempty"`
}

/**
 * Base class for all FusionAuth events.
 *
 * @author Brian Pontarelli
 */
type BaseEvent struct {
	CreateInstant int64     `json:"createInstant,omitempty"`
	Id            string    `json:"id,omitempty"`
	Info          EventInfo `json:"info,omitempty"`
	TenantId      string    `json:"tenantId,omitempty"`
	Type          EventType `json:"type,omitempty"`
}

/**
 * Base class for requests that can contain event information. This event information is used when sending Webhooks or emails
 * during the transaction. The caller is responsible for ensuring that the event information is correct.
 *
 * @author Brian Pontarelli
 */
type BaseEventRequest struct {
	EventInfo EventInfo `json:"eventInfo,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseExportRequest struct {
	DateTimeSecondsFormat string `json:"dateTimeSecondsFormat,omitempty"`
	ZoneId                string `json:"zoneId,omitempty"`
}

/**
 * Base class for all {@link Group} and {@link GroupMember} events.
 *
 * @author Spencer Witt
 */
type BaseGroupEvent struct {
	BaseEvent
	Group Group `json:"group,omitempty"`
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
type BaseIdentityProvider struct {
	Enableable
	ApplicationConfiguration map[string]interface{}                         `json:"applicationConfiguration,omitempty"`
	Data                     map[string]interface{}                         `json:"data,omitempty"`
	Debug                    bool                                           `json:"debug"`
	Id                       string                                         `json:"id,omitempty"`
	InsertInstant            int64                                          `json:"insertInstant,omitempty"`
	LambdaConfiguration      ProviderLambdaConfiguration                    `json:"lambdaConfiguration,omitempty"`
	LastUpdateInstant        int64                                          `json:"lastUpdateInstant,omitempty"`
	LinkingStrategy          IdentityProviderLinkingStrategy                `json:"linkingStrategy,omitempty"`
	Name                     string                                         `json:"name,omitempty"`
	TenantConfiguration      map[string]IdentityProviderTenantConfiguration `json:"tenantConfiguration,omitempty"`
	Type                     IdentityProviderType                           `json:"type,omitempty"`
}

type ProviderLambdaConfiguration struct {
	ReconcileId string `json:"reconcileId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseIdentityProviderApplicationConfiguration struct {
	Enableable
	CreateRegistration bool                   `json:"createRegistration"`
	Data               map[string]interface{} `json:"data,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseLoginRequest struct {
	BaseEventRequest
	ApplicationId string   `json:"applicationId,omitempty"`
	IpAddress     string   `json:"ipAddress,omitempty"`
	MetaData      MetaData `json:"metaData,omitempty"`
	NewDevice     bool     `json:"newDevice"`
	NoJWT         bool     `json:"noJWT"`
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
type BaseMessengerConfiguration struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Debug             bool                   `json:"debug"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Transport         string                 `json:"transport,omitempty"`
	Type              MessengerType          `json:"type,omitempty"`
}

/**
 * @author Lyle Schemmerling
 */
type BaseSAMLv2IdentityProvider struct {
	BaseIdentityProvider
	AssertionDecryptionConfiguration SAMLv2AssertionDecryptionConfiguration `json:"assertionDecryptionConfiguration,omitempty"`
	EmailClaim                       string                                 `json:"emailClaim,omitempty"`
	KeyId                            string                                 `json:"keyId,omitempty"`
	UniqueIdClaim                    string                                 `json:"uniqueIdClaim,omitempty"`
	UseNameIdForEmail                bool                                   `json:"useNameIdForEmail"`
	UsernameClaim                    string                                 `json:"usernameClaim,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type BaseSearchCriteria struct {
	NumberOfResults int    `json:"numberOfResults,omitempty"`
	OrderBy         string `json:"orderBy,omitempty"`
	StartRow        int    `json:"startRow,omitempty"`
}

/**
 * Base class for all {@link User}-related events.
 *
 * @author Spencer Witt
 */
type BaseUserEvent struct {
	BaseEvent
	User User `json:"user,omitempty"`
}

type IdentityInfo struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BreachedPasswordStatus string

func (e BreachedPasswordStatus) String() string {
	return string(e)
}

const (
	BreachedPasswordStatus_None            BreachedPasswordStatus = "None"
	BreachedPasswordStatus_ExactMatch      BreachedPasswordStatus = "ExactMatch"
	BreachedPasswordStatus_SubAddressMatch BreachedPasswordStatus = "SubAddressMatch"
	BreachedPasswordStatus_PasswordOnly    BreachedPasswordStatus = "PasswordOnly"
	BreachedPasswordStatus_CommonPassword  BreachedPasswordStatus = "CommonPassword"
)

/**
 * @author Daniel DeGroff
 */
type BreachedPasswordTenantMetric struct {
	ActionRequired             int `json:"actionRequired,omitempty"`
	MatchedCommonPasswordCount int `json:"matchedCommonPasswordCount,omitempty"`
	MatchedExactCount          int `json:"matchedExactCount,omitempty"`
	MatchedPasswordCount       int `json:"matchedPasswordCount,omitempty"`
	MatchedSubAddressCount     int `json:"matchedSubAddressCount,omitempty"`
	PasswordsCheckedCount      int `json:"passwordsCheckedCount,omitempty"`
}

/**
 * @author Trevor Smith
 */
type CORSConfiguration struct {
	Enableable
	AllowCredentials         bool         `json:"allowCredentials"`
	AllowedHeaders           []string     `json:"allowedHeaders,omitempty"`
	AllowedMethods           []HTTPMethod `json:"allowedMethods,omitempty"`
	AllowedOrigins           []string     `json:"allowedOrigins,omitempty"`
	Debug                    bool         `json:"debug"`
	ExposedHeaders           []string     `json:"exposedHeaders,omitempty"`
	PreflightMaxAgeInSeconds int          `json:"preflightMaxAgeInSeconds,omitempty"`
}

/**
 * XML canonicalization method enumeration. This is used for the IdP and SP side of FusionAuth SAML.
 *
 * @author Brian Pontarelli
 */
type CanonicalizationMethod string

func (e CanonicalizationMethod) String() string {
	return string(e)
}

const (
	CanonicalizationMethod_Exclusive             CanonicalizationMethod = "exclusive"
	CanonicalizationMethod_ExclusiveWithComments CanonicalizationMethod = "exclusive_with_comments"
	CanonicalizationMethod_Inclusive             CanonicalizationMethod = "inclusive"
	CanonicalizationMethod_InclusiveWithComments CanonicalizationMethod = "inclusive_with_comments"
)

/**
 * @author Brett Pontarelli
 */
type CaptchaMethod string

func (e CaptchaMethod) String() string {
	return string(e)
}

const (
	CaptchaMethod_GoogleRecaptchaV2  CaptchaMethod = "GoogleRecaptchaV2"
	CaptchaMethod_GoogleRecaptchaV3  CaptchaMethod = "GoogleRecaptchaV3"
	CaptchaMethod_HCaptcha           CaptchaMethod = "HCaptcha"
	CaptchaMethod_HCaptchaEnterprise CaptchaMethod = "HCaptchaEnterprise"
)

/**
 * @author Trevor Smith
 */
type ChangePasswordReason string

func (e ChangePasswordReason) String() string {
	return string(e)
}

const (
	ChangePasswordReason_Administrative ChangePasswordReason = "Administrative"
	ChangePasswordReason_Breached       ChangePasswordReason = "Breached"
	ChangePasswordReason_Expired        ChangePasswordReason = "Expired"
	ChangePasswordReason_Validation     ChangePasswordReason = "Validation"
)

/**
 * Change password request object.
 *
 * @author Brian Pontarelli
 */
type ChangePasswordRequest struct {
	BaseEventRequest
	ApplicationId    string   `json:"applicationId,omitempty"`
	ChangePasswordId string   `json:"changePasswordId,omitempty"`
	CurrentPassword  string   `json:"currentPassword,omitempty"`
	LoginId          string   `json:"loginId,omitempty"`
	LoginIdTypes     []string `json:"loginIdTypes,omitempty"`
	Password         string   `json:"password,omitempty"`
	RefreshToken     string   `json:"refreshToken,omitempty"`
	TrustChallenge   string   `json:"trustChallenge,omitempty"`
	TrustToken       string   `json:"trustToken,omitempty"`
}

/**
 * Change password response object.
 *
 * @author Daniel DeGroff
 */
type ChangePasswordResponse struct {
	BaseHTTPResponse
	OneTimePassword string                 `json:"oneTimePassword,omitempty"`
	State           map[string]interface{} `json:"state,omitempty"`
}

func (b *ChangePasswordResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * CleanSpeak configuration at the system and application level.
 *
 * @author Brian Pontarelli
 */
type CleanSpeakConfiguration struct {
	Enableable
	ApiKey             string             `json:"apiKey,omitempty"`
	ApplicationIds     []string           `json:"applicationIds,omitempty"`
	Url                string             `json:"url,omitempty"`
	UsernameModeration UsernameModeration `json:"usernameModeration,omitempty"`
}

type UsernameModeration struct {
	Enableable
	ApplicationId string `json:"applicationId,omitempty"`
}

/**
 * @author Brett Guy
 */
type ClientAuthenticationPolicy string

func (e ClientAuthenticationPolicy) String() string {
	return string(e)
}

const (
	ClientAuthenticationPolicy_Required                 ClientAuthenticationPolicy = "Required"
	ClientAuthenticationPolicy_NotRequired              ClientAuthenticationPolicy = "NotRequired"
	ClientAuthenticationPolicy_NotRequiredWhenUsingPKCE ClientAuthenticationPolicy = "NotRequiredWhenUsingPKCE"
)

/**
 * @author Trevor Smith
 */
type ConnectorPolicy struct {
	ConnectorId string                 `json:"connectorId,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Domains     []string               `json:"domains,omitempty"`
	Migrate     bool                   `json:"migrate"`
}

/**
 * @author Trevor Smith
 */
type ConnectorRequest struct {
	Connector BaseConnectorConfiguration `json:"connector,omitempty"`
}

/**
 * @author Trevor Smith
 */
type ConnectorResponse struct {
	BaseHTTPResponse
	Connector  BaseConnectorConfiguration   `json:"connector,omitempty"`
	Connectors []BaseConnectorConfiguration `json:"connectors,omitempty"`
}

func (b *ConnectorResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The types of connectors. This enum is stored as an ordinal on the <code>identities</code> table, order must be maintained.
 *
 * @author Trevor Smith
 */
type ConnectorType string

func (e ConnectorType) String() string {
	return string(e)
}

const (
	ConnectorType_FusionAuth ConnectorType = "FusionAuth"
	ConnectorType_Generic    ConnectorType = "Generic"
	ConnectorType_LDAP       ConnectorType = "LDAP"
)

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
type Consent struct {
	ConsentEmailTemplateId          string                 `json:"consentEmailTemplateId,omitempty"`
	CountryMinimumAgeForSelfConsent map[string]int         `json:"countryMinimumAgeForSelfConsent,omitempty"`
	Data                            map[string]interface{} `json:"data,omitempty"`
	DefaultMinimumAgeForSelfConsent int                    `json:"defaultMinimumAgeForSelfConsent,omitempty"`
	EmailPlus                       EmailPlus              `json:"emailPlus,omitempty"`
	Id                              string                 `json:"id,omitempty"`
	InsertInstant                   int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant               int64                  `json:"lastUpdateInstant,omitempty"`
	MultipleValuesAllowed           bool                   `json:"multipleValuesAllowed"`
	Name                            string                 `json:"name,omitempty"`
	Values                          []string               `json:"values,omitempty"`
}

type EmailPlus struct {
	Enableable
	EmailTemplateId               string `json:"emailTemplateId,omitempty"`
	MaximumTimeToSendEmailInHours int    `json:"maximumTimeToSendEmailInHours,omitempty"`
	MinimumTimeToSendEmailInHours int    `json:"minimumTimeToSendEmailInHours,omitempty"`
}

/**
 * API request for User consent types.
 *
 * @author Daniel DeGroff
 */
type ConsentRequest struct {
	Consent Consent `json:"consent,omitempty"`
}

/**
 * API response for consent.
 *
 * @author Daniel DeGroff
 */
type ConsentResponse struct {
	BaseHTTPResponse
	Consent  Consent   `json:"consent,omitempty"`
	Consents []Consent `json:"consents,omitempty"`
}

func (b *ConsentResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Consents
 *
 * @author Spencer Witt
 */
type ConsentSearchCriteria struct {
	BaseSearchCriteria
	Name string `json:"name,omitempty"`
}

/**
 * Search request for Consents
 *
 * @author Spencer Witt
 */
type ConsentSearchRequest struct {
	Search ConsentSearchCriteria `json:"search,omitempty"`
}

/**
 * Consent search response
 *
 * @author Spencer Witt
 */
type ConsentSearchResponse struct {
	BaseHTTPResponse
	Consents []Consent `json:"consents,omitempty"`
	Total    int64     `json:"total,omitempty"`
}

func (b *ConsentSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
type ConsentStatus string

func (e ConsentStatus) String() string {
	return string(e)
}

const (
	ConsentStatus_Active  ConsentStatus = "Active"
	ConsentStatus_Revoked ConsentStatus = "Revoked"
)

/**
 * Status for content like usernames, profile attributes, etc.
 *
 * @author Brian Pontarelli
 */
type ContentStatus string

func (e ContentStatus) String() string {
	return string(e)
}

const (
	ContentStatus_ACTIVE   ContentStatus = "ACTIVE"
	ContentStatus_PENDING  ContentStatus = "PENDING"
	ContentStatus_REJECTED ContentStatus = "REJECTED"
)

/**
 * A number identifying a cryptographic algorithm. Values should be registered with the <a
 * href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>
 *
 * @author Spencer Witt
 */
type CoseAlgorithmIdentifier string

func (e CoseAlgorithmIdentifier) String() string {
	return string(e)
}

const (
	CoseAlgorithmIdentifier_ES256 CoseAlgorithmIdentifier = "ES256"
	CoseAlgorithmIdentifier_ES384 CoseAlgorithmIdentifier = "ES384"
	CoseAlgorithmIdentifier_ES512 CoseAlgorithmIdentifier = "ES512"
	CoseAlgorithmIdentifier_RS256 CoseAlgorithmIdentifier = "RS256"
	CoseAlgorithmIdentifier_RS384 CoseAlgorithmIdentifier = "RS384"
	CoseAlgorithmIdentifier_RS512 CoseAlgorithmIdentifier = "RS512"
	CoseAlgorithmIdentifier_PS256 CoseAlgorithmIdentifier = "PS256"
	CoseAlgorithmIdentifier_PS384 CoseAlgorithmIdentifier = "PS384"
	CoseAlgorithmIdentifier_PS512 CoseAlgorithmIdentifier = "PS512"
)

/**
 * COSE Elliptic Curve identifier to determine which elliptic curve to use with a given key
 *
 * @author Spencer Witt
 */
type CoseEllipticCurve string

func (e CoseEllipticCurve) String() string {
	return string(e)
}

const (
	CoseEllipticCurve_Reserved  CoseEllipticCurve = "Reserved"
	CoseEllipticCurve_P256      CoseEllipticCurve = "P256"
	CoseEllipticCurve_P384      CoseEllipticCurve = "P384"
	CoseEllipticCurve_P521      CoseEllipticCurve = "P521"
	CoseEllipticCurve_X25519    CoseEllipticCurve = "X25519"
	CoseEllipticCurve_X448      CoseEllipticCurve = "X448"
	CoseEllipticCurve_Ed25519   CoseEllipticCurve = "Ed25519"
	CoseEllipticCurve_Ed448     CoseEllipticCurve = "Ed448"
	CoseEllipticCurve_Secp256k1 CoseEllipticCurve = "Secp256k1"
)

/**
 * COSE key type
 *
 * @author Spencer Witt
 */
type CoseKeyType string

func (e CoseKeyType) String() string {
	return string(e)
}

const (
	CoseKeyType_Reserved  CoseKeyType = "Reserved"
	CoseKeyType_OKP       CoseKeyType = "OKP"
	CoseKeyType_EC2       CoseKeyType = "EC2"
	CoseKeyType_RSA       CoseKeyType = "RSA"
	CoseKeyType_Symmetric CoseKeyType = "Symmetric"
)

/**
 * @author Brian Pontarelli
 */
type Count struct {
	Count    int `json:"count,omitempty"`
	Interval int `json:"interval,omitempty"`
}

/**
 * Contains the output for the {@code credProps} extension
 *
 * @author Spencer Witt
 */
type CredentialPropertiesOutput struct {
	Rk bool `json:"rk"`
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
type DailyActiveUserReportResponse struct {
	BaseHTTPResponse
	DailyActiveUsers []Count `json:"dailyActiveUsers,omitempty"`
	Total            int64   `json:"total,omitempty"`
}

func (b *DailyActiveUserReportResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type DeviceApprovalResponse struct {
	BaseHTTPResponse
	DeviceGrantStatus    string               `json:"deviceGrantStatus,omitempty"`
	DeviceInfo           DeviceInfo           `json:"deviceInfo,omitempty"`
	IdentityProviderLink IdentityProviderLink `json:"identityProviderLink,omitempty"`
	TenantId             string               `json:"tenantId,omitempty"`
	UserId               string               `json:"userId,omitempty"`
}

func (b *DeviceApprovalResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type DeviceInfo struct {
	Description         string `json:"description,omitempty"`
	LastAccessedAddress string `json:"lastAccessedAddress,omitempty"`
	LastAccessedInstant int64  `json:"lastAccessedInstant,omitempty"`
	Name                string `json:"name,omitempty"`
	Type                string `json:"type,omitempty"`
}

type DeviceType string

func (e DeviceType) String() string {
	return string(e)
}

const (
	DeviceType_BROWSER DeviceType = "BROWSER"
	DeviceType_DESKTOP DeviceType = "DESKTOP"
	DeviceType_LAPTOP  DeviceType = "LAPTOP"
	DeviceType_MOBILE  DeviceType = "MOBILE"
	DeviceType_OTHER   DeviceType = "OTHER"
	DeviceType_SERVER  DeviceType = "SERVER"
	DeviceType_TABLET  DeviceType = "TABLET"
	DeviceType_TV      DeviceType = "TV"
	DeviceType_UNKNOWN DeviceType = "UNKNOWN"
)

/**
 * @author Trevor Smith
 */
type DeviceResponse struct {
	BaseHTTPResponse
	DeviceCode              string `json:"device_code,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationUri         string `json:"verification_uri,omitempty"`
	VerificationUriComplete string `json:"verification_uri_complete,omitempty"`
}

func (b *DeviceResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type DeviceUserCodeResponse struct {
	BaseHTTPResponse
	ClientId       string         `json:"client_id,omitempty"`
	DeviceInfo     DeviceInfo     `json:"deviceInfo,omitempty"`
	ExpiresIn      int            `json:"expires_in,omitempty"`
	PendingIdPLink PendingIdPLink `json:"pendingIdPLink,omitempty"`
	Scope          string         `json:"scope,omitempty"`
	TenantId       string         `json:"tenantId,omitempty"`
	UserCode       string         `json:"user_code,omitempty"`
}

func (b *DeviceUserCodeResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * A displayable raw login that includes application name and user loginId.
 *
 * @author Brian Pontarelli
 */
type DisplayableRawLogin struct {
	RawLogin
	ApplicationName string   `json:"applicationName,omitempty"`
	Location        Location `json:"location,omitempty"`
	LoginId         string   `json:"loginId,omitempty"`
	LoginIdType     string   `json:"loginIdType,omitempty"`
}

/**
 * Interface for all identity providers that can be domain based.
 */
type DomainBasedIdentityProvider struct {
}

/**
 * This class is an abstraction of a simple email message.
 *
 * @author Brian Pontarelli
 */
type Email struct {
	Attachments []Attachment   `json:"attachments,omitempty"`
	Bcc         []EmailAddress `json:"bcc,omitempty"`
	Cc          []EmailAddress `json:"cc,omitempty"`
	From        EmailAddress   `json:"from,omitempty"`
	Html        string         `json:"html,omitempty"`
	ReplyTo     EmailAddress   `json:"replyTo,omitempty"`
	Subject     string         `json:"subject,omitempty"`
	Text        string         `json:"text,omitempty"`
	To          []EmailAddress `json:"to,omitempty"`
}

/**
 * An email address.
 *
 * @author Brian Pontarelli
 */
type EmailAddress struct {
	Address string `json:"address,omitempty"`
	Display string `json:"display,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type EmailConfiguration struct {
	AdditionalHeaders                    []EmailHeader          `json:"additionalHeaders,omitempty"`
	Debug                                bool                   `json:"debug"`
	DefaultFromEmail                     string                 `json:"defaultFromEmail,omitempty"`
	DefaultFromName                      string                 `json:"defaultFromName,omitempty"`
	EmailUpdateEmailTemplateId           string                 `json:"emailUpdateEmailTemplateId,omitempty"`
	EmailVerifiedEmailTemplateId         string                 `json:"emailVerifiedEmailTemplateId,omitempty"`
	ForgotPasswordEmailTemplateId        string                 `json:"forgotPasswordEmailTemplateId,omitempty"`
	Host                                 string                 `json:"host,omitempty"`
	ImplicitEmailVerificationAllowed     bool                   `json:"implicitEmailVerificationAllowed"`
	LoginIdInUseOnCreateEmailTemplateId  string                 `json:"loginIdInUseOnCreateEmailTemplateId,omitempty"`
	LoginIdInUseOnUpdateEmailTemplateId  string                 `json:"loginIdInUseOnUpdateEmailTemplateId,omitempty"`
	LoginNewDeviceEmailTemplateId        string                 `json:"loginNewDeviceEmailTemplateId,omitempty"`
	LoginSuspiciousEmailTemplateId       string                 `json:"loginSuspiciousEmailTemplateId,omitempty"`
	Password                             string                 `json:"password,omitempty"`
	PasswordlessEmailTemplateId          string                 `json:"passwordlessEmailTemplateId,omitempty"`
	PasswordResetSuccessEmailTemplateId  string                 `json:"passwordResetSuccessEmailTemplateId,omitempty"`
	PasswordUpdateEmailTemplateId        string                 `json:"passwordUpdateEmailTemplateId,omitempty"`
	Port                                 int                    `json:"port,omitempty"`
	Properties                           string                 `json:"properties,omitempty"`
	Security                             EmailSecurityType      `json:"security,omitempty"`
	SetPasswordEmailTemplateId           string                 `json:"setPasswordEmailTemplateId,omitempty"`
	TwoFactorMethodAddEmailTemplateId    string                 `json:"twoFactorMethodAddEmailTemplateId,omitempty"`
	TwoFactorMethodRemoveEmailTemplateId string                 `json:"twoFactorMethodRemoveEmailTemplateId,omitempty"`
	Unverified                           EmailUnverifiedOptions `json:"unverified,omitempty"`
	Username                             string                 `json:"username,omitempty"`
	VerificationEmailTemplateId          string                 `json:"verificationEmailTemplateId,omitempty"`
	VerificationStrategy                 VerificationStrategy   `json:"verificationStrategy,omitempty"`
	VerifyEmail                          bool                   `json:"verifyEmail"`
	VerifyEmailWhenChanged               bool                   `json:"verifyEmailWhenChanged"`
}

type EmailSecurityType string

func (e EmailSecurityType) String() string {
	return string(e)
}

const (
	EmailSecurityType_NONE EmailSecurityType = "NONE"
	EmailSecurityType_SSL  EmailSecurityType = "SSL"
	EmailSecurityType_TLS  EmailSecurityType = "TLS"
)

/**
 * @author Daniel DeGroff
 */
type EmailHeader struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

/**
 * Stores an email template used to send emails to users.
 *
 * @author Brian Pontarelli
 */
type EmailTemplate struct {
	DefaultFromName        string            `json:"defaultFromName,omitempty"`
	DefaultHtmlTemplate    string            `json:"defaultHtmlTemplate,omitempty"`
	DefaultSubject         string            `json:"defaultSubject,omitempty"`
	DefaultTextTemplate    string            `json:"defaultTextTemplate,omitempty"`
	FromEmail              string            `json:"fromEmail,omitempty"`
	Id                     string            `json:"id,omitempty"`
	InsertInstant          int64             `json:"insertInstant,omitempty"`
	LastUpdateInstant      int64             `json:"lastUpdateInstant,omitempty"`
	LocalizedFromNames     map[string]string `json:"localizedFromNames,omitempty"`
	LocalizedHtmlTemplates map[string]string `json:"localizedHtmlTemplates,omitempty"`
	LocalizedSubjects      map[string]string `json:"localizedSubjects,omitempty"`
	LocalizedTextTemplates map[string]string `json:"localizedTextTemplates,omitempty"`
	Name                   string            `json:"name,omitempty"`
}

/**
 * Email template request.
 *
 * @author Brian Pontarelli
 */
type EmailTemplateRequest struct {
	EmailTemplate EmailTemplate `json:"emailTemplate,omitempty"`
}

/**
 * Email template response.
 *
 * @author Brian Pontarelli
 */
type EmailTemplateResponse struct {
	BaseHTTPResponse
	EmailTemplate  EmailTemplate   `json:"emailTemplate,omitempty"`
	EmailTemplates []EmailTemplate `json:"emailTemplates,omitempty"`
}

func (b *EmailTemplateResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Email templates
 *
 * @author Mark Manes
 */
type EmailTemplateSearchCriteria struct {
	BaseSearchCriteria
	Name string `json:"name,omitempty"`
}

/**
 * Search request for email templates
 *
 * @author Mark Manes
 */
type EmailTemplateSearchRequest struct {
	Search EmailTemplateSearchCriteria `json:"search,omitempty"`
}

/**
 * Email template search response
 *
 * @author Mark Manes
 */
type EmailTemplateSearchResponse struct {
	BaseHTTPResponse
	EmailTemplates []EmailTemplate `json:"emailTemplates,omitempty"`
	Total          int64           `json:"total,omitempty"`
}

func (b *EmailTemplateSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type EmailUnverifiedOptions struct {
	AllowEmailChangeWhenGated bool               `json:"allowEmailChangeWhenGated"`
	Behavior                  UnverifiedBehavior `json:"behavior,omitempty"`
}

/**
 * Something that can be enabled and thus also disabled.
 *
 * @author Daniel DeGroff
 */
type Enableable struct {
	Enabled bool `json:"enabled"`
}

/**
 * Models an entity that a user can be granted permissions to. Or an entity that can be granted permissions to another entity.
 *
 * @author Brian Pontarelli
 */
type Entity struct {
	ClientId          string                 `json:"clientId,omitempty"`
	ClientSecret      string                 `json:"clientSecret,omitempty"`
	Data              map[string]interface{} `json:"data,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	ParentId          string                 `json:"parentId,omitempty"`
	TenantId          string                 `json:"tenantId,omitempty"`
	Type              EntityType             `json:"type,omitempty"`
}

/**
 * A grant for an entity to a user or another entity.
 *
 * @author Brian Pontarelli
 */
type EntityGrant struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Entity            Entity                 `json:"entity,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Permissions       []string               `json:"permissions,omitempty"`
	RecipientEntityId string                 `json:"recipientEntityId,omitempty"`
	UserId            string                 `json:"userId,omitempty"`
}

/**
 * Entity grant API request object.
 *
 * @author Brian Pontarelli
 */
type EntityGrantRequest struct {
	Grant EntityGrant `json:"grant,omitempty"`
}

/**
 * Entity grant API response object.
 *
 * @author Brian Pontarelli
 */
type EntityGrantResponse struct {
	BaseHTTPResponse
	Grant  EntityGrant   `json:"grant,omitempty"`
	Grants []EntityGrant `json:"grants,omitempty"`
}

func (b *EntityGrantResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for entity grants.
 *
 * @author Brian Pontarelli
 */
type EntityGrantSearchCriteria struct {
	BaseSearchCriteria
	EntityId string `json:"entityId,omitempty"`
	Name     string `json:"name,omitempty"`
	UserId   string `json:"userId,omitempty"`
}

/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 */
type EntityGrantSearchRequest struct {
	Search EntityGrantSearchCriteria `json:"search,omitempty"`
}

/**
 * Search request for entity grants.
 *
 * @author Brian Pontarelli
 */
type EntityGrantSearchResponse struct {
	BaseHTTPResponse
	Grants []EntityGrant `json:"grants,omitempty"`
	Total  int64         `json:"total,omitempty"`
}

func (b *EntityGrantSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Entity API request object.
 *
 * @author Brian Pontarelli
 */
type EntityRequest struct {
	Entity Entity `json:"entity,omitempty"`
}

/**
 * Entity API response object.
 *
 * @author Brian Pontarelli
 */
type EntityResponse struct {
	BaseHTTPResponse
	Entity Entity `json:"entity,omitempty"`
}

func (b *EntityResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * This class is the entity query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 */
type EntitySearchCriteria struct {
	BaseElasticSearchCriteria
}

/**
 * Search request for entities
 *
 * @author Brett Guy
 */
type EntitySearchRequest struct {
	Search EntitySearchCriteria `json:"search,omitempty"`
}

/**
 * Search request for entities
 *
 * @author Brett Guy
 */
type EntitySearchResponse struct {
	BaseHTTPResponse
	Entities    []Entity `json:"entities,omitempty"`
	NextResults string   `json:"nextResults,omitempty"`
	Total       int64    `json:"total,omitempty"`
}

func (b *EntitySearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models an entity type that has a specific set of permissions. These are global objects and can be used across tenants.
 *
 * @author Brian Pontarelli
 */
type EntityType struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	JwtConfiguration  EntityJWTConfiguration `json:"jwtConfiguration,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Permissions       []EntityTypePermission `json:"permissions,omitempty"`
}

/**
 * JWT Configuration for entities.
 */
type EntityJWTConfiguration struct {
	Enableable
	AccessTokenKeyId    string `json:"accessTokenKeyId,omitempty"`
	TimeToLiveInSeconds int    `json:"timeToLiveInSeconds,omitempty"`
}

/**
 * Models a specific entity type permission. This permission can be granted to users or other entities.
 *
 * @author Brian Pontarelli
 */
type EntityTypePermission struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Description       string                 `json:"description,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	IsDefault         bool                   `json:"isDefault"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
}

/**
 * Entity Type API request object.
 *
 * @author Brian Pontarelli
 */
type EntityTypeRequest struct {
	EntityType EntityType           `json:"entityType,omitempty"`
	Permission EntityTypePermission `json:"permission,omitempty"`
}

/**
 * Entity Type API response object.
 *
 * @author Brian Pontarelli
 */
type EntityTypeResponse struct {
	BaseHTTPResponse
	EntityType  EntityType           `json:"entityType,omitempty"`
	EntityTypes []EntityType         `json:"entityTypes,omitempty"`
	Permission  EntityTypePermission `json:"permission,omitempty"`
}

func (b *EntityTypeResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for entity types.
 *
 * @author Brian Pontarelli
 */
type EntityTypeSearchCriteria struct {
	BaseSearchCriteria
	Name string `json:"name,omitempty"`
}

/**
 * Search request for entity types.
 *
 * @author Brian Pontarelli
 */
type EntityTypeSearchRequest struct {
	Search EntityTypeSearchCriteria `json:"search,omitempty"`
}

/**
 * Search response for entity types.
 *
 * @author Brian Pontarelli
 */
type EntityTypeSearchResponse struct {
	BaseHTTPResponse
	EntityTypes []EntityType `json:"entityTypes,omitempty"`
	Total       int64        `json:"total,omitempty"`
}

func (b *EntityTypeSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brett Pontarelli
 */
type EpicGamesApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Epic gaming login provider.
 *
 * @author Brett Pontarelli
 */
type EpicGamesIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Defines an error.
 *
 * @author Brian Pontarelli
 */
type Error struct {
	Code    string                 `json:"code,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Message string                 `json:"message,omitempty"`
}

/**
 * Standard error domain object that can also be used as the response from an API call.
 *
 * @author Brian Pontarelli
 */
type Errors struct {
	FieldErrors   map[string][]Error `json:"fieldErrors,omitempty"`
	GeneralErrors []Error            `json:"generalErrors,omitempty"`
}

func (e Errors) Present() bool {
	return len(e.FieldErrors) != 0 || len(e.GeneralErrors) != 0
}

func (e Errors) Error() string {
	var messages []string
	for _, generalError := range e.GeneralErrors {
		messages = append(messages, generalError.Message)
	}
	for fieldName, fieldErrors := range e.FieldErrors {
		var fieldMessages []string
		for _, fieldError := range fieldErrors {
			fieldMessages = append(fieldMessages, fieldError.Message)
		}
		messages = append(messages, fmt.Sprintf("%s: %s", fieldName, strings.Join(fieldMessages, ",")))
	}
	return strings.Join(messages, " ")
}

/**
 * @author Brian Pontarelli
 */
type EventConfiguration struct {
	Events map[EventType]EventConfigurationData `json:"events,omitempty"`
}

type EventConfigurationData struct {
	Enableable
	TransactionType TransactionType `json:"transactionType,omitempty"`
}

/**
 * Information about a user event (login, register, etc) that helps identify the source of the event (location, device type, OS, etc).
 *
 * @author Brian Pontarelli
 */
type EventInfo struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	DeviceDescription string                 `json:"deviceDescription,omitempty"`
	DeviceName        string                 `json:"deviceName,omitempty"`
	DeviceType        string                 `json:"deviceType,omitempty"`
	IpAddress         string                 `json:"ipAddress,omitempty"`
	Location          Location               `json:"location,omitempty"`
	Os                string                 `json:"os,omitempty"`
	UserAgent         string                 `json:"userAgent,omitempty"`
}

/**
 * Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
 *
 * @author Brian Pontarelli
 */
type EventLog struct {
	Id            int64        `json:"id,omitempty"`
	InsertInstant int64        `json:"insertInstant,omitempty"`
	Message       string       `json:"message,omitempty"`
	Type          EventLogType `json:"type,omitempty"`
}

/**
 * An Event "event" to indicate an event log was created.
 *
 * @author Daniel DeGroff
 */
type EventLogCreateEvent struct {
	BaseEvent
	EventLog EventLog `json:"eventLog,omitempty"`
}

/**
 * Event log response.
 *
 * @author Daniel DeGroff
 */
type EventLogResponse struct {
	BaseHTTPResponse
	EventLog EventLog `json:"eventLog,omitempty"`
}

func (b *EventLogResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for the event log.
 *
 * @author Brian Pontarelli
 */
type EventLogSearchCriteria struct {
	BaseSearchCriteria
	End     int64        `json:"end,omitempty"`
	Message string       `json:"message,omitempty"`
	Start   int64        `json:"start,omitempty"`
	Type    EventLogType `json:"type,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type EventLogSearchRequest struct {
	Search EventLogSearchCriteria `json:"search,omitempty"`
}

/**
 * Event log response.
 *
 * @author Brian Pontarelli
 */
type EventLogSearchResponse struct {
	BaseHTTPResponse
	EventLogs []EventLog `json:"eventLogs,omitempty"`
	Total     int64      `json:"total,omitempty"`
}

func (b *EventLogSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Event Log Type
 *
 * @author Daniel DeGroff
 */
type EventLogType string

func (e EventLogType) String() string {
	return string(e)
}

const (
	EventLogType_Information EventLogType = "Information"
	EventLogType_Debug       EventLogType = "Debug"
	EventLogType_Error       EventLogType = "Error"
)

/**
 * Container for the event information. This is the JSON that is sent from FusionAuth to webhooks.
 *
 * @author Brian Pontarelli
 */
type EventRequest struct {
	Event BaseEvent `json:"event,omitempty"`
}

/**
 * Models the event types that FusionAuth produces.
 *
 * @author Brian Pontarelli
 */
type EventType string

func (e EventType) String() string {
	return string(e)
}

const (
	EventType_JWTPublicKeyUpdate             EventType = "jwt.public-key.update"
	EventType_JWTRefreshTokenRevoke          EventType = "jwt.refresh-token.revoke"
	EventType_JWTRefresh                     EventType = "jwt.refresh"
	EventType_AuditLogCreate                 EventType = "audit-log.create"
	EventType_EventLogCreate                 EventType = "event-log.create"
	EventType_KickstartSuccess               EventType = "kickstart.success"
	EventType_GroupCreate                    EventType = "group.create"
	EventType_GroupCreateComplete            EventType = "group.create.complete"
	EventType_GroupDelete                    EventType = "group.delete"
	EventType_GroupDeleteComplete            EventType = "group.delete.complete"
	EventType_GroupMemberAdd                 EventType = "group.member.add"
	EventType_GroupMemberAddComplete         EventType = "group.member.add.complete"
	EventType_GroupMemberRemove              EventType = "group.member.remove"
	EventType_GroupMemberRemoveComplete      EventType = "group.member.remove.complete"
	EventType_GroupMemberUpdate              EventType = "group.member.update"
	EventType_GroupMemberUpdateComplete      EventType = "group.member.update.complete"
	EventType_GroupUpdate                    EventType = "group.update"
	EventType_GroupUpdateComplete            EventType = "group.update.complete"
	EventType_UserAction                     EventType = "user.action"
	EventType_UserBulkCreate                 EventType = "user.bulk.create"
	EventType_UserCreate                     EventType = "user.create"
	EventType_UserCreateComplete             EventType = "user.create.complete"
	EventType_UserDeactivate                 EventType = "user.deactivate"
	EventType_UserDelete                     EventType = "user.delete"
	EventType_UserDeleteComplete             EventType = "user.delete.complete"
	EventType_UserEmailUpdate                EventType = "user.email.update"
	EventType_UserEmailVerified              EventType = "user.email.verified"
	EventType_UserIdentityProviderLink       EventType = "user.identity-provider.link"
	EventType_UserIdentityProviderUnlink     EventType = "user.identity-provider.unlink"
	EventType_UserLoginIdDuplicateOnCreate   EventType = "user.loginId.duplicate.create"
	EventType_UserLoginIdDuplicateOnUpdate   EventType = "user.loginId.duplicate.update"
	EventType_UserLoginFailed                EventType = "user.login.failed"
	EventType_UserLoginNewDevice             EventType = "user.login.new-device"
	EventType_UserLoginSuccess               EventType = "user.login.success"
	EventType_UserLoginSuspicious            EventType = "user.login.suspicious"
	EventType_UserPasswordBreach             EventType = "user.password.breach"
	EventType_UserPasswordResetSend          EventType = "user.password.reset.send"
	EventType_UserPasswordResetStart         EventType = "user.password.reset.start"
	EventType_UserPasswordResetSuccess       EventType = "user.password.reset.success"
	EventType_UserPasswordUpdate             EventType = "user.password.update"
	EventType_UserReactivate                 EventType = "user.reactivate"
	EventType_UserRegistrationCreate         EventType = "user.registration.create"
	EventType_UserRegistrationCreateComplete EventType = "user.registration.create.complete"
	EventType_UserRegistrationDelete         EventType = "user.registration.delete"
	EventType_UserRegistrationDeleteComplete EventType = "user.registration.delete.complete"
	EventType_UserRegistrationUpdate         EventType = "user.registration.update"
	EventType_UserRegistrationUpdateComplete EventType = "user.registration.update.complete"
	EventType_UserRegistrationVerified       EventType = "user.registration.verified"
	EventType_UserTwoFactorMethodAdd         EventType = "user.two-factor.method.add"
	EventType_UserTwoFactorMethodRemove      EventType = "user.two-factor.method.remove"
	EventType_UserUpdate                     EventType = "user.update"
	EventType_UserUpdateComplete             EventType = "user.update.complete"
	EventType_Test                           EventType = "test"
	EventType_UserIdentityVerified           EventType = "user.identity.verified"
	EventType_UserIdentityUpdate             EventType = "user.identity.update"
)

/**
 * An expandable API request.
 *
 * @author Daniel DeGroff
 */
type ExpandableRequest struct {
	Expand []string `json:"expand,omitempty"`
}

/**
 * An expandable API response.
 *
 * @author Daniel DeGroff
 */
type ExpandableResponse struct {
	BaseHTTPResponse
	Expandable []string `json:"expandable,omitempty"`
}

func (b *ExpandableResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type ExpiryUnit string

func (e ExpiryUnit) String() string {
	return string(e)
}

const (
	ExpiryUnit_MINUTES ExpiryUnit = "MINUTES"
	ExpiryUnit_HOURS   ExpiryUnit = "HOURS"
	ExpiryUnit_DAYS    ExpiryUnit = "DAYS"
	ExpiryUnit_WEEKS   ExpiryUnit = "WEEKS"
	ExpiryUnit_MONTHS  ExpiryUnit = "MONTHS"
	ExpiryUnit_YEARS   ExpiryUnit = "YEARS"
)

/**
 * @author Daniel DeGroff
 */
type ExternalIdentifierConfiguration struct {
	AuthorizationGrantIdTimeToLiveInSeconds            int                          `json:"authorizationGrantIdTimeToLiveInSeconds,omitempty"`
	ChangePasswordIdGenerator                          SecureGeneratorConfiguration `json:"changePasswordIdGenerator,omitempty"`
	ChangePasswordIdTimeToLiveInSeconds                int                          `json:"changePasswordIdTimeToLiveInSeconds,omitempty"`
	DeviceCodeTimeToLiveInSeconds                      int                          `json:"deviceCodeTimeToLiveInSeconds,omitempty"`
	DeviceUserCodeIdGenerator                          SecureGeneratorConfiguration `json:"deviceUserCodeIdGenerator,omitempty"`
	EmailVerificationIdGenerator                       SecureGeneratorConfiguration `json:"emailVerificationIdGenerator,omitempty"`
	EmailVerificationIdTimeToLiveInSeconds             int                          `json:"emailVerificationIdTimeToLiveInSeconds,omitempty"`
	EmailVerificationOneTimeCodeGenerator              SecureGeneratorConfiguration `json:"emailVerificationOneTimeCodeGenerator,omitempty"`
	ExternalAuthenticationIdTimeToLiveInSeconds        int                          `json:"externalAuthenticationIdTimeToLiveInSeconds,omitempty"`
	LoginIntentTimeToLiveInSeconds                     int                          `json:"loginIntentTimeToLiveInSeconds,omitempty"`
	OneTimePasswordTimeToLiveInSeconds                 int                          `json:"oneTimePasswordTimeToLiveInSeconds,omitempty"`
	PasswordlessLoginGenerator                         SecureGeneratorConfiguration `json:"passwordlessLoginGenerator,omitempty"`
	PasswordlessLoginOneTimeCodeGenerator              SecureGeneratorConfiguration `json:"passwordlessLoginOneTimeCodeGenerator,omitempty"`
	PasswordlessLoginTimeToLiveInSeconds               int                          `json:"passwordlessLoginTimeToLiveInSeconds,omitempty"`
	PendingAccountLinkTimeToLiveInSeconds              int                          `json:"pendingAccountLinkTimeToLiveInSeconds,omitempty"`
	PhoneVerificationIdGenerator                       SecureGeneratorConfiguration `json:"phoneVerificationIdGenerator,omitempty"`
	PhoneVerificationIdTimeToLiveInSeconds             int                          `json:"phoneVerificationIdTimeToLiveInSeconds,omitempty"`
	PhoneVerificationOneTimeCodeGenerator              SecureGeneratorConfiguration `json:"phoneVerificationOneTimeCodeGenerator,omitempty"`
	RegistrationVerificationIdGenerator                SecureGeneratorConfiguration `json:"registrationVerificationIdGenerator,omitempty"`
	RegistrationVerificationIdTimeToLiveInSeconds      int                          `json:"registrationVerificationIdTimeToLiveInSeconds,omitempty"`
	RegistrationVerificationOneTimeCodeGenerator       SecureGeneratorConfiguration `json:"registrationVerificationOneTimeCodeGenerator,omitempty"`
	RememberOAuthScopeConsentChoiceTimeToLiveInSeconds int                          `json:"rememberOAuthScopeConsentChoiceTimeToLiveInSeconds,omitempty"`
	Samlv2AuthNRequestIdTimeToLiveInSeconds            int                          `json:"samlv2AuthNRequestIdTimeToLiveInSeconds,omitempty"`
	SetupPasswordIdGenerator                           SecureGeneratorConfiguration `json:"setupPasswordIdGenerator,omitempty"`
	SetupPasswordIdTimeToLiveInSeconds                 int                          `json:"setupPasswordIdTimeToLiveInSeconds,omitempty"`
	TrustTokenTimeToLiveInSeconds                      int                          `json:"trustTokenTimeToLiveInSeconds,omitempty"`
	TwoFactorIdTimeToLiveInSeconds                     int                          `json:"twoFactorIdTimeToLiveInSeconds,omitempty"`
	TwoFactorOneTimeCodeIdGenerator                    SecureGeneratorConfiguration `json:"twoFactorOneTimeCodeIdGenerator,omitempty"`
	TwoFactorOneTimeCodeIdTimeToLiveInSeconds          int                          `json:"twoFactorOneTimeCodeIdTimeToLiveInSeconds,omitempty"`
	TwoFactorTrustIdTimeToLiveInSeconds                int                          `json:"twoFactorTrustIdTimeToLiveInSeconds,omitempty"`
	WebAuthnAuthenticationChallengeTimeToLiveInSeconds int                          `json:"webAuthnAuthenticationChallengeTimeToLiveInSeconds,omitempty"`
	WebAuthnRegistrationChallengeTimeToLiveInSeconds   int                          `json:"webAuthnRegistrationChallengeTimeToLiveInSeconds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ExternalJWTApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
}

/**
 * External JWT-only identity provider.
 *
 * @author Daniel DeGroff and Brian Pontarelli
 */
type ExternalJWTIdentityProvider struct {
	BaseIdentityProvider
	ClaimMap            map[string]string                   `json:"claimMap,omitempty"`
	DefaultKeyId        string                              `json:"defaultKeyId,omitempty"`
	Domains             []string                            `json:"domains,omitempty"`
	HeaderKeyParameter  string                              `json:"headerKeyParameter,omitempty"`
	Oauth2              IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
	UniqueIdentityClaim string                              `json:"uniqueIdentityClaim,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type FacebookApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	AppId        string                      `json:"appId,omitempty"`
	ButtonText   string                      `json:"buttonText,omitempty"`
	ClientSecret string                      `json:"client_secret,omitempty"`
	Fields       string                      `json:"fields,omitempty"`
	LoginMethod  IdentityProviderLoginMethod `json:"loginMethod,omitempty"`
	Permissions  string                      `json:"permissions,omitempty"`
}

/**
 * Facebook social login provider.
 *
 * @author Brian Pontarelli
 */
type FacebookIdentityProvider struct {
	BaseIdentityProvider
	AppId        string                      `json:"appId,omitempty"`
	ButtonText   string                      `json:"buttonText,omitempty"`
	ClientSecret string                      `json:"client_secret,omitempty"`
	Fields       string                      `json:"fields,omitempty"`
	LoginMethod  IdentityProviderLoginMethod `json:"loginMethod,omitempty"`
	Permissions  string                      `json:"permissions,omitempty"`
}

/**
 * A policy to configure if and when the user-action is canceled prior to the expiration of the action.
 *
 * @author Daniel DeGroff
 */
type FailedAuthenticationActionCancelPolicy struct {
	OnPasswordReset bool `json:"onPasswordReset"`
}

/**
 * Configuration for the behavior of failed login attempts. This helps us protect against brute force password attacks.
 *
 * @author Daniel DeGroff
 */
type FailedAuthenticationConfiguration struct {
	ActionCancelPolicy  FailedAuthenticationActionCancelPolicy `json:"actionCancelPolicy,omitempty"`
	ActionDuration      int64                                  `json:"actionDuration,omitempty"`
	ActionDurationUnit  ExpiryUnit                             `json:"actionDurationUnit,omitempty"`
	EmailUser           bool                                   `json:"emailUser"`
	ResetCountInSeconds int                                    `json:"resetCountInSeconds,omitempty"`
	TooManyAttempts     int                                    `json:"tooManyAttempts,omitempty"`
	UserActionId        string                                 `json:"userActionId,omitempty"`
}

/**
 * Models a family grouping of users.
 *
 * @author Brian Pontarelli
 */
type Family struct {
	Id                string         `json:"id,omitempty"`
	InsertInstant     int64          `json:"insertInstant,omitempty"`
	LastUpdateInstant int64          `json:"lastUpdateInstant,omitempty"`
	Members           []FamilyMember `json:"members,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type FamilyConfiguration struct {
	Enableable
	AllowChildRegistrations           bool   `json:"allowChildRegistrations"`
	ConfirmChildEmailTemplateId       string `json:"confirmChildEmailTemplateId,omitempty"`
	DeleteOrphanedAccounts            bool   `json:"deleteOrphanedAccounts"`
	DeleteOrphanedAccountsDays        int    `json:"deleteOrphanedAccountsDays,omitempty"`
	FamilyRequestEmailTemplateId      string `json:"familyRequestEmailTemplateId,omitempty"`
	MaximumChildAge                   int    `json:"maximumChildAge,omitempty"`
	MinimumOwnerAge                   int    `json:"minimumOwnerAge,omitempty"`
	ParentEmailRequired               bool   `json:"parentEmailRequired"`
	ParentRegistrationEmailTemplateId string `json:"parentRegistrationEmailTemplateId,omitempty"`
}

/**
 * API request for sending out family requests to parent's.
 *
 * @author Brian Pontarelli
 */
type FamilyEmailRequest struct {
	ParentEmail string `json:"parentEmail,omitempty"`
}

/**
 * Models a single family member.
 *
 * @author Brian Pontarelli
 */
type FamilyMember struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Owner             bool                   `json:"owner"`
	Role              FamilyRole             `json:"role,omitempty"`
	UserId            string                 `json:"userId,omitempty"`
}

type FamilyRole string

func (e FamilyRole) String() string {
	return string(e)
}

const (
	FamilyRole_Child FamilyRole = "Child"
	FamilyRole_Teen  FamilyRole = "Teen"
	FamilyRole_Adult FamilyRole = "Adult"
)

/**
 * API request for managing families and members.
 *
 * @author Brian Pontarelli
 */
type FamilyRequest struct {
	FamilyMember FamilyMember `json:"familyMember,omitempty"`
}

/**
 * API response for managing families and members.
 *
 * @author Brian Pontarelli
 */
type FamilyResponse struct {
	BaseHTTPResponse
	Families []Family `json:"families,omitempty"`
	Family   Family   `json:"family,omitempty"`
}

func (b *FamilyResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Forgot password request object.
 *
 * @author Brian Pontarelli
 */
type ForgotPasswordRequest struct {
	BaseEventRequest
	ApplicationId             string                 `json:"applicationId,omitempty"`
	ChangePasswordId          string                 `json:"changePasswordId,omitempty"`
	Email                     string                 `json:"email,omitempty"`
	LoginId                   string                 `json:"loginId,omitempty"`
	LoginIdTypes              []string               `json:"loginIdTypes,omitempty"`
	SendForgotPasswordEmail   bool                   `json:"sendForgotPasswordEmail"`
	SendForgotPasswordMessage bool                   `json:"sendForgotPasswordMessage"`
	State                     map[string]interface{} `json:"state,omitempty"`
	Username                  string                 `json:"username,omitempty"`
}

/**
 * Forgot password response object.
 *
 * @author Daniel DeGroff
 */
type ForgotPasswordResponse struct {
	BaseHTTPResponse
	ChangePasswordId string `json:"changePasswordId,omitempty"`
}

func (b *ForgotPasswordResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type Form struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Steps             []FormStep             `json:"steps,omitempty"`
	Type              FormType               `json:"type,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type FormControl string

func (e FormControl) String() string {
	return string(e)
}

const (
	FormControl_Checkbox FormControl = "checkbox"
	FormControl_Number   FormControl = "number"
	FormControl_Password FormControl = "password"
	FormControl_Radio    FormControl = "radio"
	FormControl_Select   FormControl = "select"
	FormControl_Textarea FormControl = "textarea"
	FormControl_Text     FormControl = "text"
)

/**
 * @author Daniel DeGroff
 */
type FormDataType string

func (e FormDataType) String() string {
	return string(e)
}

const (
	FormDataType_Bool        FormDataType = "bool"
	FormDataType_Consent     FormDataType = "consent"
	FormDataType_Date        FormDataType = "date"
	FormDataType_Email       FormDataType = "email"
	FormDataType_Number      FormDataType = "number"
	FormDataType_PhoneNumber FormDataType = "phoneNumber"
	FormDataType_String      FormDataType = "string"
)

/**
 * @author Daniel DeGroff
 */
type FormField struct {
	Confirm           bool                   `json:"confirm"`
	ConsentId         string                 `json:"consentId,omitempty"`
	Control           FormControl            `json:"control,omitempty"`
	Data              map[string]interface{} `json:"data,omitempty"`
	Description       string                 `json:"description,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	Key               string                 `json:"key,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Options           []string               `json:"options,omitempty"`
	Required          bool                   `json:"required"`
	Type              FormDataType           `json:"type,omitempty"`
	Validator         FormFieldValidator     `json:"validator,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type FormFieldAdminPolicy string

func (e FormFieldAdminPolicy) String() string {
	return string(e)
}

const (
	FormFieldAdminPolicy_Edit FormFieldAdminPolicy = "Edit"
	FormFieldAdminPolicy_View FormFieldAdminPolicy = "View"
)

/**
 * The FormField API request object.
 *
 * @author Brett Guy
 */
type FormFieldRequest struct {
	Field  FormField   `json:"field,omitempty"`
	Fields []FormField `json:"fields,omitempty"`
}

/**
 * Form field response.
 *
 * @author Brett Guy
 */
type FormFieldResponse struct {
	BaseHTTPResponse
	Field  FormField   `json:"field,omitempty"`
	Fields []FormField `json:"fields,omitempty"`
}

func (b *FormFieldResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type FormFieldValidator struct {
	Enableable
	Expression string `json:"expression,omitempty"`
}

/**
 * Form response.
 *
 * @author Daniel DeGroff
 */
type FormRequest struct {
	Form Form `json:"form,omitempty"`
}

/**
 * Form response.
 *
 * @author Daniel DeGroff
 */
type FormResponse struct {
	BaseHTTPResponse
	Form  Form   `json:"form,omitempty"`
	Forms []Form `json:"forms,omitempty"`
}

func (b *FormResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type FormStep struct {
	Fields []string `json:"fields,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type FormType string

func (e FormType) String() string {
	return string(e)
}

const (
	FormType_Registration      FormType = "registration"
	FormType_AdminRegistration FormType = "adminRegistration"
	FormType_AdminUser         FormType = "adminUser"
	FormType_SelfServiceUser   FormType = "selfServiceUser"
)

/**
 * Models the FusionAuth connector.
 *
 * @author Trevor Smith
 */
type FusionAuthConnectorConfiguration struct {
	BaseConnectorConfiguration
}

/**
 * Models a generic connector.
 *
 * @author Trevor Smith
 */
type GenericConnectorConfiguration struct {
	BaseConnectorConfiguration
	AuthenticationURL          string            `json:"authenticationURL,omitempty"`
	ConnectTimeout             int               `json:"connectTimeout,omitempty"`
	Headers                    map[string]string `json:"headers,omitempty"`
	HttpAuthenticationPassword string            `json:"httpAuthenticationPassword,omitempty"`
	HttpAuthenticationUsername string            `json:"httpAuthenticationUsername,omitempty"`
	ReadTimeout                int               `json:"readTimeout,omitempty"`
	SslCertificateKeyId        string            `json:"sslCertificateKeyId,omitempty"`
}

/**
 * @author Brett Guy
 */
type GenericMessengerConfiguration struct {
	BaseMessengerConfiguration
	ConnectTimeout             int               `json:"connectTimeout,omitempty"`
	Headers                    map[string]string `json:"headers,omitempty"`
	HttpAuthenticationPassword string            `json:"httpAuthenticationPassword,omitempty"`
	HttpAuthenticationUsername string            `json:"httpAuthenticationUsername,omitempty"`
	ReadTimeout                int               `json:"readTimeout,omitempty"`
	SslCertificate             string            `json:"sslCertificate,omitempty"`
	Url                        string            `json:"url,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type GoogleApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string                           `json:"buttonText,omitempty"`
	ClientId     string                           `json:"client_id,omitempty"`
	ClientSecret string                           `json:"client_secret,omitempty"`
	LoginMethod  IdentityProviderLoginMethod      `json:"loginMethod,omitempty"`
	Properties   GoogleIdentityProviderProperties `json:"properties,omitempty"`
	Scope        string                           `json:"scope,omitempty"`
}

/**
 * Google social login provider.
 *
 * @author Daniel DeGroff
 */
type GoogleIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string                           `json:"buttonText,omitempty"`
	ClientId     string                           `json:"client_id,omitempty"`
	ClientSecret string                           `json:"client_secret,omitempty"`
	LoginMethod  IdentityProviderLoginMethod      `json:"loginMethod,omitempty"`
	Properties   GoogleIdentityProviderProperties `json:"properties,omitempty"`
	Scope        string                           `json:"scope,omitempty"`
}

/**
 * Google social login provider parameters.
 *
 * @author Daniel DeGroff
 */
type GoogleIdentityProviderProperties struct {
	Api    string `json:"api,omitempty"`
	Button string `json:"button,omitempty"`
}

/**
 * Authorization Grant types as defined by the <a href="https://tools.ietf.org/html/rfc6749">The OAuth 2.0 Authorization
 * Framework - RFC 6749</a>.
 * <p>
 * Specific names as defined by <a href="https://tools.ietf.org/html/rfc7591#section-4.1">
 * OAuth 2.0 Dynamic Client Registration Protocol - RFC 7591 Section 4.1</a>
 *
 * @author Daniel DeGroff
 */
type GrantType string

func (e GrantType) String() string {
	return string(e)
}

const (
	GrantType_AuthorizationCode GrantType = "authorization_code"
	GrantType_Implicit          GrantType = "implicit"
	GrantType_Password          GrantType = "password"
	GrantType_ClientCredentials GrantType = "client_credentials"
	GrantType_RefreshToken      GrantType = "refresh_token"
	GrantType_Unknown           GrantType = "unknown"
	GrantType_DeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

/**
 * @author Tyler Scott
 */
type Group struct {
	Data              map[string]interface{}       `json:"data,omitempty"`
	Id                string                       `json:"id,omitempty"`
	InsertInstant     int64                        `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                        `json:"lastUpdateInstant,omitempty"`
	Name              string                       `json:"name,omitempty"`
	Roles             map[string][]ApplicationRole `json:"roles,omitempty"`
	TenantId          string                       `json:"tenantId,omitempty"`
}

/**
 * Models the Group Created Event.
 *
 * @author Daniel DeGroff
 */
type GroupCreateCompleteEvent struct {
	BaseGroupEvent
}

/**
 * Models the Group Create Event.
 *
 * @author Daniel DeGroff
 */
type GroupCreateEvent struct {
	BaseGroupEvent
}

/**
 * Models the Group Create Complete Event.
 *
 * @author Daniel DeGroff
 */
type GroupDeleteCompleteEvent struct {
	BaseGroupEvent
}

/**
 * Models the Group Delete Event.
 *
 * @author Daniel DeGroff
 */
type GroupDeleteEvent struct {
	BaseGroupEvent
}

/**
 * A User's membership into a Group
 *
 * @author Daniel DeGroff
 */
type GroupMember struct {
	Data          map[string]interface{} `json:"data,omitempty"`
	GroupId       string                 `json:"groupId,omitempty"`
	Id            string                 `json:"id,omitempty"`
	InsertInstant int64                  `json:"insertInstant,omitempty"`
	User          User                   `json:"user,omitempty"`
	UserId        string                 `json:"userId,omitempty"`
}

/**
 * Models the Group Member Add Complete Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberAddCompleteEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Models the Group Member Add Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberAddEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Models the Group Member Remove Complete Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberRemoveCompleteEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Models the Group Member Remove Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberRemoveEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Search criteria for Group Members
 *
 * @author Daniel DeGroff
 */
type GroupMemberSearchCriteria struct {
	BaseSearchCriteria
	GroupId  string `json:"groupId,omitempty"`
	TenantId string `json:"tenantId,omitempty"`
	UserId   string `json:"userId,omitempty"`
}

/**
 * Search request for Group Members.
 *
 * @author Daniel DeGroff
 */
type GroupMemberSearchRequest struct {
	Search GroupMemberSearchCriteria `json:"search,omitempty"`
}

/**
 * Search response for Group Members
 *
 * @author Daniel DeGroff
 */
type GroupMemberSearchResponse struct {
	BaseHTTPResponse
	Members []GroupMember `json:"members,omitempty"`
	Total   int64         `json:"total,omitempty"`
}

func (b *GroupMemberSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models the Group Member Update Complete Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberUpdateCompleteEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Models the Group Member Update Event.
 *
 * @author Daniel DeGroff
 */
type GroupMemberUpdateEvent struct {
	BaseGroupEvent
	Members []GroupMember `json:"members,omitempty"`
}

/**
 * Group API request object.
 *
 * @author Daniel DeGroff
 */
type GroupRequest struct {
	Group   Group    `json:"group,omitempty"`
	RoleIds []string `json:"roleIds,omitempty"`
}

/**
 * Group API response object.
 *
 * @author Daniel DeGroff
 */
type GroupResponse struct {
	BaseHTTPResponse
	Group  Group   `json:"group,omitempty"`
	Groups []Group `json:"groups,omitempty"`
}

func (b *GroupResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Groups
 *
 * @author Daniel DeGroff
 */
type GroupSearchCriteria struct {
	BaseSearchCriteria
	Name     string `json:"name,omitempty"`
	TenantId string `json:"tenantId,omitempty"`
}

/**
 * Search request for Groups.
 *
 * @author Daniel DeGroff
 */
type GroupSearchRequest struct {
	Search GroupSearchCriteria `json:"search,omitempty"`
}

/**
 * Search response for Groups
 *
 * @author Daniel DeGroff
 */
type GroupSearchResponse struct {
	BaseHTTPResponse
	Groups []Group `json:"groups,omitempty"`
	Total  int64   `json:"total,omitempty"`
}

func (b *GroupSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models the Group Update Complete Event.
 *
 * @author Daniel DeGroff
 */
type GroupUpdateCompleteEvent struct {
	BaseGroupEvent
	Original Group `json:"original,omitempty"`
}

/**
 * Models the Group Update Event.
 *
 * @author Daniel DeGroff
 */
type GroupUpdateEvent struct {
	BaseGroupEvent
	Original Group `json:"original,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type HTTPMethod string

func (e HTTPMethod) String() string {
	return string(e)
}

const (
	HTTPMethod_GET     HTTPMethod = "GET"
	HTTPMethod_POST    HTTPMethod = "POST"
	HTTPMethod_PUT     HTTPMethod = "PUT"
	HTTPMethod_DELETE  HTTPMethod = "DELETE"
	HTTPMethod_HEAD    HTTPMethod = "HEAD"
	HTTPMethod_OPTIONS HTTPMethod = "OPTIONS"
	HTTPMethod_PATCH   HTTPMethod = "PATCH"
)

/**
 * @author Daniel DeGroff
 */
type HYPRApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	RelyingPartyApplicationId string `json:"relyingPartyApplicationId,omitempty"`
	RelyingPartyURL           string `json:"relyingPartyURL,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type HYPRIdentityProvider struct {
	BaseIdentityProvider
	RelyingPartyApplicationId string `json:"relyingPartyApplicationId,omitempty"`
	RelyingPartyURL           string `json:"relyingPartyURL,omitempty"`
}

/**
 * @author Brett Guy
 */
type IPAccessControlEntry struct {
	Action         IPAccessControlEntryAction `json:"action,omitempty"`
	EndIPAddress   string                     `json:"endIPAddress,omitempty"`
	StartIPAddress string                     `json:"startIPAddress,omitempty"`
}

/**
 * @author Brett Guy
 */
type IPAccessControlEntryAction string

func (e IPAccessControlEntryAction) String() string {
	return string(e)
}

const (
	IPAccessControlEntryAction_Allow IPAccessControlEntryAction = "Allow"
	IPAccessControlEntryAction_Block IPAccessControlEntryAction = "Block"
)

/**
 * @author Brett Guy
 */
type IPAccessControlList struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Entries           []IPAccessControlEntry `json:"entries,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
}

/**
 * @author Brett Guy
 */
type IPAccessControlListRequest struct {
	IpAccessControlList IPAccessControlList `json:"ipAccessControlList,omitempty"`
}

/**
 * @author Brett Guy
 */
type IPAccessControlListResponse struct {
	BaseHTTPResponse
	IpAccessControlList  IPAccessControlList   `json:"ipAccessControlList,omitempty"`
	IpAccessControlLists []IPAccessControlList `json:"ipAccessControlLists,omitempty"`
}

func (b *IPAccessControlListResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brett Guy
 */
type IPAccessControlListSearchCriteria struct {
	BaseSearchCriteria
	Name string `json:"name,omitempty"`
}

/**
 * Search request for IP ACLs .
 *
 * @author Brett Guy
 */
type IPAccessControlListSearchRequest struct {
	Search IPAccessControlListSearchCriteria `json:"search,omitempty"`
}

/**
 * @author Brett Guy
 */
type IPAccessControlListSearchResponse struct {
	BaseHTTPResponse
	IpAccessControlLists []IPAccessControlList `json:"ipAccessControlLists,omitempty"`
	Total                int64                 `json:"total,omitempty"`
}

func (b *IPAccessControlListSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderLimitUserLinkingPolicy struct {
	Enableable
	MaximumLinks int `json:"maximumLinks,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderLink struct {
	Data                   map[string]interface{} `json:"data,omitempty"`
	DisplayName            string                 `json:"displayName,omitempty"`
	IdentityProviderId     string                 `json:"identityProviderId,omitempty"`
	IdentityProviderName   string                 `json:"identityProviderName,omitempty"`
	IdentityProviderType   IdentityProviderType   `json:"identityProviderType,omitempty"`
	IdentityProviderUserId string                 `json:"identityProviderUserId,omitempty"`
	InsertInstant          int64                  `json:"insertInstant,omitempty"`
	LastLoginInstant       int64                  `json:"lastLoginInstant,omitempty"`
	TenantId               string                 `json:"tenantId,omitempty"`
	Token                  string                 `json:"token,omitempty"`
	UserId                 string                 `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderLinkRequest struct {
	BaseEventRequest
	IdentityProviderLink IdentityProviderLink `json:"identityProviderLink,omitempty"`
	PendingIdPLinkId     string               `json:"pendingIdPLinkId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderLinkResponse struct {
	BaseHTTPResponse
	IdentityProviderLink  IdentityProviderLink   `json:"identityProviderLink,omitempty"`
	IdentityProviderLinks []IdentityProviderLink `json:"identityProviderLinks,omitempty"`
}

func (b *IdentityProviderLinkResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The IdP behavior when no user link has been made yet.
 *
 * @author Daniel DeGroff
 */
type IdentityProviderLinkingStrategy string

func (e IdentityProviderLinkingStrategy) String() string {
	return string(e)
}

const (
	IdentityProviderLinkingStrategy_CreatePendingLink             IdentityProviderLinkingStrategy = "CreatePendingLink"
	IdentityProviderLinkingStrategy_Disabled                      IdentityProviderLinkingStrategy = "Disabled"
	IdentityProviderLinkingStrategy_LinkAnonymously               IdentityProviderLinkingStrategy = "LinkAnonymously"
	IdentityProviderLinkingStrategy_LinkByEmail                   IdentityProviderLinkingStrategy = "LinkByEmail"
	IdentityProviderLinkingStrategy_LinkByEmailForExistingUser    IdentityProviderLinkingStrategy = "LinkByEmailForExistingUser"
	IdentityProviderLinkingStrategy_LinkByUsername                IdentityProviderLinkingStrategy = "LinkByUsername"
	IdentityProviderLinkingStrategy_LinkByUsernameForExistingUser IdentityProviderLinkingStrategy = "LinkByUsernameForExistingUser"
	IdentityProviderLinkingStrategy_Unsupported                   IdentityProviderLinkingStrategy = "Unsupported"
)

/**
 * @author Brett Pontarelli
 */
type IdentityProviderLoginMethod string

func (e IdentityProviderLoginMethod) String() string {
	return string(e)
}

const (
	IdentityProviderLoginMethod_UsePopup            IdentityProviderLoginMethod = "UsePopup"
	IdentityProviderLoginMethod_UseRedirect         IdentityProviderLoginMethod = "UseRedirect"
	IdentityProviderLoginMethod_UseVendorJavaScript IdentityProviderLoginMethod = "UseVendorJavaScript"
)

/**
 * Login API request object used for login to third-party systems (i.e. Login with Facebook).
 *
 * @author Brian Pontarelli
 */
type IdentityProviderLoginRequest struct {
	BaseLoginRequest
	Data               map[string]string `json:"data,omitempty"`
	EncodedJWT         string            `json:"encodedJWT,omitempty"`
	IdentityProviderId string            `json:"identityProviderId,omitempty"`
	NoLink             bool              `json:"noLink"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderOauth2Configuration struct {
	AuthorizationEndpoint      string                     `json:"authorization_endpoint,omitempty"`
	ClientId                   string                     `json:"client_id,omitempty"`
	ClientSecret               string                     `json:"client_secret,omitempty"`
	ClientAuthenticationMethod ClientAuthenticationMethod `json:"clientAuthenticationMethod,omitempty"`
	EmailClaim                 string                     `json:"emailClaim,omitempty"`
	EmailVerifiedClaim         string                     `json:"emailVerifiedClaim,omitempty"`
	Issuer                     string                     `json:"issuer,omitempty"`
	Scope                      string                     `json:"scope,omitempty"`
	TokenEndpoint              string                     `json:"token_endpoint,omitempty"`
	UniqueIdClaim              string                     `json:"uniqueIdClaim,omitempty"`
	UserinfoEndpoint           string                     `json:"userinfo_endpoint,omitempty"`
	UsernameClaim              string                     `json:"usernameClaim,omitempty"`
}

type ClientAuthenticationMethod string

func (e ClientAuthenticationMethod) String() string {
	return string(e)
}

const (
	ClientAuthenticationMethod_None              ClientAuthenticationMethod = "none"
	ClientAuthenticationMethod_ClientSecretBasic ClientAuthenticationMethod = "client_secret_basic"
	ClientAuthenticationMethod_ClientSecretPost  ClientAuthenticationMethod = "client_secret_post"
)

/**
 * @author Daniel DeGroff
 */
type IdentityProviderPendingLinkResponse struct {
	BaseHTTPResponse
	IdentityProviderTenantConfiguration IdentityProviderTenantConfiguration `json:"identityProviderTenantConfiguration,omitempty"`
	LinkCount                           int                                 `json:"linkCount,omitempty"`
	PendingIdPLink                      PendingIdPLink                      `json:"pendingIdPLink,omitempty"`
}

func (b *IdentityProviderPendingLinkResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderRequest struct {
	IdentityProvider BaseIdentityProvider `json:"identityProvider,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderResponse struct {
	BaseHTTPResponse
	IdentityProvider  BaseIdentityProvider   `json:"identityProvider,omitempty"`
	IdentityProviders []BaseIdentityProvider `json:"identityProviders,omitempty"`
}

func (b *IdentityProviderResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Identity Providers.
 *
 * @author Spencer Witt
 */
type IdentityProviderSearchCriteria struct {
	BaseSearchCriteria
	ApplicationId string               `json:"applicationId,omitempty"`
	Name          string               `json:"name,omitempty"`
	Type          IdentityProviderType `json:"type,omitempty"`
}

/**
 * Search request for Identity Providers
 *
 * @author Spencer Witt
 */
type IdentityProviderSearchRequest struct {
	Search IdentityProviderSearchCriteria `json:"search,omitempty"`
}

/**
 * Identity Provider response.
 *
 * @author Spencer Witt
 */
type IdentityProviderSearchResponse struct {
	BaseHTTPResponse
	IdentityProviders []BaseIdentityProvider `json:"identityProviders,omitempty"`
	Total             int64                  `json:"total,omitempty"`
}

func (b *IdentityProviderSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderStartLoginRequest struct {
	BaseLoginRequest
	Data               map[string]string      `json:"data,omitempty"`
	IdentityProviderId string                 `json:"identityProviderId,omitempty"`
	LoginId            string                 `json:"loginId,omitempty"`
	LoginIdTypes       []string               `json:"loginIdTypes,omitempty"`
	State              map[string]interface{} `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderStartLoginResponse struct {
	BaseHTTPResponse
	Code string `json:"code,omitempty"`
}

func (b *IdentityProviderStartLoginResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderTenantConfiguration struct {
	Data               map[string]interface{}                 `json:"data,omitempty"`
	LimitUserLinkCount IdentityProviderLimitUserLinkingPolicy `json:"limitUserLinkCount,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderType string

func (e IdentityProviderType) String() string {
	return string(e)
}

const (
	IdentityProviderType_Apple              IdentityProviderType = "Apple"
	IdentityProviderType_EpicGames          IdentityProviderType = "EpicGames"
	IdentityProviderType_ExternalJWT        IdentityProviderType = "ExternalJWT"
	IdentityProviderType_Facebook           IdentityProviderType = "Facebook"
	IdentityProviderType_Google             IdentityProviderType = "Google"
	IdentityProviderType_HYPR               IdentityProviderType = "HYPR"
	IdentityProviderType_LinkedIn           IdentityProviderType = "LinkedIn"
	IdentityProviderType_Nintendo           IdentityProviderType = "Nintendo"
	IdentityProviderType_OpenIDConnect      IdentityProviderType = "OpenIDConnect"
	IdentityProviderType_SAMLv2             IdentityProviderType = "SAMLv2"
	IdentityProviderType_SAMLv2IdPInitiated IdentityProviderType = "SAMLv2IdPInitiated"
	IdentityProviderType_SonyPSN            IdentityProviderType = "SonyPSN"
	IdentityProviderType_Steam              IdentityProviderType = "Steam"
	IdentityProviderType_Twitch             IdentityProviderType = "Twitch"
	IdentityProviderType_Twitter            IdentityProviderType = "Twitter"
	IdentityProviderType_Xbox               IdentityProviderType = "Xbox"
)

/**
 * Model identity types provided by FusionAuth.
 */
type IdentityType struct {
	Name string `json:"name,omitempty"`
}

/**
 * Models the reason that {@link UserIdentity#verified} was set to true or false.
 *
 * @author Brady Wied
 */
type IdentityVerifiedReason string

func (e IdentityVerifiedReason) String() string {
	return string(e)
}

const (
	IdentityVerifiedReason_Skipped        IdentityVerifiedReason = "Skipped"
	IdentityVerifiedReason_Trusted        IdentityVerifiedReason = "Trusted"
	IdentityVerifiedReason_Unverifiable   IdentityVerifiedReason = "Unverifiable"
	IdentityVerifiedReason_Implicit       IdentityVerifiedReason = "Implicit"
	IdentityVerifiedReason_Pending        IdentityVerifiedReason = "Pending"
	IdentityVerifiedReason_Completed      IdentityVerifiedReason = "Completed"
	IdentityVerifiedReason_Disabled       IdentityVerifiedReason = "Disabled"
	IdentityVerifiedReason_Administrative IdentityVerifiedReason = "Administrative"
	IdentityVerifiedReason_Import         IdentityVerifiedReason = "Import"
)

/**
 * Import request.
 *
 * @author Brian Pontarelli
 */
type ImportRequest struct {
	BaseEventRequest
	EncryptionScheme      string `json:"encryptionScheme,omitempty"`
	Factor                int    `json:"factor,omitempty"`
	Users                 []User `json:"users,omitempty"`
	ValidateDbConstraints bool   `json:"validateDbConstraints"`
}

/**
 * A marker interface indicating this event is not scoped to a tenant and will be sent to all webhooks.
 *
 * @author Daniel DeGroff
 */
type InstanceEvent struct {
	NonTransactionalEvent
}

/**
 * The Integration Request
 *
 * @author Daniel DeGroff
 */
type IntegrationRequest struct {
	Integrations Integrations `json:"integrations,omitempty"`
}

/**
 * The Integration Response
 *
 * @author Daniel DeGroff
 */
type IntegrationResponse struct {
	BaseHTTPResponse
	Integrations Integrations `json:"integrations,omitempty"`
}

func (b *IntegrationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Available Integrations
 *
 * @author Daniel DeGroff
 */
type Integrations struct {
	Cleanspeak CleanSpeakConfiguration `json:"cleanspeak,omitempty"`
	Kafka      KafkaConfiguration      `json:"kafka,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IssueResponse struct {
	BaseHTTPResponse
	RefreshToken string `json:"refreshToken,omitempty"`
	Token        string `json:"token,omitempty"`
}

func (b *IssueResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
 * Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
 *
 * @author Daniel DeGroff
 */
type JSONWebKey struct {
	Alg      Algorithm              `json:"alg,omitempty"`
	Crv      string                 `json:"crv,omitempty"`
	D        string                 `json:"d,omitempty"`
	Dp       string                 `json:"dp,omitempty"`
	Dq       string                 `json:"dq,omitempty"`
	E        string                 `json:"e,omitempty"`
	Kid      string                 `json:"kid,omitempty"`
	Kty      KeyType                `json:"kty,omitempty"`
	N        string                 `json:"n,omitempty"`
	Other    map[string]interface{} `json:"other,omitempty"`
	P        string                 `json:"p,omitempty"`
	Q        string                 `json:"q,omitempty"`
	Qi       string                 `json:"qi,omitempty"`
	Use      string                 `json:"use,omitempty"`
	X        string                 `json:"x,omitempty"`
	X5c      []string               `json:"x5c,omitempty"`
	X5t      string                 `json:"x5t,omitempty"`
	X5t_S256 string                 `json:"x5t#S256,omitempty"`
	Y        string                 `json:"y,omitempty"`
}

/**
 * Interface for any object that can provide JSON Web key Information.
 */
type JSONWebKeyInfoProvider struct {
}

/**
 * @author Daniel DeGroff
 */
type JWKSResponse struct {
	BaseHTTPResponse
	Keys []JSONWebKey `json:"keys,omitempty"`
}

func (b *JWKSResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * JSON Web Token (JWT) as defined by RFC 7519.
 * <pre>
 * From RFC 7519 Section 1. Introduction:
 *    The suggested pronunciation of JWT is the same as the English word "jot".
 * </pre>
 * The JWT is not Thread-Safe and should not be re-used.
 *
 * @author Daniel DeGroff
 */
type JWT struct {
	Aud         interface{}            `json:"aud,omitempty"`
	Exp         int64                  `json:"exp,omitempty"`
	Iat         int64                  `json:"iat,omitempty"`
	Iss         string                 `json:"iss,omitempty"`
	Jti         string                 `json:"jti,omitempty"`
	Nbf         int64                  `json:"nbf,omitempty"`
	OtherClaims map[string]interface{} `json:"otherClaims,omitempty"`
	Sub         string                 `json:"sub,omitempty"`
}

/**
 * JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
 * may be <code>enabled = false</code>.
 *
 * @author Daniel DeGroff
 */
type JWTConfiguration struct {
	Enableable
	AccessTokenKeyId                       string                                 `json:"accessTokenKeyId,omitempty"`
	IdTokenKeyId                           string                                 `json:"idTokenKeyId,omitempty"`
	RefreshTokenExpirationPolicy           RefreshTokenExpirationPolicy           `json:"refreshTokenExpirationPolicy,omitempty"`
	RefreshTokenOneTimeUseConfiguration    RefreshTokenOneTimeUseConfiguration    `json:"refreshTokenOneTimeUseConfiguration,omitempty"`
	RefreshTokenRevocationPolicy           RefreshTokenRevocationPolicy           `json:"refreshTokenRevocationPolicy,omitempty"`
	RefreshTokenSlidingWindowConfiguration RefreshTokenSlidingWindowConfiguration `json:"refreshTokenSlidingWindowConfiguration,omitempty"`
	RefreshTokenTimeToLiveInMinutes        int                                    `json:"refreshTokenTimeToLiveInMinutes,omitempty"`
	RefreshTokenUsagePolicy                RefreshTokenUsagePolicy                `json:"refreshTokenUsagePolicy,omitempty"`
	TimeToLiveInSeconds                    int                                    `json:"timeToLiveInSeconds,omitempty"`
}

/**
 * Models the JWT public key Refresh Token Revoke Event. This event might be for a single
 * token, a user or an entire application.
 *
 * @author Brian Pontarelli
 */
type JWTPublicKeyUpdateEvent struct {
	BaseEvent
	ApplicationIds []string `json:"applicationIds,omitempty"`
}

/**
 * Models the JWT Refresh Event. This event will be fired when a JWT is "refreshed" (generated) using a Refresh Token.
 *
 * @author Daniel DeGroff
 */
type JWTRefreshEvent struct {
	BaseEvent
	ApplicationId string `json:"applicationId,omitempty"`
	Original      string `json:"original,omitempty"`
	RefreshToken  string `json:"refreshToken,omitempty"`
	Token         string `json:"token,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * API response for refreshing a JWT with a Refresh Token.
 * <p>
 * Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a
 * string.
 *
 * @author Daniel DeGroff
 */
type JWTRefreshResponse struct {
	BaseHTTPResponse
	RefreshToken   string `json:"refreshToken,omitempty"`
	RefreshTokenId string `json:"refreshTokenId,omitempty"`
	Token          string `json:"token,omitempty"`
}

func (b *JWTRefreshResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models the Refresh Token Revoke Event. This event might be for a single token, a user
 * or an entire application.
 *
 * @author Brian Pontarelli
 */
type JWTRefreshTokenRevokeEvent struct {
	BaseEvent
	ApplicationId                  string         `json:"applicationId,omitempty"`
	ApplicationTimeToLiveInSeconds map[string]int `json:"applicationTimeToLiveInSeconds,omitempty"`
	RefreshToken                   RefreshToken   `json:"refreshToken,omitempty"`
	User                           User           `json:"user,omitempty"`
	UserId                         string         `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type JWTVendRequest struct {
	Claims              map[string]interface{} `json:"claims,omitempty"`
	KeyId               string                 `json:"keyId,omitempty"`
	TimeToLiveInSeconds int                    `json:"timeToLiveInSeconds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type JWTVendResponse struct {
	BaseHTTPResponse
	Token string `json:"token,omitempty"`
}

func (b *JWTVendResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type KafkaConfiguration struct {
	Enableable
	DefaultTopic string            `json:"defaultTopic,omitempty"`
	Producer     map[string]string `json:"producer,omitempty"`
}

/**
 * @author Brett Guy
 */
type KafkaMessengerConfiguration struct {
	BaseMessengerConfiguration
	DefaultTopic string            `json:"defaultTopic,omitempty"`
	Producer     map[string]string `json:"producer,omitempty"`
}

/**
 * Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
 *
 * @author Brian Pontarelli
 */
type Key struct {
	Algorithm              KeyAlgorithm           `json:"algorithm,omitempty"`
	Certificate            string                 `json:"certificate,omitempty"`
	CertificateInformation CertificateInformation `json:"certificateInformation,omitempty"`
	ExpirationInstant      int64                  `json:"expirationInstant,omitempty"`
	HasPrivateKey          bool                   `json:"hasPrivateKey"`
	Id                     string                 `json:"id,omitempty"`
	InsertInstant          int64                  `json:"insertInstant,omitempty"`
	Issuer                 string                 `json:"issuer,omitempty"`
	Kid                    string                 `json:"kid,omitempty"`
	LastUpdateInstant      int64                  `json:"lastUpdateInstant,omitempty"`
	Length                 int                    `json:"length,omitempty"`
	Name                   string                 `json:"name,omitempty"`
	PrivateKey             string                 `json:"privateKey,omitempty"`
	PublicKey              string                 `json:"publicKey,omitempty"`
	Secret                 string                 `json:"secret,omitempty"`
	Type                   KeyType                `json:"type,omitempty"`
}

type CertificateInformation struct {
	Issuer            string `json:"issuer,omitempty"`
	Md5Fingerprint    string `json:"md5Fingerprint,omitempty"`
	SerialNumber      string `json:"serialNumber,omitempty"`
	Sha1Fingerprint   string `json:"sha1Fingerprint,omitempty"`
	Sha1Thumbprint    string `json:"sha1Thumbprint,omitempty"`
	Sha256Fingerprint string `json:"sha256Fingerprint,omitempty"`
	Sha256Thumbprint  string `json:"sha256Thumbprint,omitempty"`
	Subject           string `json:"subject,omitempty"`
	ValidFrom         int64  `json:"validFrom,omitempty"`
	ValidTo           int64  `json:"validTo,omitempty"`
}

type KeyAlgorithm string

func (e KeyAlgorithm) String() string {
	return string(e)
}

const (
	KeyAlgorithm_ES256 KeyAlgorithm = "ES256"
	KeyAlgorithm_ES384 KeyAlgorithm = "ES384"
	KeyAlgorithm_ES512 KeyAlgorithm = "ES512"
	KeyAlgorithm_HS256 KeyAlgorithm = "HS256"
	KeyAlgorithm_HS384 KeyAlgorithm = "HS384"
	KeyAlgorithm_HS512 KeyAlgorithm = "HS512"
	KeyAlgorithm_RS256 KeyAlgorithm = "RS256"
	KeyAlgorithm_RS384 KeyAlgorithm = "RS384"
	KeyAlgorithm_RS512 KeyAlgorithm = "RS512"
)

type KeyType string

func (e KeyType) String() string {
	return string(e)
}

const (
	KeyType_EC   KeyType = "EC"
	KeyType_RSA  KeyType = "RSA"
	KeyType_HMAC KeyType = "HMAC"
)

/**
 * Key API request object.
 *
 * @author Daniel DeGroff
 */
type KeyRequest struct {
	Key Key `json:"key,omitempty"`
}

/**
 * Key API response object.
 *
 * @author Daniel DeGroff
 */
type KeyResponse struct {
	BaseHTTPResponse
	Key  Key   `json:"key,omitempty"`
	Keys []Key `json:"keys,omitempty"`
}

func (b *KeyResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Keys
 *
 * @author Spencer Witt
 */
type KeySearchCriteria struct {
	BaseSearchCriteria
	Algorithm KeyAlgorithm `json:"algorithm,omitempty"`
	Name      string       `json:"name,omitempty"`
	Type      KeyType      `json:"type,omitempty"`
}

/**
 * Search request for Keys
 *
 * @author Spencer Witt
 */
type KeySearchRequest struct {
	Search KeySearchCriteria `json:"search,omitempty"`
}

/**
 * Key search response
 *
 * @author Spencer Witt
 */
type KeySearchResponse struct {
	BaseHTTPResponse
	Keys  []Key `json:"keys,omitempty"`
	Total int64 `json:"total,omitempty"`
}

func (b *KeySearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The use type of a key.
 *
 * @author Daniel DeGroff
 */
type KeyUse string

func (e KeyUse) String() string {
	return string(e)
}

const (
	KeyUse_SignOnly      KeyUse = "SignOnly"
	KeyUse_SignAndVerify KeyUse = "SignAndVerify"
	KeyUse_VerifyOnly    KeyUse = "VerifyOnly"
)

/**
 * Event to indicate kickstart has been successfully completed.
 *
 * @author Daniel DeGroff
 */
type KickstartSuccessEvent struct {
	BaseEvent
	InstanceId string `json:"instanceId,omitempty"`
}

/**
 * Models an LDAP connector.
 *
 * @author Trevor Smith
 */
type LDAPConnectorConfiguration struct {
	BaseConnectorConfiguration
	AuthenticationURL     string                       `json:"authenticationURL,omitempty"`
	BaseStructure         string                       `json:"baseStructure,omitempty"`
	ConnectTimeout        int                          `json:"connectTimeout,omitempty"`
	IdentifyingAttribute  string                       `json:"identifyingAttribute,omitempty"`
	LambdaConfiguration   ConnectorLambdaConfiguration `json:"lambdaConfiguration,omitempty"`
	LoginIdAttribute      string                       `json:"loginIdAttribute,omitempty"`
	ReadTimeout           int                          `json:"readTimeout,omitempty"`
	RequestedAttributes   []string                     `json:"requestedAttributes,omitempty"`
	SecurityMethod        LDAPSecurityMethod           `json:"securityMethod,omitempty"`
	SystemAccountDN       string                       `json:"systemAccountDN,omitempty"`
	SystemAccountPassword string                       `json:"systemAccountPassword,omitempty"`
}

type LDAPSecurityMethod string

func (e LDAPSecurityMethod) String() string {
	return string(e)
}

const (
	LDAPSecurityMethod_None     LDAPSecurityMethod = "None"
	LDAPSecurityMethod_LDAPS    LDAPSecurityMethod = "LDAPS"
	LDAPSecurityMethod_StartTLS LDAPSecurityMethod = "StartTLS"
)

type ConnectorLambdaConfiguration struct {
	ReconcileId string `json:"reconcileId,omitempty"`
}

/**
 * A JavaScript lambda function that is executed during certain events inside FusionAuth.
 *
 * @author Brian Pontarelli
 */
type Lambda struct {
	Body              string           `json:"body,omitempty"`
	Debug             bool             `json:"debug"`
	EngineType        LambdaEngineType `json:"engineType,omitempty"`
	Id                string           `json:"id,omitempty"`
	InsertInstant     int64            `json:"insertInstant,omitempty"`
	LastUpdateInstant int64            `json:"lastUpdateInstant,omitempty"`
	Name              string           `json:"name,omitempty"`
	Type              LambdaType       `json:"type,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LambdaEngineType string

func (e LambdaEngineType) String() string {
	return string(e)
}

const (
	LambdaEngineType_GraalJS LambdaEngineType = "GraalJS"
	LambdaEngineType_Nashorn LambdaEngineType = "Nashorn"
)

/**
 * Lambda API request object.
 *
 * @author Brian Pontarelli
 */
type LambdaRequest struct {
	Lambda Lambda `json:"lambda,omitempty"`
}

/**
 * Lambda API response object.
 *
 * @author Brian Pontarelli
 */
type LambdaResponse struct {
	BaseHTTPResponse
	Lambda  Lambda   `json:"lambda,omitempty"`
	Lambdas []Lambda `json:"lambdas,omitempty"`
}

func (b *LambdaResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for Lambdas
 *
 * @author Mark Manes
 */
type LambdaSearchCriteria struct {
	BaseSearchCriteria
	Body string     `json:"body,omitempty"`
	Name string     `json:"name,omitempty"`
	Type LambdaType `json:"type,omitempty"`
}

/**
 * Search request for Lambdas
 *
 * @author Mark Manes
 */
type LambdaSearchRequest struct {
	Search LambdaSearchCriteria `json:"search,omitempty"`
}

/**
 * Lambda search response
 *
 * @author Mark Manes
 */
type LambdaSearchResponse struct {
	BaseHTTPResponse
	Lambdas []Lambda `json:"lambdas,omitempty"`
	Total   int64    `json:"total,omitempty"`
}

func (b *LambdaSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The types of lambdas that indicate how they are invoked by FusionAuth.
 *
 * @author Brian Pontarelli
 */
type LambdaType string

func (e LambdaType) String() string {
	return string(e)
}

const (
	LambdaType_JWTPopulate                       LambdaType = "JWTPopulate"
	LambdaType_OpenIDReconcile                   LambdaType = "OpenIDReconcile"
	LambdaType_SAMLv2Reconcile                   LambdaType = "SAMLv2Reconcile"
	LambdaType_SAMLv2Populate                    LambdaType = "SAMLv2Populate"
	LambdaType_AppleReconcile                    LambdaType = "AppleReconcile"
	LambdaType_ExternalJWTReconcile              LambdaType = "ExternalJWTReconcile"
	LambdaType_FacebookReconcile                 LambdaType = "FacebookReconcile"
	LambdaType_GoogleReconcile                   LambdaType = "GoogleReconcile"
	LambdaType_HYPRReconcile                     LambdaType = "HYPRReconcile"
	LambdaType_TwitterReconcile                  LambdaType = "TwitterReconcile"
	LambdaType_LDAPConnectorReconcile            LambdaType = "LDAPConnectorReconcile"
	LambdaType_LinkedInReconcile                 LambdaType = "LinkedInReconcile"
	LambdaType_EpicGamesReconcile                LambdaType = "EpicGamesReconcile"
	LambdaType_NintendoReconcile                 LambdaType = "NintendoReconcile"
	LambdaType_SonyPSNReconcile                  LambdaType = "SonyPSNReconcile"
	LambdaType_SteamReconcile                    LambdaType = "SteamReconcile"
	LambdaType_TwitchReconcile                   LambdaType = "TwitchReconcile"
	LambdaType_XboxReconcile                     LambdaType = "XboxReconcile"
	LambdaType_ClientCredentialsJWTPopulate      LambdaType = "ClientCredentialsJWTPopulate"
	LambdaType_SCIMServerGroupRequestConverter   LambdaType = "SCIMServerGroupRequestConverter"
	LambdaType_SCIMServerGroupResponseConverter  LambdaType = "SCIMServerGroupResponseConverter"
	LambdaType_SCIMServerUserRequestConverter    LambdaType = "SCIMServerUserRequestConverter"
	LambdaType_SCIMServerUserResponseConverter   LambdaType = "SCIMServerUserResponseConverter"
	LambdaType_SelfServiceRegistrationValidation LambdaType = "SelfServiceRegistrationValidation"
	LambdaType_UserInfoPopulate                  LambdaType = "UserInfoPopulate"
	LambdaType_LoginValidation                   LambdaType = "LoginValidation"
)

/**
 * @author Daniel DeGroff
 */
type LinkedInApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LinkedInIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Location information. Useful for IP addresses and other displayable data objects.
 *
 * @author Brian Pontarelli
 */
type Location struct {
	City          string  `json:"city,omitempty"`
	Country       string  `json:"country,omitempty"`
	DisplayString string  `json:"displayString,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	Region        string  `json:"region,omitempty"`
	Zipcode       string  `json:"zipcode,omitempty"`
}

/**
 * A historical state of a user log event. Since events can be modified, this stores the historical state.
 *
 * @author Brian Pontarelli
 */
type LogHistory struct {
	HistoryItems []HistoryItem `json:"historyItems,omitempty"`
}

type HistoryItem struct {
	ActionerUserId string `json:"actionerUserId,omitempty"`
	Comment        string `json:"comment,omitempty"`
	CreateInstant  int64  `json:"createInstant,omitempty"`
	Expiry         int64  `json:"expiry,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginHintConfiguration struct {
	Enableable
	ParameterName string `json:"parameterName,omitempty"`
}

/**
 * Login Ping API request object.
 *
 * @author Daniel DeGroff
 */
type LoginPingRequest struct {
	BaseLoginRequest
	UserId string `json:"userId,omitempty"`
}

/**
 * The summary of the action that is preventing login to be returned on the login response.
 *
 * @author Daniel DeGroff
 */
type LoginPreventedResponse struct {
	BaseHTTPResponse
	ActionerUserId  string `json:"actionerUserId,omitempty"`
	ActionId        string `json:"actionId,omitempty"`
	Expiry          int64  `json:"expiry,omitempty"`
	LocalizedName   string `json:"localizedName,omitempty"`
	LocalizedOption string `json:"localizedOption,omitempty"`
	LocalizedReason string `json:"localizedReason,omitempty"`
	Name            string `json:"name,omitempty"`
	Option          string `json:"option,omitempty"`
	Reason          string `json:"reason,omitempty"`
	ReasonCode      string `json:"reasonCode,omitempty"`
}

func (b *LoginPreventedResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordExportRequest struct {
	BaseExportRequest
	Criteria LoginRecordSearchCriteria `json:"criteria,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordSearchCriteria struct {
	BaseSearchCriteria
	ApplicationId string `json:"applicationId,omitempty"`
	End           int64  `json:"end,omitempty"`
	Start         int64  `json:"start,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordSearchRequest struct {
	RetrieveTotal bool                      `json:"retrieveTotal"`
	Search        LoginRecordSearchCriteria `json:"search,omitempty"`
}

/**
 * A raw login record response
 *
 * @author Daniel DeGroff
 */
type LoginRecordSearchResponse struct {
	BaseHTTPResponse
	Logins []DisplayableRawLogin `json:"logins,omitempty"`
	Total  int64                 `json:"total,omitempty"`
}

func (b *LoginRecordSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Response for the login report.
 *
 * @author Brian Pontarelli
 */
type LoginReportResponse struct {
	BaseHTTPResponse
	HourlyCounts []Count `json:"hourlyCounts,omitempty"`
	Total        int64   `json:"total,omitempty"`
}

func (b *LoginReportResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Login API request object.
 *
 * @author Seth Musselman
 */
type LoginRequest struct {
	BaseLoginRequest
	LoginId          string   `json:"loginId,omitempty"`
	LoginIdTypes     []string `json:"loginIdTypes,omitempty"`
	OneTimePassword  string   `json:"oneTimePassword,omitempty"`
	Password         string   `json:"password,omitempty"`
	TwoFactorTrustId string   `json:"twoFactorTrustId,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type LoginResponse struct {
	BaseHTTPResponse
	Actions                    []LoginPreventedResponse `json:"actions,omitempty"`
	ChangePasswordId           string                   `json:"changePasswordId,omitempty"`
	ChangePasswordReason       ChangePasswordReason     `json:"changePasswordReason,omitempty"`
	ConfigurableMethods        []string                 `json:"configurableMethods,omitempty"`
	EmailVerificationId        string                   `json:"emailVerificationId,omitempty"`
	IdentityVerificationId     string                   `json:"identityVerificationId,omitempty"`
	Methods                    []TwoFactorMethod        `json:"methods,omitempty"`
	PendingIdPLinkId           string                   `json:"pendingIdPLinkId,omitempty"`
	RefreshToken               string                   `json:"refreshToken,omitempty"`
	RefreshTokenId             string                   `json:"refreshTokenId,omitempty"`
	RegistrationVerificationId string                   `json:"registrationVerificationId,omitempty"`
	State                      map[string]interface{}   `json:"state,omitempty"`
	ThreatsDetected            []AuthenticationThreats  `json:"threatsDetected,omitempty"`
	Token                      string                   `json:"token,omitempty"`
	TokenExpirationInstant     int64                    `json:"tokenExpirationInstant,omitempty"`
	TrustToken                 string                   `json:"trustToken,omitempty"`
	TwoFactorId                string                   `json:"twoFactorId,omitempty"`
	TwoFactorTrustId           string                   `json:"twoFactorTrustId,omitempty"`
	User                       User                     `json:"user,omitempty"`
}

func (b *LoginResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Matthew Altman
 */
type LogoutBehavior string

func (e LogoutBehavior) String() string {
	return string(e)
}

const (
	LogoutBehavior_RedirectOnly    LogoutBehavior = "RedirectOnly"
	LogoutBehavior_AllApplications LogoutBehavior = "AllApplications"
)

/**
 * Request for the Logout API that can be used as an alternative to URL parameters.
 *
 * @author Brian Pontarelli
 */
type LogoutRequest struct {
	BaseEventRequest
	Global       bool   `json:"global"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LookupResponse struct {
	BaseHTTPResponse
	IdentityProvider IdentityProviderDetails `json:"identityProvider,omitempty"`
}

func (b *LookupResponse) SetStatus(status int) {
	b.StatusCode = status
}

type IdentityProviderDetails struct {
	ApplicationIds []string                            `json:"applicationIds,omitempty"`
	Id             string                              `json:"id,omitempty"`
	IdpEndpoint    string                              `json:"idpEndpoint,omitempty"`
	Name           string                              `json:"name,omitempty"`
	Oauth2         IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
	Type           IdentityProviderType                `json:"type,omitempty"`
}

/**
 * This class contains the managed fields that are also put into the database during FusionAuth setup.
 * <p>
 * Internal Note: These fields are also declared in SQL in order to bootstrap the system. These need to stay in sync.
 * Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
 *
 * @author Brian Pontarelli
 */
type ManagedFields struct {
}

/**
 * @author Daniel DeGroff
 */
type MaximumPasswordAge struct {
	Enableable
	Days int `json:"days,omitempty"`
}

/**
 * Group Member Delete Request
 *
 * @author Daniel DeGroff
 */
type MemberDeleteRequest struct {
	MemberIds []string            `json:"memberIds,omitempty"`
	Members   map[string][]string `json:"members,omitempty"`
}

/**
 * Group Member Request
 *
 * @author Daniel DeGroff
 */
type MemberRequest struct {
	Members map[string][]GroupMember `json:"members,omitempty"`
}

/**
 * Group Member Response
 *
 * @author Daniel DeGroff
 */
type MemberResponse struct {
	BaseHTTPResponse
	Members map[string][]GroupMember `json:"members,omitempty"`
}

func (b *MemberResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Mikey Sleevi
 */
type Message struct {
}

/**
 * Stores an message template used to distribute messages;
 *
 * @author Michael Sleevi
 */
type MessageTemplate struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Type              MessageType            `json:"type,omitempty"`
}

/**
 * A Message Template Request to the API
 *
 * @author Michael Sleevi
 */
type MessageTemplateRequest struct {
	MessageTemplate MessageTemplate `json:"messageTemplate,omitempty"`
}

/**
 * @author Michael Sleevi
 */
type MessageTemplateResponse struct {
	BaseHTTPResponse
	MessageTemplate  MessageTemplate   `json:"messageTemplate,omitempty"`
	MessageTemplates []MessageTemplate `json:"messageTemplates,omitempty"`
}

func (b *MessageTemplateResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Mikey Sleevi
 */
type MessageType string

func (e MessageType) String() string {
	return string(e)
}

const (
	MessageType_SMS MessageType = "SMS"
)

/**
 * @author Brett Guy
 */
type MessengerRequest struct {
	Messenger BaseMessengerConfiguration `json:"messenger,omitempty"`
}

/**
 * @author Brett Guy
 */
type MessengerResponse struct {
	BaseHTTPResponse
	Messenger  BaseMessengerConfiguration   `json:"messenger,omitempty"`
	Messengers []BaseMessengerConfiguration `json:"messengers,omitempty"`
}

func (b *MessengerResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type MessengerTransport struct {
}

/**
 * @author Brett Guy
 */
type MessengerType string

func (e MessengerType) String() string {
	return string(e)
}

const (
	MessengerType_Generic MessengerType = "Generic"
	MessengerType_Kafka   MessengerType = "Kafka"
	MessengerType_Twilio  MessengerType = "Twilio"
)

/**
 * @author Daniel DeGroff
 */
type MinimumPasswordAge struct {
	Enableable
	Seconds int `json:"seconds,omitempty"`
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
type MonthlyActiveUserReportResponse struct {
	BaseHTTPResponse
	MonthlyActiveUsers []Count `json:"monthlyActiveUsers,omitempty"`
	Total              int64   `json:"total,omitempty"`
}

func (b *MonthlyActiveUserReportResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type MultiFactorLoginPolicy string

func (e MultiFactorLoginPolicy) String() string {
	return string(e)
}

const (
	MultiFactorLoginPolicy_Disabled MultiFactorLoginPolicy = "Disabled"
	MultiFactorLoginPolicy_Enabled  MultiFactorLoginPolicy = "Enabled"
	MultiFactorLoginPolicy_Required MultiFactorLoginPolicy = "Required"
)

/**
 * @author Brett Pontarelli
 */
type NintendoApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText    string `json:"buttonText,omitempty"`
	ClientId      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	EmailClaim    string `json:"emailClaim,omitempty"`
	Scope         string `json:"scope,omitempty"`
	UniqueIdClaim string `json:"uniqueIdClaim,omitempty"`
	UsernameClaim string `json:"usernameClaim,omitempty"`
}

/**
 * Nintendo gaming login provider.
 *
 * @author Brett Pontarelli
 */
type NintendoIdentityProvider struct {
	BaseIdentityProvider
	ButtonText    string `json:"buttonText,omitempty"`
	ClientId      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	EmailClaim    string `json:"emailClaim,omitempty"`
	Scope         string `json:"scope,omitempty"`
	UniqueIdClaim string `json:"uniqueIdClaim,omitempty"`
	UsernameClaim string `json:"usernameClaim,omitempty"`
}

/**
 * A marker interface indicating this event cannot be made transactional.
 *
 * @author Daniel DeGroff
 */
type NonTransactionalEvent struct {
}

/**
 * @author Daniel DeGroff
 */
type OAuth2Configuration struct {
	AuthorizedOriginURLs          []string                            `json:"authorizedOriginURLs,omitempty"`
	AuthorizedRedirectURLs        []string                            `json:"authorizedRedirectURLs,omitempty"`
	AuthorizedURLValidationPolicy Oauth2AuthorizedURLValidationPolicy `json:"authorizedURLValidationPolicy,omitempty"`
	ClientAuthenticationPolicy    ClientAuthenticationPolicy          `json:"clientAuthenticationPolicy,omitempty"`
	ClientId                      string                              `json:"clientId,omitempty"`
	ClientSecret                  string                              `json:"clientSecret,omitempty"`
	ConsentMode                   OAuthScopeConsentMode               `json:"consentMode,omitempty"`
	Debug                         bool                                `json:"debug"`
	DeviceVerificationURL         string                              `json:"deviceVerificationURL,omitempty"`
	EnabledGrants                 []GrantType                         `json:"enabledGrants,omitempty"`
	GenerateRefreshTokens         bool                                `json:"generateRefreshTokens"`
	LogoutBehavior                LogoutBehavior                      `json:"logoutBehavior,omitempty"`
	LogoutURL                     string                              `json:"logoutURL,omitempty"`
	ProofKeyForCodeExchangePolicy ProofKeyForCodeExchangePolicy       `json:"proofKeyForCodeExchangePolicy,omitempty"`
	ProvidedScopePolicy           ProvidedScopePolicy                 `json:"providedScopePolicy,omitempty"`
	Relationship                  OAuthApplicationRelationship        `json:"relationship,omitempty"`
	RequireClientAuthentication   bool                                `json:"requireClientAuthentication"`
	RequireRegistration           bool                                `json:"requireRegistration"`
	ScopeHandlingPolicy           OAuthScopeHandlingPolicy            `json:"scopeHandlingPolicy,omitempty"`
	UnknownScopePolicy            UnknownScopePolicy                  `json:"unknownScopePolicy,omitempty"`
}

/**
 * The application's relationship to the authorization server. First-party applications will be granted implicit permission for requested scopes.
 * Third-party applications will use the {@link OAuthScopeConsentMode} policy.
 *
 * @author Spencer Witt
 */
type OAuthApplicationRelationship string

func (e OAuthApplicationRelationship) String() string {
	return string(e)
}

const (
	OAuthApplicationRelationship_FirstParty OAuthApplicationRelationship = "FirstParty"
	OAuthApplicationRelationship_ThirdParty OAuthApplicationRelationship = "ThirdParty"
)

/**
 * @author Daniel DeGroff
 */
type OAuthConfigurationResponse struct {
	BaseHTTPResponse
	HttpSessionMaxInactiveInterval int                 `json:"httpSessionMaxInactiveInterval,omitempty"`
	LogoutURL                      string              `json:"logoutURL,omitempty"`
	OauthConfiguration             OAuth2Configuration `json:"oauthConfiguration,omitempty"`
}

func (b *OAuthConfigurationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type OAuthError struct {
	ChangePasswordId string            `json:"change_password_id,omitempty"`
	Error            OAuthErrorType    `json:"error,omitempty"`
	ErrorDescription string            `json:"error_description,omitempty"`
	ErrorReason      OAuthErrorReason  `json:"error_reason,omitempty"`
	ErrorUri         string            `json:"error_uri,omitempty"`
	TwoFactorId      string            `json:"two_factor_id,omitempty"`
	TwoFactorMethods []TwoFactorMethod `json:"two_factor_methods,omitempty"`
}

type OAuthErrorReason string

func (e OAuthErrorReason) String() string {
	return string(e)
}

const (
	OAuthErrorReason_AuthCodeNotFound                    OAuthErrorReason = "auth_code_not_found"
	OAuthErrorReason_AccessTokenMalformed                OAuthErrorReason = "access_token_malformed"
	OAuthErrorReason_AccessTokenExpired                  OAuthErrorReason = "access_token_expired"
	OAuthErrorReason_AccessTokenUnavailableForProcessing OAuthErrorReason = "access_token_unavailable_for_processing"
	OAuthErrorReason_AccessTokenFailedProcessing         OAuthErrorReason = "access_token_failed_processing"
	OAuthErrorReason_AccessTokenInvalid                  OAuthErrorReason = "access_token_invalid"
	OAuthErrorReason_AccessTokenRequired                 OAuthErrorReason = "access_token_required"
	OAuthErrorReason_RefreshTokenNotFound                OAuthErrorReason = "refresh_token_not_found"
	OAuthErrorReason_RefreshTokenTypeNotSupported        OAuthErrorReason = "refresh_token_type_not_supported"
	OAuthErrorReason_InvalidClientId                     OAuthErrorReason = "invalid_client_id"
	OAuthErrorReason_InvalidExpiresIn                    OAuthErrorReason = "invalid_expires_in"
	OAuthErrorReason_InvalidUserCredentials              OAuthErrorReason = "invalid_user_credentials"
	OAuthErrorReason_InvalidGrantType                    OAuthErrorReason = "invalid_grant_type"
	OAuthErrorReason_InvalidOrigin                       OAuthErrorReason = "invalid_origin"
	OAuthErrorReason_InvalidOriginOpaque                 OAuthErrorReason = "invalid_origin_opaque"
	OAuthErrorReason_InvalidPkceCodeVerifier             OAuthErrorReason = "invalid_pkce_code_verifier"
	OAuthErrorReason_InvalidPkceCodeChallenge            OAuthErrorReason = "invalid_pkce_code_challenge"
	OAuthErrorReason_InvalidPkceCodeChallengeMethod      OAuthErrorReason = "invalid_pkce_code_challenge_method"
	OAuthErrorReason_InvalidRedirectUri                  OAuthErrorReason = "invalid_redirect_uri"
	OAuthErrorReason_InvalidResponseMode                 OAuthErrorReason = "invalid_response_mode"
	OAuthErrorReason_InvalidResponseType                 OAuthErrorReason = "invalid_response_type"
	OAuthErrorReason_InvalidIdTokenHint                  OAuthErrorReason = "invalid_id_token_hint"
	OAuthErrorReason_InvalidPostLogoutRedirectUri        OAuthErrorReason = "invalid_post_logout_redirect_uri"
	OAuthErrorReason_InvalidDeviceCode                   OAuthErrorReason = "invalid_device_code"
	OAuthErrorReason_InvalidUserCode                     OAuthErrorReason = "invalid_user_code"
	OAuthErrorReason_InvalidAdditionalClientId           OAuthErrorReason = "invalid_additional_client_id"
	OAuthErrorReason_InvalidTargetEntityScope            OAuthErrorReason = "invalid_target_entity_scope"
	OAuthErrorReason_InvalidEntityPermissionScope        OAuthErrorReason = "invalid_entity_permission_scope"
	OAuthErrorReason_InvalidUserId                       OAuthErrorReason = "invalid_user_id"
	OAuthErrorReason_InvalidTenantId                     OAuthErrorReason = "invalid_tenant_id"
	OAuthErrorReason_GrantTypeDisabled                   OAuthErrorReason = "grant_type_disabled"
	OAuthErrorReason_MissingClientId                     OAuthErrorReason = "missing_client_id"
	OAuthErrorReason_MissingClientSecret                 OAuthErrorReason = "missing_client_secret"
	OAuthErrorReason_MissingCode                         OAuthErrorReason = "missing_code"
	OAuthErrorReason_MissingCodeChallenge                OAuthErrorReason = "missing_code_challenge"
	OAuthErrorReason_MissingCodeVerifier                 OAuthErrorReason = "missing_code_verifier"
	OAuthErrorReason_MissingDeviceCode                   OAuthErrorReason = "missing_device_code"
	OAuthErrorReason_MissingGrantType                    OAuthErrorReason = "missing_grant_type"
	OAuthErrorReason_MissingRedirectUri                  OAuthErrorReason = "missing_redirect_uri"
	OAuthErrorReason_MissingRefreshToken                 OAuthErrorReason = "missing_refresh_token"
	OAuthErrorReason_MissingResponseType                 OAuthErrorReason = "missing_response_type"
	OAuthErrorReason_MissingToken                        OAuthErrorReason = "missing_token"
	OAuthErrorReason_MissingUserCode                     OAuthErrorReason = "missing_user_code"
	OAuthErrorReason_MissingUserId                       OAuthErrorReason = "missing_user_id"
	OAuthErrorReason_MissingVerificationUri              OAuthErrorReason = "missing_verification_uri"
	OAuthErrorReason_MissingTenantId                     OAuthErrorReason = "missing_tenant_id"
	OAuthErrorReason_LoginPrevented                      OAuthErrorReason = "login_prevented"
	OAuthErrorReason_NotLicensed                         OAuthErrorReason = "not_licensed"
	OAuthErrorReason_UserCodeExpired                     OAuthErrorReason = "user_code_expired"
	OAuthErrorReason_UserExpired                         OAuthErrorReason = "user_expired"
	OAuthErrorReason_UserLocked                          OAuthErrorReason = "user_locked"
	OAuthErrorReason_UserNotFound                        OAuthErrorReason = "user_not_found"
	OAuthErrorReason_ClientAuthenticationMissing         OAuthErrorReason = "client_authentication_missing"
	OAuthErrorReason_InvalidClientAuthenticationScheme   OAuthErrorReason = "invalid_client_authentication_scheme"
	OAuthErrorReason_InvalidClientAuthentication         OAuthErrorReason = "invalid_client_authentication"
	OAuthErrorReason_ClientIdMismatch                    OAuthErrorReason = "client_id_mismatch"
	OAuthErrorReason_ChangePasswordAdministrative        OAuthErrorReason = "change_password_administrative"
	OAuthErrorReason_ChangePasswordBreached              OAuthErrorReason = "change_password_breached"
	OAuthErrorReason_ChangePasswordExpired               OAuthErrorReason = "change_password_expired"
	OAuthErrorReason_ChangePasswordValidation            OAuthErrorReason = "change_password_validation"
	OAuthErrorReason_Unknown                             OAuthErrorReason = "unknown"
	OAuthErrorReason_MissingRequiredScope                OAuthErrorReason = "missing_required_scope"
	OAuthErrorReason_UnknownScope                        OAuthErrorReason = "unknown_scope"
	OAuthErrorReason_ConsentCanceled                     OAuthErrorReason = "consent_canceled"
)

type OAuthErrorType string

func (e OAuthErrorType) String() string {
	return string(e)
}

const (
	OAuthErrorType_InvalidRequest          OAuthErrorType = "invalid_request"
	OAuthErrorType_InvalidClient           OAuthErrorType = "invalid_client"
	OAuthErrorType_InvalidGrant            OAuthErrorType = "invalid_grant"
	OAuthErrorType_InvalidToken            OAuthErrorType = "invalid_token"
	OAuthErrorType_UnauthorizedClient      OAuthErrorType = "unauthorized_client"
	OAuthErrorType_InvalidScope            OAuthErrorType = "invalid_scope"
	OAuthErrorType_ServerError             OAuthErrorType = "server_error"
	OAuthErrorType_UnsupportedGrantType    OAuthErrorType = "unsupported_grant_type"
	OAuthErrorType_UnsupportedResponseType OAuthErrorType = "unsupported_response_type"
	OAuthErrorType_AccessDenied            OAuthErrorType = "access_denied"
	OAuthErrorType_ChangePasswordRequired  OAuthErrorType = "change_password_required"
	OAuthErrorType_NotLicensed             OAuthErrorType = "not_licensed"
	OAuthErrorType_TwoFactorRequired       OAuthErrorType = "two_factor_required"
	OAuthErrorType_AuthorizationPending    OAuthErrorType = "authorization_pending"
	OAuthErrorType_ExpiredToken            OAuthErrorType = "expired_token"
	OAuthErrorType_UnsupportedTokenType    OAuthErrorType = "unsupported_token_type"
)

/**
 * @author Daniel DeGroff
 */
type OAuthResponse struct {
	BaseHTTPResponse
}

func (b *OAuthResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Controls the policy for requesting user permission to grant access to requested scopes during an OAuth workflow
 * for a third-party application.
 *
 * @author Spencer Witt
 */
type OAuthScopeConsentMode string

func (e OAuthScopeConsentMode) String() string {
	return string(e)
}

const (
	OAuthScopeConsentMode_AlwaysPrompt     OAuthScopeConsentMode = "AlwaysPrompt"
	OAuthScopeConsentMode_RememberDecision OAuthScopeConsentMode = "RememberDecision"
	OAuthScopeConsentMode_NeverPrompt      OAuthScopeConsentMode = "NeverPrompt"
)

/**
 * Controls the policy for whether OAuth workflows will more strictly adhere to the OAuth and OIDC specification
 * or run in backwards compatibility mode.
 *
 * @author David Charles
 */
type OAuthScopeHandlingPolicy string

func (e OAuthScopeHandlingPolicy) String() string {
	return string(e)
}

const (
	OAuthScopeHandlingPolicy_Compatibility OAuthScopeHandlingPolicy = "Compatibility"
	OAuthScopeHandlingPolicy_Strict        OAuthScopeHandlingPolicy = "Strict"
)

/**
 * @author Johnathon Wood
 */
type Oauth2AuthorizedURLValidationPolicy string

func (e Oauth2AuthorizedURLValidationPolicy) String() string {
	return string(e)
}

const (
	Oauth2AuthorizedURLValidationPolicy_AllowWildcards Oauth2AuthorizedURLValidationPolicy = "AllowWildcards"
	Oauth2AuthorizedURLValidationPolicy_ExactMatch     Oauth2AuthorizedURLValidationPolicy = "ExactMatch"
)

/**
 * A marker interface indicating this event is an event that can supply a linked object Id.
 *
 * @author Spencer Witt
 */
type ObjectIdentifiable struct {
}

/**
 * @author Daniel DeGroff
 */
type ObjectState string

func (e ObjectState) String() string {
	return string(e)
}

const (
	ObjectState_Active        ObjectState = "Active"
	ObjectState_Inactive      ObjectState = "Inactive"
	ObjectState_PendingDelete ObjectState = "PendingDelete"
)

/**
 * OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
 * Provider Metadata</a>.
 *
 * @author Daniel DeGroff
 */
type OpenIdConfiguration struct {
	BaseHTTPResponse
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	FrontchannelLogoutSupported       bool     `json:"frontchannel_logout_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	Issuer                            string   `json:"issuer,omitempty"`
	JwksUri                           string   `json:"jwks_uri,omitempty"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`
}

func (b *OpenIdConfiguration) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type OpenIdConnectApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonImageURL string                              `json:"buttonImageURL,omitempty"`
	ButtonText     string                              `json:"buttonText,omitempty"`
	Oauth2         IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type OpenIdConnectIdentityProvider struct {
	BaseIdentityProvider
	ButtonImageURL string                              `json:"buttonImageURL,omitempty"`
	ButtonText     string                              `json:"buttonText,omitempty"`
	Domains        []string                            `json:"domains,omitempty"`
	Oauth2         IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
	PostRequest    bool                                `json:"postRequest"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordBreachDetection struct {
	Enableable
	MatchMode                 BreachMatchMode `json:"matchMode,omitempty"`
	NotifyUserEmailTemplateId string          `json:"notifyUserEmailTemplateId,omitempty"`
	OnLogin                   BreachAction    `json:"onLogin,omitempty"`
}

type BreachAction string

func (e BreachAction) String() string {
	return string(e)
}

const (
	BreachAction_Off           BreachAction = "Off"
	BreachAction_RecordOnly    BreachAction = "RecordOnly"
	BreachAction_NotifyUser    BreachAction = "NotifyUser"
	BreachAction_RequireChange BreachAction = "RequireChange"
)

type BreachMatchMode string

func (e BreachMatchMode) String() string {
	return string(e)
}

const (
	BreachMatchMode_Low    BreachMatchMode = "Low"
	BreachMatchMode_Medium BreachMatchMode = "Medium"
	BreachMatchMode_High   BreachMatchMode = "High"
)

/**
 * Password Encryption Scheme Configuration
 *
 * @author Daniel DeGroff
 */
type PasswordEncryptionConfiguration struct {
	EncryptionScheme              string `json:"encryptionScheme,omitempty"`
	EncryptionSchemeFactor        int    `json:"encryptionSchemeFactor,omitempty"`
	ModifyEncryptionSchemeOnLogin bool   `json:"modifyEncryptionSchemeOnLogin"`
}

/**
 * @author Derek Klatt
 */
type PasswordValidationRules struct {
	BreachDetection           PasswordBreachDetection   `json:"breachDetection,omitempty"`
	MaxLength                 int                       `json:"maxLength,omitempty"`
	MinLength                 int                       `json:"minLength,omitempty"`
	RememberPreviousPasswords RememberPreviousPasswords `json:"rememberPreviousPasswords,omitempty"`
	RequireMixedCase          bool                      `json:"requireMixedCase"`
	RequireNonAlpha           bool                      `json:"requireNonAlpha"`
	RequireNumber             bool                      `json:"requireNumber"`
	ValidateOnLogin           bool                      `json:"validateOnLogin"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordValidationRulesResponse struct {
	BaseHTTPResponse
	PasswordValidationRules PasswordValidationRules `json:"passwordValidationRules,omitempty"`
}

func (b *PasswordValidationRulesResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Interface for all identity providers that are passwordless and do not accept a password.
 */
type PasswordlessIdentityProvider struct {
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessLoginRequest struct {
	BaseLoginRequest
	Code             string `json:"code,omitempty"`
	OneTimeCode      string `json:"oneTimeCode,omitempty"`
	TwoFactorTrustId string `json:"twoFactorTrustId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessSendRequest struct {
	ApplicationId string                 `json:"applicationId,omitempty"`
	Code          string                 `json:"code,omitempty"`
	LoginId       string                 `json:"loginId,omitempty"`
	State         map[string]interface{} `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessStartRequest struct {
	ApplicationId string                 `json:"applicationId,omitempty"`
	LoginId       string                 `json:"loginId,omitempty"`
	LoginIdTypes  []string               `json:"loginIdTypes,omitempty"`
	LoginStrategy PasswordlessStrategy   `json:"loginStrategy,omitempty"`
	State         map[string]interface{} `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessStartResponse struct {
	BaseHTTPResponse
	Code        string `json:"code,omitempty"`
	OneTimeCode string `json:"oneTimeCode,omitempty"`
}

func (b *PasswordlessStartResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessStrategy string

func (e PasswordlessStrategy) String() string {
	return string(e)
}

const (
	PasswordlessStrategy_ClickableLink PasswordlessStrategy = "ClickableLink"
	PasswordlessStrategy_FormField     PasswordlessStrategy = "FormField"
)

/**
 * @author Daniel DeGroff
 */
type PendingIdPLink struct {
	DisplayName                         string                              `json:"displayName,omitempty"`
	Email                               string                              `json:"email,omitempty"`
	IdentityProviderId                  string                              `json:"identityProviderId,omitempty"`
	IdentityProviderLinks               []IdentityProviderLink              `json:"identityProviderLinks,omitempty"`
	IdentityProviderName                string                              `json:"identityProviderName,omitempty"`
	IdentityProviderTenantConfiguration IdentityProviderTenantConfiguration `json:"identityProviderTenantConfiguration,omitempty"`
	IdentityProviderType                IdentityProviderType                `json:"identityProviderType,omitempty"`
	IdentityProviderUserId              string                              `json:"identityProviderUserId,omitempty"`
	User                                User                                `json:"user,omitempty"`
	Username                            string                              `json:"username,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type PendingResponse struct {
	BaseHTTPResponse
	Users []User `json:"users,omitempty"`
}

func (b *PendingResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Configuration for unverified phone number identities.
 *
 * @author Spencer Witt
 */
type PhoneUnverifiedOptions struct {
	AllowPhoneNumberChangeWhenGated bool               `json:"allowPhoneNumberChangeWhenGated"`
	Behavior                        UnverifiedBehavior `json:"behavior,omitempty"`
}

/**
 * @author Michael Sleevi
 */
type PreviewMessageTemplateRequest struct {
	Locale          string          `json:"locale,omitempty"`
	MessageTemplate MessageTemplate `json:"messageTemplate,omitempty"`
}

/**
 * @author Michael Sleevi
 */
type PreviewMessageTemplateResponse struct {
	BaseHTTPResponse
	Errors  Errors     `json:"errors,omitempty"`
	Message SMSMessage `json:"message,omitempty"`
}

func (b *PreviewMessageTemplateResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type PreviewRequest struct {
	EmailTemplate EmailTemplate `json:"emailTemplate,omitempty"`
	Locale        string        `json:"locale,omitempty"`
}

/**
 * @author Seth Musselman
 */
type PreviewResponse struct {
	BaseHTTPResponse
	Email  Email  `json:"email,omitempty"`
	Errors Errors `json:"errors,omitempty"`
}

func (b *PreviewResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brett Guy
 */
type ProofKeyForCodeExchangePolicy string

func (e ProofKeyForCodeExchangePolicy) String() string {
	return string(e)
}

const (
	ProofKeyForCodeExchangePolicy_Required                                 ProofKeyForCodeExchangePolicy = "Required"
	ProofKeyForCodeExchangePolicy_NotRequired                              ProofKeyForCodeExchangePolicy = "NotRequired"
	ProofKeyForCodeExchangePolicy_NotRequiredWhenUsingClientAuthentication ProofKeyForCodeExchangePolicy = "NotRequiredWhenUsingClientAuthentication"
)

/**
 * The handling policy for scopes provided by FusionAuth
 *
 * @author Spencer Witt
 */
type ProvidedScopePolicy struct {
	Address Requirable `json:"address,omitempty"`
	Email   Requirable `json:"email,omitempty"`
	Phone   Requirable `json:"phone,omitempty"`
	Profile Requirable `json:"profile,omitempty"`
}

/**
 * Allows the Relying Party to specify desired attributes of a new credential.
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialCreationOptions struct {
	Attestation            AttestationConveyancePreference       `json:"attestation,omitempty"`
	AuthenticatorSelection AuthenticatorSelectionCriteria        `json:"authenticatorSelection,omitempty"`
	Challenge              string                                `json:"challenge,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor       `json:"excludeCredentials,omitempty"`
	Extensions             WebAuthnRegistrationExtensionOptions  `json:"extensions,omitempty"`
	PubKeyCredParams       []PublicKeyCredentialParameters       `json:"pubKeyCredParams,omitempty"`
	Rp                     PublicKeyCredentialRelyingPartyEntity `json:"rp,omitempty"`
	Timeout                int64                                 `json:"timeout,omitempty"`
	User                   PublicKeyCredentialUserEntity         `json:"user,omitempty"`
}

/**
 * Contains attributes for the Relying Party to refer to an existing public key credential as an input parameter.
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialDescriptor struct {
	Id         string                  `json:"id,omitempty"`
	Transports []string                `json:"transports,omitempty"`
	Type       PublicKeyCredentialType `json:"type,omitempty"`
}

/**
 * Describes a user account or WebAuthn Relying Party associated with a public key credential
 */
type PublicKeyCredentialEntity struct {
	Name string `json:"name,omitempty"`
}

/**
 * Supply information on credential type and algorithm to the <i>authenticator</i>.
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialParameters struct {
	Alg  CoseAlgorithmIdentifier `json:"alg,omitempty"`
	Type PublicKeyCredentialType `json:"type,omitempty"`
}

/**
 * Supply additional information about the Relying Party when creating a new credential
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialRelyingPartyEntity struct {
	PublicKeyCredentialEntity
	Id string `json:"id,omitempty"`
}

/**
 * Provides the <i>authenticator</i> with the data it needs to generate an assertion.
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialRequestOptions struct {
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	Challenge        string                          `json:"challenge,omitempty"`
	RpId             string                          `json:"rpId,omitempty"`
	Timeout          int64                           `json:"timeout,omitempty"`
	UserVerification UserVerificationRequirement     `json:"userVerification,omitempty"`
}

/**
 * Defines valid credential types. This is an extension point in the WebAuthn spec. The only defined value at this time is "public-key"
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialType string

func (e PublicKeyCredentialType) String() string {
	return string(e)
}

const (
	PublicKeyCredentialType_PublicKey PublicKeyCredentialType = "publicKey"
)

/**
 * Supply additional information about the user account when creating a new credential
 *
 * @author Spencer Witt
 */
type PublicKeyCredentialUserEntity struct {
	PublicKeyCredentialEntity
	DisplayName string `json:"displayName,omitempty"`
	Id          string `json:"id,omitempty"`
}

/**
 * JWT Public Key Response Object
 *
 * @author Daniel DeGroff
 */
type PublicKeyResponse struct {
	BaseHTTPResponse
	PublicKey  string            `json:"publicKey,omitempty"`
	PublicKeys map[string]string `json:"publicKeys,omitempty"`
}

func (b *PublicKeyResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type RateLimitedRequestConfiguration struct {
	Enableable
	Limit               int `json:"limit,omitempty"`
	TimePeriodInSeconds int `json:"timePeriodInSeconds,omitempty"`
}

/**
 * Raw login information for each time a user logs into an application.
 *
 * @author Brian Pontarelli
 */
type RawLogin struct {
	ApplicationId string `json:"applicationId,omitempty"`
	Instant       int64  `json:"instant,omitempty"`
	IpAddress     string `json:"ipAddress,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type ReactorFeatureStatus string

func (e ReactorFeatureStatus) String() string {
	return string(e)
}

const (
	ReactorFeatureStatus_ACTIVE       ReactorFeatureStatus = "ACTIVE"
	ReactorFeatureStatus_DISCONNECTED ReactorFeatureStatus = "DISCONNECTED"
	ReactorFeatureStatus_PENDING      ReactorFeatureStatus = "PENDING"
	ReactorFeatureStatus_DISABLED     ReactorFeatureStatus = "DISABLED"
	ReactorFeatureStatus_UNKNOWN      ReactorFeatureStatus = "UNKNOWN"
)

/**
 * @author Daniel DeGroff
 */
type ReactorMetrics struct {
	BreachedPasswordMetrics map[string]BreachedPasswordTenantMetric `json:"breachedPasswordMetrics,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ReactorMetricsResponse struct {
	BaseHTTPResponse
	Metrics ReactorMetrics `json:"metrics,omitempty"`
}

func (b *ReactorMetricsResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Request for managing FusionAuth Reactor and licenses.
 *
 * @author Brian Pontarelli
 */
type ReactorRequest struct {
	License   string `json:"license,omitempty"`
	LicenseId string `json:"licenseId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ReactorResponse struct {
	BaseHTTPResponse
	Status ReactorStatus `json:"status,omitempty"`
}

func (b *ReactorResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type ReactorStatus struct {
	AdvancedIdentityProviders                 ReactorFeatureStatus `json:"advancedIdentityProviders,omitempty"`
	AdvancedLambdas                           ReactorFeatureStatus `json:"advancedLambdas,omitempty"`
	AdvancedMultiFactorAuthentication         ReactorFeatureStatus `json:"advancedMultiFactorAuthentication,omitempty"`
	AdvancedOAuthScopes                       ReactorFeatureStatus `json:"advancedOAuthScopes,omitempty"`
	AdvancedOAuthScopesCustomScopes           ReactorFeatureStatus `json:"advancedOAuthScopesCustomScopes,omitempty"`
	AdvancedOAuthScopesThirdPartyApplications ReactorFeatureStatus `json:"advancedOAuthScopesThirdPartyApplications,omitempty"`
	AdvancedRegistration                      ReactorFeatureStatus `json:"advancedRegistration,omitempty"`
	ApplicationMultiFactorAuthentication      ReactorFeatureStatus `json:"applicationMultiFactorAuthentication,omitempty"`
	ApplicationThemes                         ReactorFeatureStatus `json:"applicationThemes,omitempty"`
	BreachedPasswordDetection                 ReactorFeatureStatus `json:"breachedPasswordDetection,omitempty"`
	Connectors                                ReactorFeatureStatus `json:"connectors,omitempty"`
	EntityManagement                          ReactorFeatureStatus `json:"entityManagement,omitempty"`
	Expiration                                string               `json:"expiration,omitempty"`
	LicenseAttributes                         map[string]string    `json:"licenseAttributes,omitempty"`
	Licensed                                  bool                 `json:"licensed"`
	ScimServer                                ReactorFeatureStatus `json:"scimServer,omitempty"`
	TenantManagerApplication                  ReactorFeatureStatus `json:"tenantManagerApplication,omitempty"`
	ThreatDetection                           ReactorFeatureStatus `json:"threatDetection,omitempty"`
	UniversalApplication                      ReactorFeatureStatus `json:"universalApplication,omitempty"`
	WebAuthn                                  ReactorFeatureStatus `json:"webAuthn,omitempty"`
	WebAuthnPlatformAuthenticators            ReactorFeatureStatus `json:"webAuthnPlatformAuthenticators,omitempty"`
	WebAuthnRoamingAuthenticators             ReactorFeatureStatus `json:"webAuthnRoamingAuthenticators,omitempty"`
}

/**
 * Response for the user login report.
 *
 * @author Seth Musselman
 */
type RecentLoginResponse struct {
	BaseHTTPResponse
	Logins []DisplayableRawLogin `json:"logins,omitempty"`
}

func (b *RecentLoginResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type RefreshRequest struct {
	BaseEventRequest
	RefreshToken        string `json:"refreshToken,omitempty"`
	TimeToLiveInSeconds int    `json:"timeToLiveInSeconds,omitempty"`
	Token               string `json:"token,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RefreshResponse struct {
	BaseHTTPResponse
}

func (b *RefreshResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models a JWT Refresh Token.
 *
 * @author Daniel DeGroff
 */
type RefreshToken struct {
	ApplicationId string                 `json:"applicationId,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Id            string                 `json:"id,omitempty"`
	InsertInstant int64                  `json:"insertInstant,omitempty"`
	MetaData      MetaData               `json:"metaData,omitempty"`
	StartInstant  int64                  `json:"startInstant,omitempty"`
	TenantId      string                 `json:"tenantId,omitempty"`
	Token         string                 `json:"token,omitempty"`
	UserId        string                 `json:"userId,omitempty"`
}

type MetaData struct {
	Data   map[string]interface{} `json:"data,omitempty"`
	Device DeviceInfo             `json:"device,omitempty"`
	Scopes []string               `json:"scopes,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RefreshTokenExpirationPolicy string

func (e RefreshTokenExpirationPolicy) String() string {
	return string(e)
}

const (
	RefreshTokenExpirationPolicy_Fixed                            RefreshTokenExpirationPolicy = "Fixed"
	RefreshTokenExpirationPolicy_SlidingWindow                    RefreshTokenExpirationPolicy = "SlidingWindow"
	RefreshTokenExpirationPolicy_SlidingWindowWithMaximumLifetime RefreshTokenExpirationPolicy = "SlidingWindowWithMaximumLifetime"
)

/**
 * Refresh Token Import request.
 *
 * @author Brett Guy
 */
type RefreshTokenImportRequest struct {
	RefreshTokens         []RefreshToken `json:"refreshTokens,omitempty"`
	ValidateDbConstraints bool           `json:"validateDbConstraints"`
}

/**
 * Refresh token one-time use configuration. This configuration is utilized when the usage policy is
 * configured for one-time use.
 *
 * @author Daniel DeGroff
 */
type RefreshTokenOneTimeUseConfiguration struct {
	GracePeriodInSeconds int `json:"gracePeriodInSeconds,omitempty"`
}

/**
 * API response for retrieving Refresh Tokens
 *
 * @author Daniel DeGroff
 */
type RefreshTokenResponse struct {
	BaseHTTPResponse
	RefreshToken  RefreshToken   `json:"refreshToken,omitempty"`
	RefreshTokens []RefreshToken `json:"refreshTokens,omitempty"`
}

func (b *RefreshTokenResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type RefreshTokenRevocationPolicy struct {
	OnLoginPrevented    bool `json:"onLoginPrevented"`
	OnMultiFactorEnable bool `json:"onMultiFactorEnable"`
	OnOneTimeTokenReuse bool `json:"onOneTimeTokenReuse"`
	OnPasswordChanged   bool `json:"onPasswordChanged"`
}

/**
 * Request for the Refresh Token API to revoke a refresh token rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 */
type RefreshTokenRevokeRequest struct {
	BaseEventRequest
	ApplicationId string `json:"applicationId,omitempty"`
	Token         string `json:"token,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RefreshTokenSlidingWindowConfiguration struct {
	MaximumTimeToLiveInMinutes int `json:"maximumTimeToLiveInMinutes,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RefreshTokenUsagePolicy string

func (e RefreshTokenUsagePolicy) String() string {
	return string(e)
}

const (
	RefreshTokenUsagePolicy_Reusable   RefreshTokenUsagePolicy = "Reusable"
	RefreshTokenUsagePolicy_OneTimeUse RefreshTokenUsagePolicy = "OneTimeUse"
)

/**
 * Registration delete API request object.
 *
 * @author Brian Pontarelli
 */
type RegistrationDeleteRequest struct {
	BaseEventRequest
}

/**
 * Response for the registration report.
 *
 * @author Brian Pontarelli
 */
type RegistrationReportResponse struct {
	BaseHTTPResponse
	HourlyCounts []Count `json:"hourlyCounts,omitempty"`
	Total        int64   `json:"total,omitempty"`
}

func (b *RegistrationReportResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 */
type RegistrationRequest struct {
	BaseEventRequest
	DisableDomainBlock           bool                        `json:"disableDomainBlock"`
	GenerateAuthenticationToken  bool                        `json:"generateAuthenticationToken"`
	Registration                 UserRegistration            `json:"registration,omitempty"`
	SendSetPasswordEmail         bool                        `json:"sendSetPasswordEmail"`
	SendSetPasswordIdentityType  SendSetPasswordIdentityType `json:"sendSetPasswordIdentityType,omitempty"`
	SkipRegistrationVerification bool                        `json:"skipRegistrationVerification"`
	SkipVerification             bool                        `json:"skipVerification"`
	User                         User                        `json:"user,omitempty"`
}

/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 */
type RegistrationResponse struct {
	BaseHTTPResponse
	RefreshToken                        string           `json:"refreshToken,omitempty"`
	RefreshTokenId                      string           `json:"refreshTokenId,omitempty"`
	Registration                        UserRegistration `json:"registration,omitempty"`
	RegistrationVerificationId          string           `json:"registrationVerificationId,omitempty"`
	RegistrationVerificationOneTimeCode string           `json:"registrationVerificationOneTimeCode,omitempty"`
	Token                               string           `json:"token,omitempty"`
	TokenExpirationInstant              int64            `json:"tokenExpirationInstant,omitempty"`
	User                                User             `json:"user,omitempty"`
}

func (b *RegistrationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type RegistrationUnverifiedOptions struct {
	Behavior UnverifiedBehavior `json:"behavior,omitempty"`
}

/**
 * Reindex API request
 *
 * @author Daniel DeGroff
 */
type ReindexRequest struct {
	Index string `json:"index,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ReloadRequest struct {
	Names []string `json:"names,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RememberPreviousPasswords struct {
	Enableable
	Count int `json:"count,omitempty"`
}

/**
 * Something that can be required and thus also optional. This currently extends Enableable because anything that is
 * required/optional is almost always enableable as well.
 *
 * @author Brian Pontarelli
 */
type Requirable struct {
	Enableable
	Required bool `json:"required"`
}

/**
 * Interface describing the need for CORS configuration.
 *
 * @author Daniel DeGroff
 */
type RequiresCORSConfiguration struct {
}

/**
 * Describes the Relying Party's requirements for <a href="https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential">client-side
 * discoverable credentials</a> (formerly known as "resident keys")
 *
 * @author Spencer Witt
 */
type ResidentKeyRequirement string

func (e ResidentKeyRequirement) String() string {
	return string(e)
}

const (
	ResidentKeyRequirement_Discouraged ResidentKeyRequirement = "discouraged"
	ResidentKeyRequirement_Preferred   ResidentKeyRequirement = "preferred"
	ResidentKeyRequirement_Required    ResidentKeyRequirement = "required"
)

/**
 * @author Brian Pontarelli
 */
type SAMLv2ApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonImageURL string `json:"buttonImageURL,omitempty"`
	ButtonText     string `json:"buttonText,omitempty"`
}

/**
 * @author Lyle Schemmerling
 */
type SAMLv2AssertionConfiguration struct {
	Destination SAMLv2DestinationAssertionConfiguration `json:"destination,omitempty"`
}

/**
 * Configuration for encrypted assertions when acting as SAML Service Provider
 *
 * @author Jaret Hendrickson
 */
type SAMLv2AssertionDecryptionConfiguration struct {
	Enableable
	KeyTransportDecryptionKeyId string `json:"keyTransportDecryptionKeyId,omitempty"`
}

/**
 * @author Lyle Schemmerling
 */
type SAMLv2DestinationAssertionConfiguration struct {
	Alternates []string                         `json:"alternates,omitempty"`
	Policy     SAMLv2DestinationAssertionPolicy `json:"policy,omitempty"`
}

/**
 * @author Lyle Schemmerling
 */
type SAMLv2DestinationAssertionPolicy string

func (e SAMLv2DestinationAssertionPolicy) String() string {
	return string(e)
}

const (
	SAMLv2DestinationAssertionPolicy_Enabled         SAMLv2DestinationAssertionPolicy = "Enabled"
	SAMLv2DestinationAssertionPolicy_Disabled        SAMLv2DestinationAssertionPolicy = "Disabled"
	SAMLv2DestinationAssertionPolicy_AllowAlternates SAMLv2DestinationAssertionPolicy = "AllowAlternates"
)

/**
 * @author Daniel DeGroff
 */
type SAMLv2IdPInitiatedApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
}

/**
 * SAML v2 IdP Initiated identity provider configuration.
 *
 * @author Daniel DeGroff
 */
type SAMLv2IdPInitiatedIdentityProvider struct {
	BaseSAMLv2IdentityProvider
	Issuer string `json:"issuer,omitempty"`
}

/**
 * IdP Initiated login configuration
 *
 * @author Daniel DeGroff
 */
type SAMLv2IdPInitiatedLoginConfiguration struct {
	Enableable
	NameIdFormat string `json:"nameIdFormat,omitempty"`
}

/**
 * SAML v2 identity provider configuration.
 *
 * @author Brian Pontarelli
 */
type SAMLv2IdentityProvider struct {
	BaseSAMLv2IdentityProvider
	AssertionConfiguration    SAMLv2AssertionConfiguration    `json:"assertionConfiguration,omitempty"`
	ButtonImageURL            string                          `json:"buttonImageURL,omitempty"`
	ButtonText                string                          `json:"buttonText,omitempty"`
	Domains                   []string                        `json:"domains,omitempty"`
	IdpEndpoint               string                          `json:"idpEndpoint,omitempty"`
	IdpInitiatedConfiguration SAMLv2IdpInitiatedConfiguration `json:"idpInitiatedConfiguration,omitempty"`
	Issuer                    string                          `json:"issuer,omitempty"`
	LoginHintConfiguration    LoginHintConfiguration          `json:"loginHintConfiguration,omitempty"`
	NameIdFormat              string                          `json:"nameIdFormat,omitempty"`
	PostRequest               bool                            `json:"postRequest"`
	RequestSigningKeyId       string                          `json:"requestSigningKeyId,omitempty"`
	SignRequest               bool                            `json:"signRequest"`
	XmlSignatureC14nMethod    CanonicalizationMethod          `json:"xmlSignatureC14nMethod,omitempty"`
}

/**
 * Config for regular SAML IDP configurations that support IdP initiated requests
 *
 * @author Lyle Schemmerling
 */
type SAMLv2IdpInitiatedConfiguration struct {
	Enableable
	Issuer string `json:"issuer,omitempty"`
}

/**
 * @author Michael Sleevi
 */
type SMSMessage struct {
	PhoneNumber string `json:"phoneNumber,omitempty"`
	TextMessage string `json:"textMessage,omitempty"`
}

/**
 * @author Michael Sleevi
 */
type SMSMessageTemplate struct {
	MessageTemplate
	DefaultTemplate    string            `json:"defaultTemplate,omitempty"`
	LocalizedTemplates map[string]string `json:"localizedTemplates,omitempty"`
}

/**
 * Search API request.
 *
 * @author Brian Pontarelli
 */
type SearchRequest struct {
	ExpandableRequest
	Search UserSearchCriteria `json:"search,omitempty"`
}

/**
 * Search API response.
 *
 * @author Brian Pontarelli
 */
type SearchResponse struct {
	BaseHTTPResponse
	ExpandableResponse
	NextResults string `json:"nextResults,omitempty"`
	Total       int64  `json:"total,omitempty"`
	Users       []User `json:"users,omitempty"`
}

func (b *SearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search results.
 *
 * @author Brian Pontarelli
 */
type SearchResults struct {
	NextResults        string        `json:"nextResults,omitempty"`
	Results            []interface{} `json:"results,omitempty"`
	Total              int64         `json:"total,omitempty"`
	TotalEqualToActual bool          `json:"totalEqualToActual"`
}

/**
 * @author Daniel DeGroff
 */
type SecretResponse struct {
	BaseHTTPResponse
	Secret              string `json:"secret,omitempty"`
	SecretBase32Encoded string `json:"secretBase32Encoded,omitempty"`
}

func (b *SecretResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type SecureGeneratorConfiguration struct {
	Length int                 `json:"length,omitempty"`
	Type   SecureGeneratorType `json:"type,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SecureGeneratorType string

func (e SecureGeneratorType) String() string {
	return string(e)
}

const (
	SecureGeneratorType_RandomDigits       SecureGeneratorType = "randomDigits"
	SecureGeneratorType_RandomBytes        SecureGeneratorType = "randomBytes"
	SecureGeneratorType_RandomAlpha        SecureGeneratorType = "randomAlpha"
	SecureGeneratorType_RandomAlphaNumeric SecureGeneratorType = "randomAlphaNumeric"
)

/**
 * @author Daniel DeGroff
 */
type SecureIdentity struct {
	BreachedPasswordLastCheckedInstant int64                  `json:"breachedPasswordLastCheckedInstant,omitempty"`
	BreachedPasswordStatus             BreachedPasswordStatus `json:"breachedPasswordStatus,omitempty"`
	ConnectorId                        string                 `json:"connectorId,omitempty"`
	EncryptionScheme                   string                 `json:"encryptionScheme,omitempty"`
	Factor                             int                    `json:"factor,omitempty"`
	Id                                 string                 `json:"id,omitempty"`
	Identities                         []UserIdentity         `json:"identities,omitempty"`
	LastLoginInstant                   int64                  `json:"lastLoginInstant,omitempty"`
	Password                           string                 `json:"password,omitempty"`
	PasswordChangeReason               ChangePasswordReason   `json:"passwordChangeReason,omitempty"`
	PasswordChangeRequired             bool                   `json:"passwordChangeRequired"`
	PasswordLastUpdateInstant          int64                  `json:"passwordLastUpdateInstant,omitempty"`
	Salt                               string                 `json:"salt,omitempty"`
	UniqueUsername                     string                 `json:"uniqueUsername,omitempty"`
	Username                           string                 `json:"username,omitempty"`
	UsernameStatus                     ContentStatus          `json:"usernameStatus,omitempty"`
	Verified                           bool                   `json:"verified"`
	VerifiedInstant                    int64                  `json:"verifiedInstant,omitempty"`
}

/**
 * @author andrewpai
 */
type SelfServiceFormConfiguration struct {
	RequireCurrentPasswordOnPasswordChange bool `json:"requireCurrentPasswordOnPasswordChange"`
}

/**
 * @author Daniel DeGroff
 */
type SendRequest struct {
	ApplicationId      string                 `json:"applicationId,omitempty"`
	BccAddresses       []string               `json:"bccAddresses,omitempty"`
	CcAddresses        []string               `json:"ccAddresses,omitempty"`
	PreferredLanguages []string               `json:"preferredLanguages,omitempty"`
	RequestData        map[string]interface{} `json:"requestData,omitempty"`
	ToAddresses        []EmailAddress         `json:"toAddresses,omitempty"`
	UserIds            []string               `json:"userIds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SendResponse struct {
	BaseHTTPResponse
	AnonymousResults map[string]EmailTemplateErrors `json:"anonymousResults,omitempty"`
	Results          map[string]EmailTemplateErrors `json:"results,omitempty"`
}

func (b *SendResponse) SetStatus(status int) {
	b.StatusCode = status
}

type EmailTemplateErrors struct {
	ParseErrors  map[string]string `json:"parseErrors,omitempty"`
	RenderErrors map[string]string `json:"renderErrors,omitempty"`
}

/**
 * Used to indicate which identity type a password "request" might go to. It could be
 * used for send set passwords or send password resets.
 */
type SendSetPasswordIdentityType string

func (e SendSetPasswordIdentityType) String() string {
	return string(e)
}

const (
	SendSetPasswordIdentityType_Email     SendSetPasswordIdentityType = "email"
	SendSetPasswordIdentityType_Phone     SendSetPasswordIdentityType = "phone"
	SendSetPasswordIdentityType_DoNotSend SendSetPasswordIdentityType = "doNotSend"
)

/**
 * Theme object for values used in the css variables for simple themes.
 *
 * @author Lyle Schemmerling
 */
type SimpleThemeVariables struct {
	AlertBackgroundColor        string `json:"alertBackgroundColor,omitempty"`
	AlertFontColor              string `json:"alertFontColor,omitempty"`
	BackgroundImageURL          string `json:"backgroundImageURL,omitempty"`
	BackgroundSize              string `json:"backgroundSize,omitempty"`
	BorderRadius                string `json:"borderRadius,omitempty"`
	DeleteButtonColor           string `json:"deleteButtonColor,omitempty"`
	DeleteButtonFocusColor      string `json:"deleteButtonFocusColor,omitempty"`
	DeleteButtonTextColor       string `json:"deleteButtonTextColor,omitempty"`
	DeleteButtonTextFocusColor  string `json:"deleteButtonTextFocusColor,omitempty"`
	ErrorFontColor              string `json:"errorFontColor,omitempty"`
	ErrorIconColor              string `json:"errorIconColor,omitempty"`
	FontColor                   string `json:"fontColor,omitempty"`
	FontFamily                  string `json:"fontFamily,omitempty"`
	FooterDisplay               bool   `json:"footerDisplay"`
	IconBackgroundColor         string `json:"iconBackgroundColor,omitempty"`
	IconColor                   string `json:"iconColor,omitempty"`
	InfoIconColor               string `json:"infoIconColor,omitempty"`
	InputBackgroundColor        string `json:"inputBackgroundColor,omitempty"`
	InputIconColor              string `json:"inputIconColor,omitempty"`
	InputTextColor              string `json:"inputTextColor,omitempty"`
	LinkTextColor               string `json:"linkTextColor,omitempty"`
	LinkTextFocusColor          string `json:"linkTextFocusColor,omitempty"`
	LogoImageSize               string `json:"logoImageSize,omitempty"`
	LogoImageURL                string `json:"logoImageURL,omitempty"`
	MonoFontColor               string `json:"monoFontColor,omitempty"`
	MonoFontFamily              string `json:"monoFontFamily,omitempty"`
	PageBackgroundColor         string `json:"pageBackgroundColor,omitempty"`
	PanelBackgroundColor        string `json:"panelBackgroundColor,omitempty"`
	PrimaryButtonColor          string `json:"primaryButtonColor,omitempty"`
	PrimaryButtonFocusColor     string `json:"primaryButtonFocusColor,omitempty"`
	PrimaryButtonTextColor      string `json:"primaryButtonTextColor,omitempty"`
	PrimaryButtonTextFocusColor string `json:"primaryButtonTextFocusColor,omitempty"`
}

/**
 * @author Brett Pontarelli
 */
type SonyPSNApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * SonyPSN gaming login provider.
 *
 * @author Brett Pontarelli
 */
type SonyPSNIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type Sort string

func (e Sort) String() string {
	return string(e)
}

const (
	Sort_Asc  Sort = "asc"
	Sort_Desc Sort = "desc"
)

/**
 * @author Daniel DeGroff
 */
type SortField struct {
	Missing string `json:"missing,omitempty"`
	Name    string `json:"name,omitempty"`
	Order   Sort   `json:"order,omitempty"`
}

/**
 * The public Status API response
 *
 * @author Daniel DeGroff
 */
type StatusResponse struct {
	BaseHTTPResponse
	LinkedHashMap
}

func (b *StatusResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Steam API modes.
 *
 * @author Daniel DeGroff
 */
type SteamAPIMode string

func (e SteamAPIMode) String() string {
	return string(e)
}

const (
	SteamAPIMode_Public  SteamAPIMode = "Public"
	SteamAPIMode_Partner SteamAPIMode = "Partner"
)

/**
 * @author Brett Pontarelli
 */
type SteamApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ApiMode    SteamAPIMode `json:"apiMode,omitempty"`
	ButtonText string       `json:"buttonText,omitempty"`
	ClientId   string       `json:"client_id,omitempty"`
	Scope      string       `json:"scope,omitempty"`
	WebAPIKey  string       `json:"webAPIKey,omitempty"`
}

/**
 * Steam gaming login provider.
 *
 * @author Brett Pontarelli
 */
type SteamIdentityProvider struct {
	BaseIdentityProvider
	ApiMode    SteamAPIMode `json:"apiMode,omitempty"`
	ButtonText string       `json:"buttonText,omitempty"`
	ClientId   string       `json:"client_id,omitempty"`
	Scope      string       `json:"scope,omitempty"`
	WebAPIKey  string       `json:"webAPIKey,omitempty"`
}

/**
 * Helper interface that indicates an identity provider can be federated to using the HTTP POST method.
 *
 * @author Brian Pontarelli
 */
type SupportsPostBindings struct {
}

/**
 * @author Brian Pontarelli
 */
type SystemConfiguration struct {
	AuditLogConfiguration        AuditLogConfiguration           `json:"auditLogConfiguration,omitempty"`
	CorsConfiguration            CORSConfiguration               `json:"corsConfiguration,omitempty"`
	Data                         map[string]interface{}          `json:"data,omitempty"`
	EventLogConfiguration        EventLogConfiguration           `json:"eventLogConfiguration,omitempty"`
	InsertInstant                int64                           `json:"insertInstant,omitempty"`
	LastUpdateInstant            int64                           `json:"lastUpdateInstant,omitempty"`
	LoginRecordConfiguration     LoginRecordConfiguration        `json:"loginRecordConfiguration,omitempty"`
	ReportTimezone               string                          `json:"reportTimezone,omitempty"`
	TrustedProxyConfiguration    SystemTrustedProxyConfiguration `json:"trustedProxyConfiguration,omitempty"`
	UiConfiguration              UIConfiguration                 `json:"uiConfiguration,omitempty"`
	UsageDataConfiguration       UsageDataConfiguration          `json:"usageDataConfiguration,omitempty"`
	WebhookEventLogConfiguration WebhookEventLogConfiguration    `json:"webhookEventLogConfiguration,omitempty"`
}

type AuditLogConfiguration struct {
	Delete DeleteConfiguration `json:"delete,omitempty"`
}

type DeleteConfiguration struct {
	Enableable
	NumberOfDaysToRetain int `json:"numberOfDaysToRetain,omitempty"`
}

type EventLogConfiguration struct {
	NumberToRetain int `json:"numberToRetain,omitempty"`
}

type LoginRecordConfiguration struct {
	Delete DeleteConfiguration `json:"delete,omitempty"`
}

type UIConfiguration struct {
	HeaderColor   string `json:"headerColor,omitempty"`
	LogoURL       string `json:"logoURL,omitempty"`
	MenuFontColor string `json:"menuFontColor,omitempty"`
}

/**
 * Request for the system configuration API.
 *
 * @author Brian Pontarelli
 */
type SystemConfigurationRequest struct {
	SystemConfiguration SystemConfiguration `json:"systemConfiguration,omitempty"`
}

/**
 * Response for the system configuration API.
 *
 * @author Brian Pontarelli
 */
type SystemConfigurationResponse struct {
	BaseHTTPResponse
	SystemConfiguration SystemConfiguration `json:"systemConfiguration,omitempty"`
}

func (b *SystemConfigurationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type SystemLogsExportRequest struct {
	BaseExportRequest
	IncludeArchived bool `json:"includeArchived"`
	LastNBytes      int  `json:"lastNBytes,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SystemTrustedProxyConfiguration struct {
	Trusted     []string                              `json:"trusted,omitempty"`
	TrustPolicy SystemTrustedProxyConfigurationPolicy `json:"trustPolicy,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SystemTrustedProxyConfigurationPolicy string

func (e SystemTrustedProxyConfigurationPolicy) String() string {
	return string(e)
}

const (
	SystemTrustedProxyConfigurationPolicy_All            SystemTrustedProxyConfigurationPolicy = "All"
	SystemTrustedProxyConfigurationPolicy_OnlyConfigured SystemTrustedProxyConfigurationPolicy = "OnlyConfigured"
)

/**
 * @author Daniel DeGroff
 */
type Tenant struct {
	AccessControlConfiguration        TenantAccessControlConfiguration  `json:"accessControlConfiguration,omitempty"`
	CaptchaConfiguration              TenantCaptchaConfiguration        `json:"captchaConfiguration,omitempty"`
	Configured                        bool                              `json:"configured"`
	ConnectorPolicies                 []ConnectorPolicy                 `json:"connectorPolicies,omitempty"`
	Data                              map[string]interface{}            `json:"data,omitempty"`
	EmailConfiguration                EmailConfiguration                `json:"emailConfiguration,omitempty"`
	EventConfiguration                EventConfiguration                `json:"eventConfiguration,omitempty"`
	ExternalIdentifierConfiguration   ExternalIdentifierConfiguration   `json:"externalIdentifierConfiguration,omitempty"`
	FailedAuthenticationConfiguration FailedAuthenticationConfiguration `json:"failedAuthenticationConfiguration,omitempty"`
	FamilyConfiguration               FamilyConfiguration               `json:"familyConfiguration,omitempty"`
	FormConfiguration                 TenantFormConfiguration           `json:"formConfiguration,omitempty"`
	HttpSessionMaxInactiveInterval    int                               `json:"httpSessionMaxInactiveInterval,omitempty"`
	Id                                string                            `json:"id,omitempty"`
	InsertInstant                     int64                             `json:"insertInstant,omitempty"`
	Issuer                            string                            `json:"issuer,omitempty"`
	JwtConfiguration                  JWTConfiguration                  `json:"jwtConfiguration,omitempty"`
	LambdaConfiguration               TenantLambdaConfiguration         `json:"lambdaConfiguration,omitempty"`
	LastUpdateInstant                 int64                             `json:"lastUpdateInstant,omitempty"`
	LoginConfiguration                TenantLoginConfiguration          `json:"loginConfiguration,omitempty"`
	LogoutURL                         string                            `json:"logoutURL,omitempty"`
	MaximumPasswordAge                MaximumPasswordAge                `json:"maximumPasswordAge,omitempty"`
	MinimumPasswordAge                MinimumPasswordAge                `json:"minimumPasswordAge,omitempty"`
	MultiFactorConfiguration          TenantMultiFactorConfiguration    `json:"multiFactorConfiguration,omitempty"`
	Name                              string                            `json:"name,omitempty"`
	OauthConfiguration                TenantOAuth2Configuration         `json:"oauthConfiguration,omitempty"`
	PasswordEncryptionConfiguration   PasswordEncryptionConfiguration   `json:"passwordEncryptionConfiguration,omitempty"`
	PasswordValidationRules           PasswordValidationRules           `json:"passwordValidationRules,omitempty"`
	PhoneConfiguration                TenantPhoneConfiguration          `json:"phoneConfiguration,omitempty"`
	RateLimitConfiguration            TenantRateLimitConfiguration      `json:"rateLimitConfiguration,omitempty"`
	RegistrationConfiguration         TenantRegistrationConfiguration   `json:"registrationConfiguration,omitempty"`
	ScimServerConfiguration           TenantSCIMServerConfiguration     `json:"scimServerConfiguration,omitempty"`
	SsoConfiguration                  TenantSSOConfiguration            `json:"ssoConfiguration,omitempty"`
	State                             ObjectState                       `json:"state,omitempty"`
	ThemeId                           string                            `json:"themeId,omitempty"`
	UserDeletePolicy                  TenantUserDeletePolicy            `json:"userDeletePolicy,omitempty"`
	UsernameConfiguration             TenantUsernameConfiguration       `json:"usernameConfiguration,omitempty"`
	WebAuthnConfiguration             TenantWebAuthnConfiguration       `json:"webAuthnConfiguration,omitempty"`
}

type TenantOAuth2Configuration struct {
	ClientCredentialsAccessTokenPopulateLambdaId string `json:"clientCredentialsAccessTokenPopulateLambdaId,omitempty"`
}

/**
 * @author Brett Guy
 */
type TenantAccessControlConfiguration struct {
	UiIPAccessControlListId string `json:"uiIPAccessControlListId,omitempty"`
}

/**
 * @author Brett Pontarelli
 */
type TenantCaptchaConfiguration struct {
	Enableable
	CaptchaMethod CaptchaMethod `json:"captchaMethod,omitempty"`
	SecretKey     string        `json:"secretKey,omitempty"`
	SiteKey       string        `json:"siteKey,omitempty"`
	Threshold     float64       `json:"threshold,omitempty"`
}

/**
 * Request for the Tenant API to delete a tenant rather than using the URL parameters.
 *
 * @author Brian Pontarelli
 */
type TenantDeleteRequest struct {
	BaseEventRequest
	Async bool `json:"async"`
}

/**
 * @author Daniel DeGroff
 */
type TenantFormConfiguration struct {
	AdminUserFormId string `json:"adminUserFormId,omitempty"`
}

/**
 * @author Rob Davis
 */
type TenantLambdaConfiguration struct {
	LoginValidationId                     string `json:"loginValidationId,omitempty"`
	ScimEnterpriseUserRequestConverterId  string `json:"scimEnterpriseUserRequestConverterId,omitempty"`
	ScimEnterpriseUserResponseConverterId string `json:"scimEnterpriseUserResponseConverterId,omitempty"`
	ScimGroupRequestConverterId           string `json:"scimGroupRequestConverterId,omitempty"`
	ScimGroupResponseConverterId          string `json:"scimGroupResponseConverterId,omitempty"`
	ScimUserRequestConverterId            string `json:"scimUserRequestConverterId,omitempty"`
	ScimUserResponseConverterId           string `json:"scimUserResponseConverterId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantLoginConfiguration struct {
	RequireAuthentication bool `json:"requireAuthentication"`
}

/**
 * @author Mikey Sleevi
 */
type TenantMultiFactorConfiguration struct {
	Authenticator MultiFactorAuthenticatorMethod `json:"authenticator,omitempty"`
	Email         MultiFactorEmailMethod         `json:"email,omitempty"`
	LoginPolicy   MultiFactorLoginPolicy         `json:"loginPolicy,omitempty"`
	Sms           MultiFactorSMSMethod           `json:"sms,omitempty"`
}

type MultiFactorAuthenticatorMethod struct {
	Enableable
	Algorithm  TOTPAlgorithm `json:"algorithm,omitempty"`
	CodeLength int           `json:"codeLength,omitempty"`
	TimeStep   int           `json:"timeStep,omitempty"`
}

type MultiFactorEmailMethod struct {
	Enableable
	TemplateId string `json:"templateId,omitempty"`
}

type MultiFactorSMSMethod struct {
	Enableable
	MessengerId string `json:"messengerId,omitempty"`
	TemplateId  string `json:"templateId,omitempty"`
}

/**
 * Hold tenant phone configuration for passwordless and verification cases.
 *
 * @author Brady Wied
 */
type TenantPhoneConfiguration struct {
	ForgotPasswordTemplateId         string                 `json:"forgotPasswordTemplateId,omitempty"`
	IdentityUpdateTemplateId         string                 `json:"identityUpdateTemplateId,omitempty"`
	ImplicitPhoneVerificationAllowed bool                   `json:"implicitPhoneVerificationAllowed"`
	LoginIdInUseOnCreateTemplateId   string                 `json:"loginIdInUseOnCreateTemplateId,omitempty"`
	LoginIdInUseOnUpdateTemplateId   string                 `json:"loginIdInUseOnUpdateTemplateId,omitempty"`
	LoginNewDeviceTemplateId         string                 `json:"loginNewDeviceTemplateId,omitempty"`
	LoginSuspiciousTemplateId        string                 `json:"loginSuspiciousTemplateId,omitempty"`
	MessengerId                      string                 `json:"messengerId,omitempty"`
	PasswordlessTemplateId           string                 `json:"passwordlessTemplateId,omitempty"`
	PasswordResetSuccessTemplateId   string                 `json:"passwordResetSuccessTemplateId,omitempty"`
	PasswordUpdateTemplateId         string                 `json:"passwordUpdateTemplateId,omitempty"`
	SetPasswordTemplateId            string                 `json:"setPasswordTemplateId,omitempty"`
	TwoFactorMethodAddTemplateId     string                 `json:"twoFactorMethodAddTemplateId,omitempty"`
	TwoFactorMethodRemoveTemplateId  string                 `json:"twoFactorMethodRemoveTemplateId,omitempty"`
	Unverified                       PhoneUnverifiedOptions `json:"unverified,omitempty"`
	VerificationCompleteTemplateId   string                 `json:"verificationCompleteTemplateId,omitempty"`
	VerificationStrategy             VerificationStrategy   `json:"verificationStrategy,omitempty"`
	VerificationTemplateId           string                 `json:"verificationTemplateId,omitempty"`
	VerifyPhoneNumber                bool                   `json:"verifyPhoneNumber"`
}

/**
 * @author Daniel DeGroff
 */
type TenantRateLimitConfiguration struct {
	FailedLogin                  RateLimitedRequestConfiguration `json:"failedLogin,omitempty"`
	ForgotPassword               RateLimitedRequestConfiguration `json:"forgotPassword,omitempty"`
	SendEmailVerification        RateLimitedRequestConfiguration `json:"sendEmailVerification,omitempty"`
	SendPasswordless             RateLimitedRequestConfiguration `json:"sendPasswordless,omitempty"`
	SendPasswordlessPhone        RateLimitedRequestConfiguration `json:"sendPasswordlessPhone,omitempty"`
	SendPhoneVerification        RateLimitedRequestConfiguration `json:"sendPhoneVerification,omitempty"`
	SendRegistrationVerification RateLimitedRequestConfiguration `json:"sendRegistrationVerification,omitempty"`
	SendTwoFactor                RateLimitedRequestConfiguration `json:"sendTwoFactor,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantRegistrationConfiguration struct {
	BlockedDomains []string `json:"blockedDomains,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantRequest struct {
	BaseEventRequest
	SourceTenantId string   `json:"sourceTenantId,omitempty"`
	Tenant         Tenant   `json:"tenant,omitempty"`
	WebhookIds     []string `json:"webhookIds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantResponse struct {
	BaseHTTPResponse
	Tenant  Tenant   `json:"tenant,omitempty"`
	Tenants []Tenant `json:"tenants,omitempty"`
}

func (b *TenantResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Rob Davis
 */
type TenantSCIMServerConfiguration struct {
	Enableable
	ClientEntityTypeId string                 `json:"clientEntityTypeId,omitempty"`
	Schemas            map[string]interface{} `json:"schemas,omitempty"`
	ServerEntityTypeId string                 `json:"serverEntityTypeId,omitempty"`
}

/**
 * @author Brett Pontarelli
 */
type TenantSSOConfiguration struct {
	AllowAccessTokenBootstrap      bool `json:"allowAccessTokenBootstrap"`
	DeviceTrustTimeToLiveInSeconds int  `json:"deviceTrustTimeToLiveInSeconds,omitempty"`
}

/**
 * Search criteria for Tenants
 *
 * @author Mark Manes
 */
type TenantSearchCriteria struct {
	BaseSearchCriteria
	Name string `json:"name,omitempty"`
}

/**
 * Search request for Tenants
 *
 * @author Mark Manes
 */
type TenantSearchRequest struct {
	Search TenantSearchCriteria `json:"search,omitempty"`
}

/**
 * Tenant search response
 *
 * @author Mark Manes
 */
type TenantSearchResponse struct {
	BaseHTTPResponse
	Tenants []Tenant `json:"tenants,omitempty"`
	Total   int64    `json:"total,omitempty"`
}

func (b *TenantSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type TenantUnverifiedConfiguration struct {
	Email     UnverifiedBehavior            `json:"email,omitempty"`
	WhenGated RegistrationUnverifiedOptions `json:"whenGated,omitempty"`
}

/**
 * A Tenant-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
type TenantUserDeletePolicy struct {
	Unverified TimeBasedDeletePolicy `json:"unverified,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantUsernameConfiguration struct {
	Unique UniqueUsernameConfiguration `json:"unique,omitempty"`
}

type UniqueUsernameConfiguration struct {
	Enableable
	NumberOfDigits int                    `json:"numberOfDigits,omitempty"`
	Separator      string                 `json:"separator,omitempty"`
	Strategy       UniqueUsernameStrategy `json:"strategy,omitempty"`
}

type UniqueUsernameStrategy string

func (e UniqueUsernameStrategy) String() string {
	return string(e)
}

const (
	UniqueUsernameStrategy_Always      UniqueUsernameStrategy = "Always"
	UniqueUsernameStrategy_OnCollision UniqueUsernameStrategy = "OnCollision"
)

/**
 * Tenant-level configuration for WebAuthn
 *
 * @author Spencer Witt
 */
type TenantWebAuthnConfiguration struct {
	Enableable
	BootstrapWorkflow        TenantWebAuthnWorkflowConfiguration `json:"bootstrapWorkflow,omitempty"`
	Debug                    bool                                `json:"debug"`
	ReauthenticationWorkflow TenantWebAuthnWorkflowConfiguration `json:"reauthenticationWorkflow,omitempty"`
	RelyingPartyId           string                              `json:"relyingPartyId,omitempty"`
	RelyingPartyName         string                              `json:"relyingPartyName,omitempty"`
}

/**
 * @author Spencer Witt
 */
type TenantWebAuthnWorkflowConfiguration struct {
	Enableable
	AuthenticatorAttachmentPreference AuthenticatorAttachmentPreference `json:"authenticatorAttachmentPreference,omitempty"`
	UserVerificationRequirement       UserVerificationRequirement       `json:"userVerificationRequirement,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type Tenantable struct {
}

/**
 * @author Daniel DeGroff
 */
type TestEvent struct {
	BaseEvent
	Message string `json:"message,omitempty"`
}

/**
 * @author Trevor Smith
 */
type Theme struct {
	Data              map[string]interface{} `json:"data,omitempty"`
	DefaultMessages   string                 `json:"defaultMessages,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	LocalizedMessages map[string]string      `json:"localizedMessages,omitempty"`
	Name              string                 `json:"name,omitempty"`
	Stylesheet        string                 `json:"stylesheet,omitempty"`
	Templates         Templates              `json:"templates,omitempty"`
	Type              ThemeType              `json:"type,omitempty"`
	Variables         SimpleThemeVariables   `json:"variables,omitempty"`
}

type Templates struct {
	AccountEdit                               string `json:"accountEdit,omitempty"`
	AccountIndex                              string `json:"accountIndex,omitempty"`
	AccountTwoFactorDisable                   string `json:"accountTwoFactorDisable,omitempty"`
	AccountTwoFactorEnable                    string `json:"accountTwoFactorEnable,omitempty"`
	AccountTwoFactorIndex                     string `json:"accountTwoFactorIndex,omitempty"`
	AccountWebAuthnAdd                        string `json:"accountWebAuthnAdd,omitempty"`
	AccountWebAuthnDelete                     string `json:"accountWebAuthnDelete,omitempty"`
	AccountWebAuthnIndex                      string `json:"accountWebAuthnIndex,omitempty"`
	ConfirmationRequired                      string `json:"confirmationRequired,omitempty"`
	EmailComplete                             string `json:"emailComplete,omitempty"`
	EmailSend                                 string `json:"emailSend,omitempty"`
	EmailSent                                 string `json:"emailSent,omitempty"`
	EmailVerificationRequired                 string `json:"emailVerificationRequired,omitempty"`
	EmailVerify                               string `json:"emailVerify,omitempty"`
	Helpers                                   string `json:"helpers,omitempty"`
	Index                                     string `json:"index,omitempty"`
	Oauth2Authorize                           string `json:"oauth2Authorize,omitempty"`
	Oauth2AuthorizedNotRegistered             string `json:"oauth2AuthorizedNotRegistered,omitempty"`
	Oauth2ChildRegistrationNotAllowed         string `json:"oauth2ChildRegistrationNotAllowed,omitempty"`
	Oauth2ChildRegistrationNotAllowedComplete string `json:"oauth2ChildRegistrationNotAllowedComplete,omitempty"`
	Oauth2CompleteRegistration                string `json:"oauth2CompleteRegistration,omitempty"`
	Oauth2Consent                             string `json:"oauth2Consent,omitempty"`
	Oauth2Device                              string `json:"oauth2Device,omitempty"`
	Oauth2DeviceComplete                      string `json:"oauth2DeviceComplete,omitempty"`
	Oauth2Error                               string `json:"oauth2Error,omitempty"`
	Oauth2Logout                              string `json:"oauth2Logout,omitempty"`
	Oauth2Passwordless                        string `json:"oauth2Passwordless,omitempty"`
	Oauth2Register                            string `json:"oauth2Register,omitempty"`
	Oauth2StartIdPLink                        string `json:"oauth2StartIdPLink,omitempty"`
	Oauth2TwoFactor                           string `json:"oauth2TwoFactor,omitempty"`
	Oauth2TwoFactorEnable                     string `json:"oauth2TwoFactorEnable,omitempty"`
	Oauth2TwoFactorEnableComplete             string `json:"oauth2TwoFactorEnableComplete,omitempty"`
	Oauth2TwoFactorMethods                    string `json:"oauth2TwoFactorMethods,omitempty"`
	Oauth2Wait                                string `json:"oauth2Wait,omitempty"`
	Oauth2WebAuthn                            string `json:"oauth2WebAuthn,omitempty"`
	Oauth2WebAuthnReauth                      string `json:"oauth2WebAuthnReauth,omitempty"`
	Oauth2WebAuthnReauthEnable                string `json:"oauth2WebAuthnReauthEnable,omitempty"`
	PasswordChange                            string `json:"passwordChange,omitempty"`
	PasswordComplete                          string `json:"passwordComplete,omitempty"`
	PasswordForgot                            string `json:"passwordForgot,omitempty"`
	PasswordSent                              string `json:"passwordSent,omitempty"`
	PhoneComplete                             string `json:"phoneComplete,omitempty"`
	PhoneSent                                 string `json:"phoneSent,omitempty"`
	PhoneVerificationRequired                 string `json:"phoneVerificationRequired,omitempty"`
	PhoneVerify                               string `json:"phoneVerify,omitempty"`
	RegistrationComplete                      string `json:"registrationComplete,omitempty"`
	RegistrationSend                          string `json:"registrationSend,omitempty"`
	RegistrationSent                          string `json:"registrationSent,omitempty"`
	RegistrationVerificationRequired          string `json:"registrationVerificationRequired,omitempty"`
	RegistrationVerify                        string `json:"registrationVerify,omitempty"`
	Samlv2Logout                              string `json:"samlv2Logout,omitempty"`
	Unauthorized                              string `json:"unauthorized,omitempty"`
}

/**
 * Theme API request object.
 *
 * @author Trevor Smith
 */
type ThemeRequest struct {
	SourceThemeId string `json:"sourceThemeId,omitempty"`
	Theme         Theme  `json:"theme,omitempty"`
}

/**
 * Theme API response object.
 *
 * @author Trevor Smith
 */
type ThemeResponse struct {
	BaseHTTPResponse
	Theme  Theme   `json:"theme,omitempty"`
	Themes []Theme `json:"themes,omitempty"`
}

func (b *ThemeResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for themes
 *
 * @author Mark Manes
 */
type ThemeSearchCriteria struct {
	BaseSearchCriteria
	Name string    `json:"name,omitempty"`
	Type ThemeType `json:"type,omitempty"`
}

/**
 * Search request for Themes.
 *
 * @author Mark Manes
 */
type ThemeSearchRequest struct {
	Search ThemeSearchCriteria `json:"search,omitempty"`
}

/**
 * Search response for Themes
 *
 * @author Mark Manes
 */
type ThemeSearchResponse struct {
	BaseHTTPResponse
	Themes []Theme `json:"themes,omitempty"`
	Total  int64   `json:"total,omitempty"`
}

func (b *ThemeSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

type ThemeType string

func (e ThemeType) String() string {
	return string(e)
}

const (
	ThemeType_Advanced ThemeType = "advanced"
	ThemeType_Simple   ThemeType = "simple"
)

/**
 * A policy for deleting Users based upon some external criteria.
 *
 * @author Trevor Smith
 */
type TimeBasedDeletePolicy struct {
	Enableable
	EnabledInstant       int64 `json:"enabledInstant,omitempty"`
	NumberOfDaysToRetain int   `json:"numberOfDaysToRetain,omitempty"`
}

/**
 * <ul>
 * <li>Bearer Token type as defined by <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>.</li>
 * <li>MAC Token type as referenced by <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
 * <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05">
 * Draft RFC on OAuth 2.0 Message Authentication Code (MAC) Tokens</a>
 * </li>
 * </ul>
 *
 * @author Daniel DeGroff
 */
type TokenType string

func (e TokenType) String() string {
	return string(e)
}

const (
	TokenType_Bearer TokenType = "Bearer"
	TokenType_MAC    TokenType = "MAC"
)

/**
 * The response from the total report. This report stores the total numbers for each application.
 *
 * @author Brian Pontarelli
 */
type TotalsReportResponse struct {
	BaseHTTPResponse
	ApplicationTotals        map[string]Totals `json:"applicationTotals,omitempty"`
	GlobalRegistrations      int64             `json:"globalRegistrations,omitempty"`
	TotalGlobalRegistrations int64             `json:"totalGlobalRegistrations,omitempty"`
}

func (b *TotalsReportResponse) SetStatus(status int) {
	b.StatusCode = status
}

type Totals struct {
	Logins             int64 `json:"logins,omitempty"`
	Registrations      int64 `json:"registrations,omitempty"`
	TotalRegistrations int64 `json:"totalRegistrations,omitempty"`
}

/**
 * The transaction types for Webhooks and other event systems within FusionAuth.
 *
 * @author Brian Pontarelli
 */
type TransactionType string

func (e TransactionType) String() string {
	return string(e)
}

const (
	TransactionType_None             TransactionType = "None"
	TransactionType_Any              TransactionType = "Any"
	TransactionType_SimpleMajority   TransactionType = "SimpleMajority"
	TransactionType_SuperMajority    TransactionType = "SuperMajority"
	TransactionType_AbsoluteMajority TransactionType = "AbsoluteMajority"
)

/**
 * @author Brett Guy
 */
type TwilioMessengerConfiguration struct {
	BaseMessengerConfiguration
	AccountSID          string `json:"accountSID,omitempty"`
	AuthToken           string `json:"authToken,omitempty"`
	FromPhoneNumber     string `json:"fromPhoneNumber,omitempty"`
	MessagingServiceSid string `json:"messagingServiceSid,omitempty"`
	Url                 string `json:"url,omitempty"`
}

/**
 * @author Brett Pontarelli
 */
type TwitchApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Twitch gaming login provider.
 *
 * @author Brett Pontarelli
 */
type TwitchIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwitterApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText     string `json:"buttonText,omitempty"`
	ConsumerKey    string `json:"consumerKey,omitempty"`
	ConsumerSecret string `json:"consumerSecret,omitempty"`
}

/**
 * Twitter social login provider.
 *
 * @author Daniel DeGroff
 */
type TwitterIdentityProvider struct {
	BaseIdentityProvider
	ButtonText     string `json:"buttonText,omitempty"`
	ConsumerKey    string `json:"consumerKey,omitempty"`
	ConsumerSecret string `json:"consumerSecret,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type TwoFactorDisableRequest struct {
	BaseEventRequest
	ApplicationId string `json:"applicationId,omitempty"`
	Code          string `json:"code,omitempty"`
	MethodId      string `json:"methodId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorEnableDisableSendRequest struct {
	Email       string `json:"email,omitempty"`
	Method      string `json:"method,omitempty"`
	MethodId    string `json:"methodId,omitempty"`
	MobilePhone string `json:"mobilePhone,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorLoginRequest struct {
	BaseLoginRequest
	Code          string `json:"code,omitempty"`
	TrustComputer bool   `json:"trustComputer"`
	TwoFactorId   string `json:"twoFactorId,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorMethod struct {
	Authenticator AuthenticatorConfiguration `json:"authenticator,omitempty"`
	Email         string                     `json:"email,omitempty"`
	Id            string                     `json:"id,omitempty"`
	LastUsed      bool                       `json:"lastUsed"`
	Method        string                     `json:"method,omitempty"`
	MobilePhone   string                     `json:"mobilePhone,omitempty"`
	Secret        string                     `json:"secret,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorRecoveryCodeResponse struct {
	BaseHTTPResponse
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
}

func (b *TwoFactorRecoveryCodeResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type TwoFactorRequest struct {
	BaseEventRequest
	ApplicationId       string `json:"applicationId,omitempty"`
	AuthenticatorId     string `json:"authenticatorId,omitempty"`
	Code                string `json:"code,omitempty"`
	Email               string `json:"email,omitempty"`
	Method              string `json:"method,omitempty"`
	MobilePhone         string `json:"mobilePhone,omitempty"`
	Secret              string `json:"secret,omitempty"`
	SecretBase32Encoded string `json:"secretBase32Encoded,omitempty"`
	TwoFactorId         string `json:"twoFactorId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorResponse struct {
	BaseHTTPResponse
	Code          string   `json:"code,omitempty"`
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
}

func (b *TwoFactorResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorSendRequest struct {
	ApplicationId string `json:"applicationId,omitempty"`
	Email         string `json:"email,omitempty"`
	Method        string `json:"method,omitempty"`
	MethodId      string `json:"methodId,omitempty"`
	MobilePhone   string `json:"mobilePhone,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Brett Guy
 */
type TwoFactorStartRequest struct {
	ApplicationId  string                 `json:"applicationId,omitempty"`
	Code           string                 `json:"code,omitempty"`
	LoginId        string                 `json:"loginId,omitempty"`
	LoginIdTypes   []string               `json:"loginIdTypes,omitempty"`
	State          map[string]interface{} `json:"state,omitempty"`
	TrustChallenge string                 `json:"trustChallenge,omitempty"`
	UserId         string                 `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorStartResponse struct {
	BaseHTTPResponse
	Code        string            `json:"code,omitempty"`
	Methods     []TwoFactorMethod `json:"methods,omitempty"`
	TwoFactorId string            `json:"twoFactorId,omitempty"`
}

func (b *TwoFactorStartResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorStatusResponse struct {
	BaseHTTPResponse
	Trusts           []TwoFactorTrust `json:"trusts,omitempty"`
	TwoFactorTrustId string           `json:"twoFactorTrustId,omitempty"`
}

func (b *TwoFactorStatusResponse) SetStatus(status int) {
	b.StatusCode = status
}

type TwoFactorTrust struct {
	ApplicationId string `json:"applicationId,omitempty"`
	Expiration    int64  `json:"expiration,omitempty"`
	StartInstant  int64  `json:"startInstant,omitempty"`
}

/**
 * @author Lyle Schemmerling
 */
type UniversalApplicationConfiguration struct {
	Universal bool `json:"universal"`
}

/**
 * Policy for handling unknown OAuth scopes in the request
 *
 * @author Spencer Witt
 */
type UnknownScopePolicy string

func (e UnknownScopePolicy) String() string {
	return string(e)
}

const (
	UnknownScopePolicy_Allow  UnknownScopePolicy = "Allow"
	UnknownScopePolicy_Remove UnknownScopePolicy = "Remove"
	UnknownScopePolicy_Reject UnknownScopePolicy = "Reject"
)

/**
 * @author Daniel DeGroff
 */
type UnverifiedBehavior string

func (e UnverifiedBehavior) String() string {
	return string(e)
}

const (
	UnverifiedBehavior_Allow UnverifiedBehavior = "Allow"
	UnverifiedBehavior_Gated UnverifiedBehavior = "Gated"
)

/**
 * Config for Usage Data / Stats
 *
 * @author Lyle Schemmerling
 */
type UsageDataConfiguration struct {
	Enableable
	NumberOfDaysToRetain int `json:"numberOfDaysToRetain,omitempty"`
}

/**
 * The public, global view of a User. This object contains all global information about the user including birthdate, registration information
 * preferred languages, global attributes, etc.
 *
 * @author Seth Musselman
 */
type User struct {
	SecureIdentity
	Active             bool                       `json:"active"`
	BirthDate          string                     `json:"birthDate,omitempty"`
	CleanSpeakId       string                     `json:"cleanSpeakId,omitempty"`
	Data               map[string]interface{}     `json:"data,omitempty"`
	Email              string                     `json:"email,omitempty"`
	Expiry             int64                      `json:"expiry,omitempty"`
	FirstName          string                     `json:"firstName,omitempty"`
	FullName           string                     `json:"fullName,omitempty"`
	ImageUrl           string                     `json:"imageUrl,omitempty"`
	InsertInstant      int64                      `json:"insertInstant,omitempty"`
	LastName           string                     `json:"lastName,omitempty"`
	LastUpdateInstant  int64                      `json:"lastUpdateInstant,omitempty"`
	Memberships        []GroupMember              `json:"memberships,omitempty"`
	MiddleName         string                     `json:"middleName,omitempty"`
	MobilePhone        string                     `json:"mobilePhone,omitempty"`
	ParentEmail        string                     `json:"parentEmail,omitempty"`
	PhoneNumber        string                     `json:"phoneNumber,omitempty"`
	PreferredLanguages []string                   `json:"preferredLanguages,omitempty"`
	Registrations      []UserRegistration         `json:"registrations,omitempty"`
	TenantId           string                     `json:"tenantId,omitempty"`
	Timezone           string                     `json:"timezone,omitempty"`
	TwoFactor          UserTwoFactorConfiguration `json:"twoFactor,omitempty"`
}

/**
 * An action that can be executed on a user (discipline or reward potentially).
 *
 * @author Brian Pontarelli
 */
type UserAction struct {
	Active                   bool               `json:"active"`
	CancelEmailTemplateId    string             `json:"cancelEmailTemplateId,omitempty"`
	EndEmailTemplateId       string             `json:"endEmailTemplateId,omitempty"`
	Id                       string             `json:"id,omitempty"`
	IncludeEmailInEventJSON  bool               `json:"includeEmailInEventJSON"`
	InsertInstant            int64              `json:"insertInstant,omitempty"`
	LastUpdateInstant        int64              `json:"lastUpdateInstant,omitempty"`
	LocalizedNames           map[string]string  `json:"localizedNames,omitempty"`
	ModifyEmailTemplateId    string             `json:"modifyEmailTemplateId,omitempty"`
	Name                     string             `json:"name,omitempty"`
	Options                  []UserActionOption `json:"options,omitempty"`
	PreventLogin             bool               `json:"preventLogin"`
	SendEndEvent             bool               `json:"sendEndEvent"`
	StartEmailTemplateId     string             `json:"startEmailTemplateId,omitempty"`
	Temporal                 bool               `json:"temporal"`
	TransactionType          TransactionType    `json:"transactionType,omitempty"`
	UserEmailingEnabled      bool               `json:"userEmailingEnabled"`
	UserNotificationsEnabled bool               `json:"userNotificationsEnabled"`
}

/**
 * Models the user action Event.
 *
 * @author Brian Pontarelli
 */
type UserActionEvent struct {
	BaseEvent
	Action            string          `json:"action,omitempty"`
	ActioneeUserId    string          `json:"actioneeUserId,omitempty"`
	ActionerUserId    string          `json:"actionerUserId,omitempty"`
	ActionId          string          `json:"actionId,omitempty"`
	ApplicationIds    []string        `json:"applicationIds,omitempty"`
	Comment           string          `json:"comment,omitempty"`
	Email             Email           `json:"email,omitempty"`
	EmailedUser       bool            `json:"emailedUser"`
	Expiry            int64           `json:"expiry,omitempty"`
	LocalizedAction   string          `json:"localizedAction,omitempty"`
	LocalizedDuration string          `json:"localizedDuration,omitempty"`
	LocalizedOption   string          `json:"localizedOption,omitempty"`
	LocalizedReason   string          `json:"localizedReason,omitempty"`
	NotifyUser        bool            `json:"notifyUser"`
	Option            string          `json:"option,omitempty"`
	Phase             UserActionPhase `json:"phase,omitempty"`
	Reason            string          `json:"reason,omitempty"`
	ReasonCode        string          `json:"reasonCode,omitempty"`
}

/**
 * A log for an action that was taken on a User.
 *
 * @author Brian Pontarelli
 */
type UserActionLog struct {
	ActioneeUserId  string     `json:"actioneeUserId,omitempty"`
	ActionerUserId  string     `json:"actionerUserId,omitempty"`
	ApplicationIds  []string   `json:"applicationIds,omitempty"`
	Comment         string     `json:"comment,omitempty"`
	EmailUserOnEnd  bool       `json:"emailUserOnEnd"`
	EndEventSent    bool       `json:"endEventSent"`
	Expiry          int64      `json:"expiry,omitempty"`
	History         LogHistory `json:"history,omitempty"`
	Id              string     `json:"id,omitempty"`
	InsertInstant   int64      `json:"insertInstant,omitempty"`
	LocalizedName   string     `json:"localizedName,omitempty"`
	LocalizedOption string     `json:"localizedOption,omitempty"`
	LocalizedReason string     `json:"localizedReason,omitempty"`
	Name            string     `json:"name,omitempty"`
	NotifyUserOnEnd bool       `json:"notifyUserOnEnd"`
	Option          string     `json:"option,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	ReasonCode      string     `json:"reasonCode,omitempty"`
	UserActionId    string     `json:"userActionId,omitempty"`
}

/**
 * Models content user action options.
 *
 * @author Brian Pontarelli
 */
type UserActionOption struct {
	LocalizedNames map[string]string `json:"localizedNames,omitempty"`
	Name           string            `json:"name,omitempty"`
}

/**
 * The phases of a time-based user action.
 *
 * @author Brian Pontarelli
 */
type UserActionPhase string

func (e UserActionPhase) String() string {
	return string(e)
}

const (
	UserActionPhase_Start  UserActionPhase = "start"
	UserActionPhase_Modify UserActionPhase = "modify"
	UserActionPhase_Cancel UserActionPhase = "cancel"
	UserActionPhase_End    UserActionPhase = "end"
)

/**
 * Models action reasons.
 *
 * @author Brian Pontarelli
 */
type UserActionReason struct {
	Code              string            `json:"code,omitempty"`
	Id                string            `json:"id,omitempty"`
	InsertInstant     int64             `json:"insertInstant,omitempty"`
	LastUpdateInstant int64             `json:"lastUpdateInstant,omitempty"`
	LocalizedTexts    map[string]string `json:"localizedTexts,omitempty"`
	Text              string            `json:"text,omitempty"`
}

/**
 * User Action Reason API request object.
 *
 * @author Brian Pontarelli
 */
type UserActionReasonRequest struct {
	UserActionReason UserActionReason `json:"userActionReason,omitempty"`
}

/**
 * User Action Reason API response object.
 *
 * @author Brian Pontarelli
 */
type UserActionReasonResponse struct {
	BaseHTTPResponse
	UserActionReason  UserActionReason   `json:"userActionReason,omitempty"`
	UserActionReasons []UserActionReason `json:"userActionReasons,omitempty"`
}

func (b *UserActionReasonResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * User Action API request object.
 *
 * @author Brian Pontarelli
 */
type UserActionRequest struct {
	UserAction UserAction `json:"userAction,omitempty"`
}

/**
 * User Action API response object.
 *
 * @author Brian Pontarelli
 */
type UserActionResponse struct {
	BaseHTTPResponse
	UserAction  UserAction   `json:"userAction,omitempty"`
	UserActions []UserAction `json:"userActions,omitempty"`
}

func (b *UserActionResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models the User Bulk Create Event.
 *
 * @author Brian Pontarelli
 */
type UserBulkCreateEvent struct {
	BaseEvent
	Users []User `json:"users,omitempty"`
}

/**
 * A log for an event that happened to a User.
 *
 * @author Brian Pontarelli
 */
type UserComment struct {
	Comment       string `json:"comment,omitempty"`
	CommenterId   string `json:"commenterId,omitempty"`
	Id            string `json:"id,omitempty"`
	InsertInstant int64  `json:"insertInstant,omitempty"`
	UserId        string `json:"userId,omitempty"`
}

/**
 * @author Seth Musselman
 */
type UserCommentRequest struct {
	UserComment UserComment `json:"userComment,omitempty"`
}

/**
 * User Comment Response
 *
 * @author Seth Musselman
 */
type UserCommentResponse struct {
	BaseHTTPResponse
	UserComment  UserComment   `json:"userComment,omitempty"`
	UserComments []UserComment `json:"userComments,omitempty"`
}

func (b *UserCommentResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for user comments.
 *
 * @author Spencer Witt
 */
type UserCommentSearchCriteria struct {
	BaseSearchCriteria
	Comment     string `json:"comment,omitempty"`
	CommenterId string `json:"commenterId,omitempty"`
	TenantId    string `json:"tenantId,omitempty"`
	UserId      string `json:"userId,omitempty"`
}

/**
 * Search request for user comments
 *
 * @author Spencer Witt
 */
type UserCommentSearchRequest struct {
	Search UserCommentSearchCriteria `json:"search,omitempty"`
}

/**
 * User comment search response
 *
 * @author Spencer Witt
 */
type UserCommentSearchResponse struct {
	BaseHTTPResponse
	Total        int64         `json:"total,omitempty"`
	UserComments []UserComment `json:"userComments,omitempty"`
}

func (b *UserCommentSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models a User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsent struct {
	Consent           Consent                `json:"consent,omitempty"`
	ConsentId         string                 `json:"consentId,omitempty"`
	Data              map[string]interface{} `json:"data,omitempty"`
	GiverUserId       string                 `json:"giverUserId,omitempty"`
	Id                string                 `json:"id,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	Status            ConsentStatus          `json:"status,omitempty"`
	UserId            string                 `json:"userId,omitempty"`
	Values            []string               `json:"values,omitempty"`
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsentRequest struct {
	UserConsent UserConsent `json:"userConsent,omitempty"`
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsentResponse struct {
	BaseHTTPResponse
	UserConsent  UserConsent   `json:"userConsent,omitempty"`
	UserConsents []UserConsent `json:"userConsents,omitempty"`
}

func (b *UserConsentResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Models the User Created Event.
 * <p>
 * This is different than the user.create event in that it will be sent after the user has been created. This event cannot be made transactional.
 *
 * @author Daniel DeGroff
 */
type UserCreateCompleteEvent struct {
	BaseUserEvent
}

/**
 * Models the User Create Event.
 *
 * @author Brian Pontarelli
 */
type UserCreateEvent struct {
	BaseUserEvent
}

/**
 * Models the User Deactivate Event.
 *
 * @author Brian Pontarelli
 */
type UserDeactivateEvent struct {
	BaseUserEvent
}

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 * <p>
 * This is different than user.delete because it is sent after the tx is committed, this cannot be transactional.
 *
 * @author Daniel DeGroff
 */
type UserDeleteCompleteEvent struct {
	BaseUserEvent
}

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 *
 * @author Brian Pontarelli
 */
type UserDeleteEvent struct {
	BaseUserEvent
}

/**
 * User API delete request object.
 *
 * @author Daniel DeGroff
 */
type UserDeleteRequest struct {
	BaseEventRequest
	DryRun      bool     `json:"dryRun"`
	HardDelete  bool     `json:"hardDelete"`
	Limit       int      `json:"limit,omitempty"`
	Query       string   `json:"query,omitempty"`
	QueryString string   `json:"queryString,omitempty"`
	UserIds     []string `json:"userIds,omitempty"`
}

/**
 * User API bulk response object.
 *
 * @author Trevor Smith
 */
type UserDeleteResponse struct {
	BaseHTTPResponse
	DryRun     bool     `json:"dryRun"`
	HardDelete bool     `json:"hardDelete"`
	Total      int      `json:"total,omitempty"`
	UserIds    []string `json:"userIds,omitempty"`
}

func (b *UserDeleteResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * User API delete request object for a single user.
 *
 * @author Brian Pontarelli
 */
type UserDeleteSingleRequest struct {
	BaseEventRequest
	HardDelete bool `json:"hardDelete"`
}

/**
 * Models an event where a user's email is updated outside of a forgot / change password workflow.
 *
 * @author Daniel DeGroff
 */
type UserEmailUpdateEvent struct {
	BaseUserEvent
	PreviousEmail string `json:"previousEmail,omitempty"`
}

/**
 * Models the User Email Verify Event.
 *
 * @author Trevor Smith
 */
type UserEmailVerifiedEvent struct {
	BaseUserEvent
}

/**
 * @author Daniel DeGroff
 */
type UserIdentity struct {
	DisplayValue      string                 `json:"displayValue,omitempty"`
	InsertInstant     int64                  `json:"insertInstant,omitempty"`
	LastLoginInstant  int64                  `json:"lastLoginInstant,omitempty"`
	LastUpdateInstant int64                  `json:"lastUpdateInstant,omitempty"`
	ModerationStatus  ContentStatus          `json:"moderationStatus,omitempty"`
	Primary           bool                   `json:"primary"`
	Type              string                 `json:"type,omitempty"`
	Value             string                 `json:"value,omitempty"`
	Verified          bool                   `json:"verified"`
	VerifiedInstant   int64                  `json:"verifiedInstant,omitempty"`
	VerifiedReason    IdentityVerifiedReason `json:"verifiedReason,omitempty"`
}

/**
 * Models the User Identity Provider Link Event.
 *
 * @author Rob Davis
 */
type UserIdentityProviderLinkEvent struct {
	BaseUserEvent
	IdentityProviderLink IdentityProviderLink `json:"identityProviderLink,omitempty"`
}

/**
 * Models the User Identity Provider Unlink Event.
 *
 * @author Rob Davis
 */
type UserIdentityProviderUnlinkEvent struct {
	BaseUserEvent
	IdentityProviderLink IdentityProviderLink `json:"identityProviderLink,omitempty"`
}

/**
 * Models the user identity update event
 *
 * @author Brent Halsey
 */
type UserIdentityUpdateEvent struct {
	BaseUserEvent
	LoginIdType     string `json:"loginIdType,omitempty"`
	NewLoginId      string `json:"newLoginId,omitempty"`
	PreviousLoginId string `json:"previousLoginId,omitempty"`
}

/**
 * Models the user identity verified event
 *
 * @author Brady Wied
 */
type UserIdentityVerifiedEvent struct {
	BaseUserEvent
	LoginId     string `json:"loginId,omitempty"`
	LoginIdType string `json:"loginIdType,omitempty"`
}

/**
 * Models the User Login Failed Event.
 *
 * @author Daniel DeGroff
 */
type UserLoginFailedEvent struct {
	BaseUserEvent
	ApplicationId      string                `json:"applicationId,omitempty"`
	AuthenticationType string                `json:"authenticationType,omitempty"`
	IpAddress          string                `json:"ipAddress,omitempty"`
	Reason             UserLoginFailedReason `json:"reason,omitempty"`
}

/**
 * The reason for the login failure.
 *
 * @author Daniel DeGroff
 */
type UserLoginFailedReason struct {
	Code         string `json:"code,omitempty"`
	LambdaId     string `json:"lambdaId,omitempty"`
	LambdaResult Errors `json:"lambdaResult,omitempty"`
}

/**
 * User login failed reason codes.
 */
type UserLoginFailedReasonCode struct {
}

/**
 * Models an event where a user is being created with an "in-use" login Id (email, username, or other identities).
 *
 * @author Daniel DeGroff
 */
type UserLoginIdDuplicateOnCreateEvent struct {
	BaseUserEvent
	DuplicateEmail       string         `json:"duplicateEmail,omitempty"`
	DuplicateIdentities  []IdentityInfo `json:"duplicateIdentities,omitempty"`
	DuplicatePhoneNumber string         `json:"duplicatePhoneNumber,omitempty"`
	DuplicateUsername    string         `json:"duplicateUsername,omitempty"`
	Existing             User           `json:"existing,omitempty"`
}

/**
 * Models an event where a user is being updated and tries to use an "in-use" login Id (email or username).
 *
 * @author Daniel DeGroff
 */
type UserLoginIdDuplicateOnUpdateEvent struct {
	UserLoginIdDuplicateOnCreateEvent
}

/**
 * Models the User Login event for a new device (un-recognized)
 *
 * @author Daniel DeGroff
 */
type UserLoginNewDeviceEvent struct {
	UserLoginSuccessEvent
}

/**
 * Models the User Login Success Event.
 *
 * @author Daniel DeGroff
 */
type UserLoginSuccessEvent struct {
	BaseUserEvent
	ApplicationId        string `json:"applicationId,omitempty"`
	AuthenticationType   string `json:"authenticationType,omitempty"`
	ConnectorId          string `json:"connectorId,omitempty"`
	IdentityProviderId   string `json:"identityProviderId,omitempty"`
	IdentityProviderName string `json:"identityProviderName,omitempty"`
	IpAddress            string `json:"ipAddress,omitempty"`
}

/**
 * Models the User Login event that is suspicious.
 *
 * @author Daniel DeGroff
 */
type UserLoginSuspiciousEvent struct {
	UserLoginSuccessEvent
	ThreatsDetected []AuthenticationThreats `json:"threatsDetected,omitempty"`
}

/**
 * Models the User Password Breach Event.
 *
 * @author Matthew Altman
 */
type UserPasswordBreachEvent struct {
	BaseUserEvent
}

/**
 * Models the User Password Reset Send Event.
 *
 * @author Daniel DeGroff
 */
type UserPasswordResetSendEvent struct {
	BaseUserEvent
}

/**
 * Models the User Password Reset Start Event.
 *
 * @author Daniel DeGroff
 */
type UserPasswordResetStartEvent struct {
	BaseUserEvent
}

/**
 * Models the User Password Reset Success Event.
 *
 * @author Daniel DeGroff
 */
type UserPasswordResetSuccessEvent struct {
	BaseUserEvent
}

/**
 * Models the User Password Update Event.
 *
 * @author Daniel DeGroff
 */
type UserPasswordUpdateEvent struct {
	BaseUserEvent
}

/**
 * Models the User Reactivate Event.
 *
 * @author Brian Pontarelli
 */
type UserReactivateEvent struct {
	BaseUserEvent
}

/**
 * User registration information for a single application.
 *
 * @author Brian Pontarelli
 */
type UserRegistration struct {
	ApplicationId       string                 `json:"applicationId,omitempty"`
	AuthenticationToken string                 `json:"authenticationToken,omitempty"`
	CleanSpeakId        string                 `json:"cleanSpeakId,omitempty"`
	Data                map[string]interface{} `json:"data,omitempty"`
	Id                  string                 `json:"id,omitempty"`
	InsertInstant       int64                  `json:"insertInstant,omitempty"`
	LastLoginInstant    int64                  `json:"lastLoginInstant,omitempty"`
	LastUpdateInstant   int64                  `json:"lastUpdateInstant,omitempty"`
	PreferredLanguages  []string               `json:"preferredLanguages,omitempty"`
	Roles               []string               `json:"roles,omitempty"`
	Timezone            string                 `json:"timezone,omitempty"`
	Tokens              map[string]string      `json:"tokens,omitempty"`
	Username            string                 `json:"username,omitempty"`
	UsernameStatus      ContentStatus          `json:"usernameStatus,omitempty"`
	Verified            bool                   `json:"verified"`
	VerifiedInstant     int64                  `json:"verifiedInstant,omitempty"`
}

/**
 * Models the User Created Registration Event.
 * <p>
 * This is different than the user.registration.create event in that it will be sent after the user has been created. This event cannot be made
 * transactional.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationCreateCompleteEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Create Registration Event.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationCreateEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Deleted Registration Event.
 * <p>
 * This is different than user.registration.delete in that it is sent after the TX has been committed. This event cannot be transactional.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationDeleteCompleteEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Delete Registration Event.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationDeleteEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Update Registration Event.
 * <p>
 * This is different than user.registration.update in that it is sent after this event completes, this cannot be transactional.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationUpdateCompleteEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Original      UserRegistration `json:"original,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Update Registration Event.
 *
 * @author Daniel DeGroff
 */
type UserRegistrationUpdateEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Original      UserRegistration `json:"original,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * Models the User Registration Verified Event.
 *
 * @author Trevor Smith
 */
type UserRegistrationVerifiedEvent struct {
	BaseUserEvent
	ApplicationId string           `json:"applicationId,omitempty"`
	Registration  UserRegistration `json:"registration,omitempty"`
}

/**
 * User API request object.
 *
 * @author Brian Pontarelli
 */
type UserRequest struct {
	BaseEventRequest
	ApplicationId               string                      `json:"applicationId,omitempty"`
	CurrentPassword             string                      `json:"currentPassword,omitempty"`
	DisableDomainBlock          bool                        `json:"disableDomainBlock"`
	SendSetPasswordEmail        bool                        `json:"sendSetPasswordEmail"`
	SendSetPasswordIdentityType SendSetPasswordIdentityType `json:"sendSetPasswordIdentityType,omitempty"`
	SkipVerification            bool                        `json:"skipVerification"`
	User                        User                        `json:"user,omitempty"`
	VerificationIds             []string                    `json:"verificationIds,omitempty"`
}

/**
 * User API response object.
 *
 * @author Brian Pontarelli
 */
type UserResponse struct {
	BaseHTTPResponse
	EmailVerificationId                  string            `json:"emailVerificationId,omitempty"`
	EmailVerificationOneTimeCode         string            `json:"emailVerificationOneTimeCode,omitempty"`
	RegistrationVerificationIds          map[string]string `json:"registrationVerificationIds,omitempty"`
	RegistrationVerificationOneTimeCodes map[string]string `json:"registrationVerificationOneTimeCodes,omitempty"`
	Token                                string            `json:"token,omitempty"`
	TokenExpirationInstant               int64             `json:"tokenExpirationInstant,omitempty"`
	User                                 User              `json:"user,omitempty"`
	VerificationIds                      []VerificationId  `json:"verificationIds,omitempty"`
}

func (b *UserResponse) SetStatus(status int) {
	b.StatusCode = status
}

type VerificationId struct {
	Id          string `json:"id,omitempty"`
	OneTimeCode string `json:"oneTimeCode,omitempty"`
	Type        string `json:"type,omitempty"`
	Value       string `json:"value,omitempty"`
}

/**
 * This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 */
type UserSearchCriteria struct {
	BaseElasticSearchCriteria
}

/**
 * @author Daniel DeGroff
 */
type UserState string

func (e UserState) String() string {
	return string(e)
}

const (
	UserState_Authenticated                        UserState = "Authenticated"
	UserState_AuthenticatedNotRegistered           UserState = "AuthenticatedNotRegistered"
	UserState_AuthenticatedNotVerified             UserState = "AuthenticatedNotVerified"
	UserState_AuthenticatedRegistrationNotVerified UserState = "AuthenticatedRegistrationNotVerified"
)

/**
 * @author Daniel DeGroff
 */
type UserTwoFactorConfiguration struct {
	Methods       []TwoFactorMethod `json:"methods,omitempty"`
	RecoveryCodes []string          `json:"recoveryCodes,omitempty"`
}

/**
 * Model a user event when a two-factor method has been removed.
 *
 * @author Daniel DeGroff
 */
type UserTwoFactorMethodAddEvent struct {
	BaseUserEvent
	Method TwoFactorMethod `json:"method,omitempty"`
}

/**
 * Model a user event when a two-factor method has been added.
 *
 * @author Daniel DeGroff
 */
type UserTwoFactorMethodRemoveEvent struct {
	BaseUserEvent
	Method TwoFactorMethod `json:"method,omitempty"`
}

/**
 * Models the User Update Event once it is completed. This cannot be transactional.
 *
 * @author Daniel DeGroff
 */
type UserUpdateCompleteEvent struct {
	BaseUserEvent
	Original User `json:"original,omitempty"`
}

/**
 * Models the User Update Event.
 *
 * @author Brian Pontarelli
 */
type UserUpdateEvent struct {
	BaseUserEvent
	Original User `json:"original,omitempty"`
}

/**
 * Used to express whether the Relying Party requires <a href="https://www.w3.org/TR/webauthn-2/#user-verification">user verification</a> for the
 * current operation.
 *
 * @author Spencer Witt
 */
type UserVerificationRequirement string

func (e UserVerificationRequirement) String() string {
	return string(e)
}

const (
	UserVerificationRequirement_Required    UserVerificationRequirement = "required"
	UserVerificationRequirement_Preferred   UserVerificationRequirement = "preferred"
	UserVerificationRequirement_Discouraged UserVerificationRequirement = "discouraged"
)

/**
 * @author Daniel DeGroff
 */
type ValidateResponse struct {
	BaseHTTPResponse
	Jwt JWT `json:"jwt,omitempty"`
}

func (b *ValidateResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VerificationStrategy string

func (e VerificationStrategy) String() string {
	return string(e)
}

const (
	VerificationStrategy_ClickableLink VerificationStrategy = "ClickableLink"
	VerificationStrategy_FormField     VerificationStrategy = "FormField"
)

/**
 * Verify Complete API request object.
 */
type VerifyCompleteRequest struct {
	BaseEventRequest
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

/**
 * Verify Complete API response object.
 */
type VerifyCompleteResponse struct {
	BaseHTTPResponse
	State map[string]interface{} `json:"state,omitempty"`
}

func (b *VerifyCompleteResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VerifyEmailRequest struct {
	BaseEventRequest
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	UserId         string `json:"userId,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type VerifyEmailResponse struct {
	BaseHTTPResponse
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

func (b *VerifyEmailResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VerifyRegistrationRequest struct {
	BaseEventRequest
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type VerifyRegistrationResponse struct {
	BaseHTTPResponse
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

func (b *VerifyRegistrationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Identity verify request. Used to administratively verify an identity.
 */
type VerifyRequest struct {
	BaseEventRequest
	LoginId     string `json:"loginId,omitempty"`
	LoginIdType string `json:"loginIdType,omitempty"`
}

/**
 * Verify Send API request object.
 */
type VerifySendRequest struct {
	VerificationId string `json:"verificationId,omitempty"`
}

/**
 * @author Brady Wied
 */
type VerifyStartRequest struct {
	ApplicationId        string                 `json:"applicationId,omitempty"`
	LoginId              string                 `json:"loginId,omitempty"`
	LoginIdType          string                 `json:"loginIdType,omitempty"`
	State                map[string]interface{} `json:"state,omitempty"`
	VerificationStrategy VerificationStrategy   `json:"verificationStrategy,omitempty"`
}

/**
 * @author Brady Wied
 */
type VerifyStartResponse struct {
	BaseHTTPResponse
	OneTimeCode    string `json:"oneTimeCode,omitempty"`
	VerificationId string `json:"verificationId,omitempty"`
}

func (b *VerifyStartResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VersionResponse struct {
	BaseHTTPResponse
	Version string `json:"version,omitempty"`
}

func (b *VersionResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * API response for completing WebAuthn assertion
 *
 * @author Spencer Witt
 */
type WebAuthnAssertResponse struct {
	BaseHTTPResponse
	Credential WebAuthnCredential `json:"credential,omitempty"`
}

func (b *WebAuthnAssertResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The <i>authenticator's</i> response for the authentication ceremony in its encoded format
 *
 * @author Spencer Witt
 */
type WebAuthnAuthenticatorAuthenticationResponse struct {
	BaseHTTPResponse
	AuthenticatorData string `json:"authenticatorData,omitempty"`
	ClientDataJSON    string `json:"clientDataJSON,omitempty"`
	Signature         string `json:"signature,omitempty"`
	UserHandle        string `json:"userHandle,omitempty"`
}

func (b *WebAuthnAuthenticatorAuthenticationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The <i>authenticator's</i> response for the registration ceremony in its encoded format
 *
 * @author Spencer Witt
 */
type WebAuthnAuthenticatorRegistrationResponse struct {
	BaseHTTPResponse
	AttestationObject string `json:"attestationObject,omitempty"`
	ClientDataJSON    string `json:"clientDataJSON,omitempty"`
}

func (b *WebAuthnAuthenticatorRegistrationResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * A User's WebAuthnCredential. Contains all data required to complete WebAuthn authentication ceremonies.
 *
 * @author Spencer Witt
 */
type WebAuthnCredential struct {
	Algorithm                             CoseAlgorithmIdentifier `json:"algorithm,omitempty"`
	AttestationType                       AttestationType         `json:"attestationType,omitempty"`
	AuthenticatorSupportsUserVerification bool                    `json:"authenticatorSupportsUserVerification"`
	CredentialId                          string                  `json:"credentialId,omitempty"`
	Data                                  map[string]interface{}  `json:"data,omitempty"`
	Discoverable                          bool                    `json:"discoverable"`
	DisplayName                           string                  `json:"displayName,omitempty"`
	Id                                    string                  `json:"id,omitempty"`
	InsertInstant                         int64                   `json:"insertInstant,omitempty"`
	LastUseInstant                        int64                   `json:"lastUseInstant,omitempty"`
	Name                                  string                  `json:"name,omitempty"`
	PublicKey                             string                  `json:"publicKey,omitempty"`
	RelyingPartyId                        string                  `json:"relyingPartyId,omitempty"`
	SignCount                             int                     `json:"signCount,omitempty"`
	TenantId                              string                  `json:"tenantId,omitempty"`
	Transports                            []string                `json:"transports,omitempty"`
	UserAgent                             string                  `json:"userAgent,omitempty"`
	UserId                                string                  `json:"userId,omitempty"`
}

/**
 * API request to import an existing WebAuthn credential(s)
 *
 * @author Spencer Witt
 */
type WebAuthnCredentialImportRequest struct {
	Credentials           []WebAuthnCredential `json:"credentials,omitempty"`
	ValidateDbConstraints bool                 `json:"validateDbConstraints"`
}

/**
 * WebAuthn Credential API response
 *
 * @author Spencer Witt
 */
type WebAuthnCredentialResponse struct {
	BaseHTTPResponse
	Credential  WebAuthnCredential   `json:"credential,omitempty"`
	Credentials []WebAuthnCredential `json:"credentials,omitempty"`
}

func (b *WebAuthnCredentialResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Contains extension output for requested extensions during a WebAuthn ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnExtensionsClientOutputs struct {
	CredProps CredentialPropertiesOutput `json:"credProps,omitempty"`
}

/**
 * Request to complete the WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnLoginRequest struct {
	BaseLoginRequest
	Credential       WebAuthnPublicKeyAuthenticationRequest `json:"credential,omitempty"`
	Origin           string                                 `json:"origin,omitempty"`
	RpId             string                                 `json:"rpId,omitempty"`
	TwoFactorTrustId string                                 `json:"twoFactorTrustId,omitempty"`
}

/**
 * Request to authenticate with WebAuthn
 *
 * @author Spencer Witt
 */
type WebAuthnPublicKeyAuthenticationRequest struct {
	ClientExtensionResults WebAuthnExtensionsClientOutputs             `json:"clientExtensionResults,omitempty"`
	Id                     string                                      `json:"id,omitempty"`
	Response               WebAuthnAuthenticatorAuthenticationResponse `json:"response,omitempty"`
	RpId                   string                                      `json:"rpId,omitempty"`
	Type                   string                                      `json:"type,omitempty"`
}

/**
 * Request to register a new public key with WebAuthn
 *
 * @author Spencer Witt
 */
type WebAuthnPublicKeyRegistrationRequest struct {
	ClientExtensionResults WebAuthnExtensionsClientOutputs           `json:"clientExtensionResults,omitempty"`
	Id                     string                                    `json:"id,omitempty"`
	Response               WebAuthnAuthenticatorRegistrationResponse `json:"response,omitempty"`
	RpId                   string                                    `json:"rpId,omitempty"`
	Transports             []string                                  `json:"transports,omitempty"`
	Type                   string                                    `json:"type,omitempty"`
}

/**
 * Request to complete the WebAuthn registration ceremony for a new credential,.
 *
 * @author Spencer Witt
 */
type WebAuthnRegisterCompleteRequest struct {
	Credential WebAuthnPublicKeyRegistrationRequest `json:"credential,omitempty"`
	Origin     string                               `json:"origin,omitempty"`
	RpId       string                               `json:"rpId,omitempty"`
	UserId     string                               `json:"userId,omitempty"`
}

/**
 * API response for completing WebAuthn credential registration or assertion
 *
 * @author Spencer Witt
 */
type WebAuthnRegisterCompleteResponse struct {
	BaseHTTPResponse
	Credential WebAuthnCredential `json:"credential,omitempty"`
}

func (b *WebAuthnRegisterCompleteResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * API request to start a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnRegisterStartRequest struct {
	DisplayName string           `json:"displayName,omitempty"`
	Name        string           `json:"name,omitempty"`
	UserAgent   string           `json:"userAgent,omitempty"`
	UserId      string           `json:"userId,omitempty"`
	Workflow    WebAuthnWorkflow `json:"workflow,omitempty"`
}

/**
 * API response for starting a WebAuthn registration ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnRegisterStartResponse struct {
	BaseHTTPResponse
	Options PublicKeyCredentialCreationOptions `json:"options,omitempty"`
}

func (b *WebAuthnRegisterStartResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Options to request extensions during credential registration
 *
 * @author Spencer Witt
 */
type WebAuthnRegistrationExtensionOptions struct {
	CredProps bool `json:"credProps"`
}

/**
 * API request to start a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnStartRequest struct {
	ApplicationId string                 `json:"applicationId,omitempty"`
	CredentialId  string                 `json:"credentialId,omitempty"`
	LoginId       string                 `json:"loginId,omitempty"`
	LoginIdTypes  []string               `json:"loginIdTypes,omitempty"`
	State         map[string]interface{} `json:"state,omitempty"`
	UserId        string                 `json:"userId,omitempty"`
	Workflow      WebAuthnWorkflow       `json:"workflow,omitempty"`
}

/**
 * API response for starting a WebAuthn authentication ceremony
 *
 * @author Spencer Witt
 */
type WebAuthnStartResponse struct {
	BaseHTTPResponse
	Options PublicKeyCredentialRequestOptions `json:"options,omitempty"`
}

func (b *WebAuthnStartResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Identifies the WebAuthn workflow. This will affect the parameters used for credential creation
 * and request based on the Tenant configuration.
 *
 * @author Spencer Witt
 */
type WebAuthnWorkflow string

func (e WebAuthnWorkflow) String() string {
	return string(e)
}

const (
	WebAuthnWorkflow_Bootstrap        WebAuthnWorkflow = "bootstrap"
	WebAuthnWorkflow_General          WebAuthnWorkflow = "general"
	WebAuthnWorkflow_Reauthentication WebAuthnWorkflow = "reauthentication"
)

/**
 * A server where events are sent. This includes user action events and any other events sent by FusionAuth.
 *
 * @author Brian Pontarelli
 */
type Webhook struct {
	ConnectTimeout             int                           `json:"connectTimeout,omitempty"`
	Data                       map[string]interface{}        `json:"data,omitempty"`
	Description                string                        `json:"description,omitempty"`
	EventsEnabled              map[EventType]bool            `json:"eventsEnabled,omitempty"`
	Global                     bool                          `json:"global"`
	Headers                    map[string]string             `json:"headers,omitempty"`
	HttpAuthenticationPassword string                        `json:"httpAuthenticationPassword,omitempty"`
	HttpAuthenticationUsername string                        `json:"httpAuthenticationUsername,omitempty"`
	Id                         string                        `json:"id,omitempty"`
	InsertInstant              int64                         `json:"insertInstant,omitempty"`
	LastUpdateInstant          int64                         `json:"lastUpdateInstant,omitempty"`
	ReadTimeout                int                           `json:"readTimeout,omitempty"`
	SignatureConfiguration     WebhookSignatureConfiguration `json:"signatureConfiguration,omitempty"`
	SslCertificate             string                        `json:"sslCertificate,omitempty"`
	SslCertificateKeyId        string                        `json:"sslCertificateKeyId,omitempty"`
	TenantIds                  []string                      `json:"tenantIds,omitempty"`
	Url                        string                        `json:"url,omitempty"`
}

/**
 * A webhook call attempt log.
 *
 * @author Spencer Witt
 */
type WebhookAttemptLog struct {
	AttemptResult       WebhookAttemptResult   `json:"attemptResult,omitempty"`
	Data                map[string]interface{} `json:"data,omitempty"`
	EndInstant          int64                  `json:"endInstant,omitempty"`
	Id                  string                 `json:"id,omitempty"`
	StartInstant        int64                  `json:"startInstant,omitempty"`
	WebhookCallResponse WebhookCallResponse    `json:"webhookCallResponse,omitempty"`
	WebhookEventLogId   string                 `json:"webhookEventLogId,omitempty"`
	WebhookId           string                 `json:"webhookId,omitempty"`
}

/**
 * Webhook attempt log response.
 *
 * @author Spencer Witt
 */
type WebhookAttemptLogResponse struct {
	BaseHTTPResponse
	WebhookAttemptLog WebhookAttemptLog `json:"webhookAttemptLog,omitempty"`
}

func (b *WebhookAttemptLogResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The possible states of an individual webhook attempt to a single endpoint.
 *
 * @author Spencer Witt
 */
type WebhookAttemptResult string

func (e WebhookAttemptResult) String() string {
	return string(e)
}

const (
	WebhookAttemptResult_Success WebhookAttemptResult = "Success"
	WebhookAttemptResult_Failure WebhookAttemptResult = "Failure"
	WebhookAttemptResult_Unknown WebhookAttemptResult = "Unknown"
)

/**
 * A webhook call response.
 *
 * @author Spencer Witt
 */
type WebhookCallResponse struct {
	BaseHTTPResponse
	Exception  string `json:"exception,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	Url        string `json:"url,omitempty"`
}

func (b *WebhookCallResponse) SetStatus(status int) {
	b.StatusCode = status
}

type WebhookEventLog struct {
	Attempts           []WebhookAttemptLog    `json:"attempts,omitempty"`
	Data               map[string]interface{} `json:"data,omitempty"`
	Event              EventRequest           `json:"event,omitempty"`
	EventResult        WebhookEventResult     `json:"eventResult,omitempty"`
	EventType          EventType              `json:"eventType,omitempty"`
	FailedAttempts     int                    `json:"failedAttempts,omitempty"`
	Id                 string                 `json:"id,omitempty"`
	InsertInstant      int64                  `json:"insertInstant,omitempty"`
	LastAttemptInstant int64                  `json:"lastAttemptInstant,omitempty"`
	LastUpdateInstant  int64                  `json:"lastUpdateInstant,omitempty"`
	LinkedObjectId     string                 `json:"linkedObjectId,omitempty"`
	Sequence           int64                  `json:"sequence,omitempty"`
	SuccessfulAttempts int                    `json:"successfulAttempts,omitempty"`
}

/**
 * The system configuration for Webhook Event Log data.
 *
 * @author Spencer Witt
 */
type WebhookEventLogConfiguration struct {
	Enableable
	Delete DeleteConfiguration `json:"delete,omitempty"`
}

/**
 * Webhook event log response.
 *
 * @author Spencer Witt
 */
type WebhookEventLogResponse struct {
	BaseHTTPResponse
	WebhookEventLog WebhookEventLog `json:"webhookEventLog,omitempty"`
}

func (b *WebhookEventLogResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for the webhook event log.
 *
 * @author Spencer Witt
 */
type WebhookEventLogSearchCriteria struct {
	BaseSearchCriteria
	End         int64              `json:"end,omitempty"`
	Event       string             `json:"event,omitempty"`
	EventResult WebhookEventResult `json:"eventResult,omitempty"`
	EventType   EventType          `json:"eventType,omitempty"`
	Start       int64              `json:"start,omitempty"`
}

/**
 * Webhook event log search request.
 *
 * @author Spencer Witt
 */
type WebhookEventLogSearchRequest struct {
	Search WebhookEventLogSearchCriteria `json:"search,omitempty"`
}

/**
 * Webhook event log search response.
 *
 * @author Spencer Witt
 */
type WebhookEventLogSearchResponse struct {
	BaseHTTPResponse
	Total            int64             `json:"total,omitempty"`
	WebhookEventLogs []WebhookEventLog `json:"webhookEventLogs,omitempty"`
}

func (b *WebhookEventLogSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * The possible result states of a webhook event. This tracks the success of the overall webhook transaction according to the {@link TransactionType}
 * and configured webhooks.
 *
 * @author Spencer Witt
 */
type WebhookEventResult string

func (e WebhookEventResult) String() string {
	return string(e)
}

const (
	WebhookEventResult_Failed    WebhookEventResult = "Failed"
	WebhookEventResult_Running   WebhookEventResult = "Running"
	WebhookEventResult_Succeeded WebhookEventResult = "Succeeded"
)

/**
 * Webhook API request object.
 *
 * @author Brian Pontarelli
 */
type WebhookRequest struct {
	Webhook Webhook `json:"webhook,omitempty"`
}

/**
 * Webhook API response object.
 *
 * @author Brian Pontarelli
 */
type WebhookResponse struct {
	BaseHTTPResponse
	Webhook  Webhook   `json:"webhook,omitempty"`
	Webhooks []Webhook `json:"webhooks,omitempty"`
}

func (b *WebhookResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Search criteria for webhooks.
 *
 * @author Spencer Witt
 */
type WebhookSearchCriteria struct {
	BaseSearchCriteria
	Description string `json:"description,omitempty"`
	TenantId    string `json:"tenantId,omitempty"`
	Url         string `json:"url,omitempty"`
}

/**
 * Search request for webhooks
 *
 * @author Spencer Witt
 */
type WebhookSearchRequest struct {
	Search WebhookSearchCriteria `json:"search,omitempty"`
}

/**
 * Webhook search response
 *
 * @author Spencer Witt
 */
type WebhookSearchResponse struct {
	BaseHTTPResponse
	Total    int64     `json:"total,omitempty"`
	Webhooks []Webhook `json:"webhooks,omitempty"`
}

func (b *WebhookSearchResponse) SetStatus(status int) {
	b.StatusCode = status
}

/**
 * Configuration for signing webhooks.
 *
 * @author Brent Halsey
 */
type WebhookSignatureConfiguration struct {
	Enableable
	SigningKeyId string `json:"signingKeyId,omitempty"`
}

/**
 * @author Brett Pontarelli
 */
type XboxApplicationConfiguration struct {
	BaseIdentityProviderApplicationConfiguration
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Xbox gaming login provider.
 *
 * @author Brett Pontarelli
 */
type XboxIdentityProvider struct {
	BaseIdentityProvider
	ButtonText   string `json:"buttonText,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

/**
 * Controls the policy for refresh token expiration
 * @author Maksym Cierżniak
 */
type OauthRefreshTokenExpirationPolicy string

func (e OauthRefreshTokenExpirationPolicy) String() string {
	return string(e)
}

const (
	OauthRefreshTokenExpirationPolicy_Fixed                            RefreshTokenExpirationPolicy = "Fixed"
	OauthRefreshTokenExpirationPolicy_SlidingWindow                    RefreshTokenExpirationPolicy = "SlidingWindow"
	OauthRefreshTokenExpirationPolicy_SlidingWindowWithMaximumLifetime RefreshTokenExpirationPolicy = "SlidingWindowWithMaximumLifetime"
)
