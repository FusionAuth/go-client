/*
* Copyright (c) 2019, FusionAuth, All Rights Reserved
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

/**
 * @author Daniel DeGroff
 */
type AccessToken struct {
  BaseHTTPResponse
  AccessToken               string                    `json:"access_token,omitempty"`
  ExpiresIn                 int                       `json:"expires_in,omitempty"`
  IdToken                   string                    `json:"id_token,omitempty"`
  RefreshToken              string                    `json:"refresh_token,omitempty"`
  Scope                     string                    `json:"scope,omitempty"`
  TokenType                 TokenType                 `json:"token_type,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}
func (b *AccessToken) SetStatus(status int) {
  b.StatusCode = status
}

type ActionData struct {
  ActioneeUserId            string                    `json:"actioneeUserId,omitempty"`
  ActionerUserId            string                    `json:"actionerUserId,omitempty"`
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
  Comment                   string                    `json:"comment,omitempty"`
  EmailUser                 bool                      `json:"emailUser,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
  NotifyUser                bool                      `json:"notifyUser,omitempty"`
  Option                    string                    `json:"option,omitempty"`
  ReasonId                  string                    `json:"reasonId,omitempty"`
  UserActionId              string                    `json:"userActionId,omitempty"`
}

/**
 * The user action request object.
 *
 * @author Brian Pontarelli
 */
type ActionRequest struct {
  Action                    ActionData                `json:"action,omitempty"`
  Broadcast                 bool                      `json:"broadcast,omitempty"`
}

/**
 * The user action response object.
 *
 * @author Brian Pontarelli
 */
type ActionResponse struct {
  BaseHTTPResponse
  Action                    UserActionLog             `json:"action,omitempty"`
  Actions                   []UserActionLog           `json:"actions,omitempty"`
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
const (
  Algorithm_ES256                Algorithm            = "ES256"
  Algorithm_ES384                Algorithm            = "ES384"
  Algorithm_ES512                Algorithm            = "ES512"
  Algorithm_HS256                Algorithm            = "HS256"
  Algorithm_HS384                Algorithm            = "HS384"
  Algorithm_HS512                Algorithm            = "HS512"
  Algorithm_RS256                Algorithm            = "RS256"
  Algorithm_RS384                Algorithm            = "RS384"
  Algorithm_RS512                Algorithm            = "RS512"
  Algorithm_None                 Algorithm            = "none"
)

/**
 * @author Seth Musselman
 */
type Application struct {
  Active                    bool                      `json:"active,omitempty"`
  AuthenticationTokenConfiguration AuthenticationTokenConfiguration `json:"authenticationTokenConfiguration,omitempty"`
  CleanSpeakConfiguration   CleanSpeakConfiguration   `json:"cleanSpeakConfiguration,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  JwtConfiguration          JWTConfiguration          `json:"jwtConfiguration,omitempty"`
  LambdaConfiguration       LambdaConfiguration       `json:"lambdaConfiguration,omitempty"`
  LoginConfiguration        LoginConfiguration        `json:"loginConfiguration,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  OauthConfiguration        OAuth2Configuration       `json:"oauthConfiguration,omitempty"`
  PasswordlessConfiguration PasswordlessConfiguration `json:"passwordlessConfiguration,omitempty"`
  RegistrationConfiguration RegistrationConfiguration `json:"registrationConfiguration,omitempty"`
  RegistrationDeletePolicy  ApplicationRegistrationDeletePolicy `json:"registrationDeletePolicy,omitempty"`
  Roles                     []ApplicationRole         `json:"roles,omitempty"`
  Samlv2Configuration       SAMLv2Configuration       `json:"samlv2Configuration,omitempty"`
  TenantId                  string                    `json:"tenantId,omitempty"`
  VerificationEmailTemplateId string                    `json:"verificationEmailTemplateId,omitempty"`
  VerifyRegistration        bool                      `json:"verifyRegistration,omitempty"`
}

/**
 * A Application-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
type ApplicationRegistrationDeletePolicy struct {
  Unverified                TimeBasedDeletePolicy     `json:"unverified,omitempty"`
}

/**
 * The Application API request object.
 *
 * @author Brian Pontarelli
 */
type ApplicationRequest struct {
  Application               Application               `json:"application,omitempty"`
  Role                      ApplicationRole           `json:"role,omitempty"`
  WebhookIds                []string                  `json:"webhookIds,omitempty"`
}

/**
 * The Application API response.
 *
 * @author Brian Pontarelli
 */
type ApplicationResponse struct {
  BaseHTTPResponse
  Application               Application               `json:"application,omitempty"`
  Applications              []Application             `json:"applications,omitempty"`
  Role                      ApplicationRole           `json:"role,omitempty"`
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
  Description               string                    `json:"description,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  IsDefault                 bool                      `json:"isDefault,omitempty"`
  IsSuperRole               bool                      `json:"isSuperRole,omitempty"`
  Name                      string                    `json:"name,omitempty"`
}

/**
 * This class is a simple attachment with a byte array, name and MIME type.
 *
 * @author Brian Pontarelli
 */
type Attachment struct {
  Attachment                []byte                    `json:"attachment,omitempty"`
  Mime                      string                    `json:"mime,omitempty"`
  Name                      string                    `json:"name,omitempty"`
}

/**
 * An audit log.
 *
 * @author Brian Pontarelli
 */
type AuditLog struct {
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Id                        int64                     `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  InsertUser                string                    `json:"insertUser,omitempty"`
  Message                   string                    `json:"message,omitempty"`
  NewValue                  interface{}               `json:"newValue,omitempty"`
  OldValue                  interface{}               `json:"oldValue,omitempty"`
  Reason                    string                    `json:"reason,omitempty"`
}

type AuditLogConfiguration struct {
  Delete                    DeleteConfiguration       `json:"delete,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type AuditLogExportRequest struct {
  BaseExportRequest
  Criteria                  AuditLogSearchCriteria    `json:"criteria,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type AuditLogRequest struct {
  AuditLog                  AuditLog                  `json:"auditLog,omitempty"`
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
type AuditLogResponse struct {
  BaseHTTPResponse
  AuditLog                  AuditLog                  `json:"auditLog,omitempty"`
}
func (b *AuditLogResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type AuditLogSearchCriteria struct {
  BaseSearchCriteria
  End                       int64                     `json:"end,omitempty"`
  Message                   string                    `json:"message,omitempty"`
  Start                     int64                     `json:"start,omitempty"`
  User                      string                    `json:"user,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type AuditLogSearchRequest struct {
  Search                    AuditLogSearchCriteria    `json:"search,omitempty"`
}

/**
 * Audit log response.
 *
 * @author Brian Pontarelli
 */
type AuditLogSearchResponse struct {
  BaseHTTPResponse
  AuditLogs                 []AuditLog                `json:"auditLogs,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
}
func (b *AuditLogSearchResponse) SetStatus(status int) {
  b.StatusCode = status
}

type AuthenticationTokenConfiguration struct {
  Enableable
}

/**
 * Base-class for all FusionAuth events.
 *
 * @author Brian Pontarelli
 */
type BaseEvent struct {
  CreateInstant             int64                     `json:"createInstant,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  TenantId                  string                    `json:"tenantId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseExportRequest struct {
  DateTimeSecondsFormat     string                    `json:"dateTimeSecondsFormat,omitempty"`
  ZoneId                    string                    `json:"zoneId,omitempty"`
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
type BaseIdentityProvider struct {
  Enableable
  ApplicationConfiguration  map[string]interface{}    `json:"applicationConfiguration,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Debug                     bool                      `json:"debug,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Type                      IdentityProviderType      `json:"type,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseIdentityProviderApplicationConfiguration struct {
  Enableable
  CreateRegistration        bool                      `json:"createRegistration,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type BaseLoginRequest struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  IpAddress                 string                    `json:"ipAddress,omitempty"`
  MetaData                  MetaData                  `json:"metaData,omitempty"`
  NoJWT                     bool                      `json:"noJWT,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type BaseSearchCriteria struct {
  NumberOfResults           int                       `json:"numberOfResults,omitempty"`
  OrderBy                   string                    `json:"orderBy,omitempty"`
  StartRow                  int                       `json:"startRow,omitempty"`
}

type CanonicalizationMethod string
const (
  CanonicalizationMethod_Exclusive            CanonicalizationMethod = "exclusive"
  CanonicalizationMethod_ExclusiveWithComments CanonicalizationMethod = "exclusive_with_comments"
  CanonicalizationMethod_Inclusive            CanonicalizationMethod = "inclusive"
  CanonicalizationMethod_InclusiveWithComments CanonicalizationMethod = "inclusive_with_comments"
)

type CertificateInformation struct {
  Issuer                    string                    `json:"issuer,omitempty"`
  Md5Fingerprint            string                    `json:"md5Fingerprint,omitempty"`
  SerialNumber              string                    `json:"serialNumber,omitempty"`
  Sha1Fingerprint           string                    `json:"sha1Fingerprint,omitempty"`
  Sha1Thumbprint            string                    `json:"sha1Thumbprint,omitempty"`
  Sha256Fingerprint         string                    `json:"sha256Fingerprint,omitempty"`
  Sha256Thumbprint          string                    `json:"sha256Thumbprint,omitempty"`
  Subject                   string                    `json:"subject,omitempty"`
  ValidFrom                 int64                     `json:"validFrom,omitempty"`
  ValidTo                   int64                     `json:"validTo,omitempty"`
}

/**
 * Change password request object.
 *
 * @author Brian Pontarelli
 */
type ChangePasswordRequest struct {
  CurrentPassword           string                    `json:"currentPassword,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
  Password                  string                    `json:"password,omitempty"`
  RefreshToken              string                    `json:"refreshToken,omitempty"`
}

/**
 * Change password response object.
 *
 * @author Daniel DeGroff
 */
type ChangePasswordResponse struct {
  BaseHTTPResponse
  OneTimePassword           string                    `json:"oneTimePassword,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
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
  ApiKey                    string                    `json:"apiKey,omitempty"`
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
  Url                       string                    `json:"url,omitempty"`
  UsernameModeration        UsernameModeration        `json:"usernameModeration,omitempty"`
}

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
type Consent struct {
  ConsentEmailTemplateId    string                    `json:"consentEmailTemplateId,omitempty"`
  CountryMinimumAgeForSelfConsent map[string]int            `json:"countryMinimumAgeForSelfConsent,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  DefaultMinimumAgeForSelfConsent int                       `json:"defaultMinimumAgeForSelfConsent,omitempty"`
  EmailPlus                 EmailPlus                 `json:"emailPlus,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  MultipleValuesAllowed     bool                      `json:"multipleValuesAllowed,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Values                    []string                  `json:"values,omitempty"`
}

/**
 * API request for User consent types.
 *
 * @author Daniel DeGroff
 */
type ConsentRequest struct {
  Consent                   Consent                   `json:"consent,omitempty"`
}

/**
 * API response for consent.
 *
 * @author Daniel DeGroff
 */
type ConsentResponse struct {
  BaseHTTPResponse
  Consent                   Consent                   `json:"consent,omitempty"`
  Consents                  []Consent                 `json:"consents,omitempty"`
}
func (b *ConsentResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Models a consent.
 *
 * @author Daniel DeGroff
 */
type ConsentStatus string
const (
  ConsentStatus_Active               ConsentStatus        = "Active"
  ConsentStatus_Revoked              ConsentStatus        = "Revoked"
)

/**
 * Status for content like usernames, profile attributes, etc.
 *
 * @author Brian Pontarelli
 */
type ContentStatus string
const (
  ContentStatus_ACTIVE               ContentStatus        = "ACTIVE"
  ContentStatus_PENDING              ContentStatus        = "PENDING"
  ContentStatus_REJECTED             ContentStatus        = "REJECTED"
)

type CORSConfiguration struct {
  Enableable
  AllowCredentials          bool                      `json:"allowCredentials,omitempty"`
  AllowedHeaders            []string                  `json:"allowedHeaders,omitempty"`
  AllowedMethods            []HTTPMethod              `json:"allowedMethods,omitempty"`
  AllowedOrigins            []string                  `json:"allowedOrigins,omitempty"`
  ExposedHeaders            []string                  `json:"exposedHeaders,omitempty"`
  PreflightMaxAgeInSeconds  int                       `json:"preflightMaxAgeInSeconds,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type Count struct {
  Count                     int                       `json:"count,omitempty"`
  Interval                  int                       `json:"interval,omitempty"`
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
type DailyActiveUserReportResponse struct {
  BaseHTTPResponse
  DailyActiveUsers          []Count                   `json:"dailyActiveUsers,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
}
func (b *DailyActiveUserReportResponse) SetStatus(status int) {
  b.StatusCode = status
}

type DeleteConfiguration struct {
  Enableable
  NumberOfDaysToRetain      int                       `json:"numberOfDaysToRetain,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type DeviceInfo struct {
  Description               string                    `json:"description,omitempty"`
  LastAccessedAddress       string                    `json:"lastAccessedAddress,omitempty"`
  LastAccessedInstant       int64                     `json:"lastAccessedInstant,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Type                      DeviceType                `json:"type,omitempty"`
}

/**
 * @author Trevor Smith
 */
type DeviceResponse struct {
  BaseHTTPResponse
  DeviceCode                string                    `json:"device_code,omitempty"`
  ExpiresIn                 int                       `json:"expires_in,omitempty"`
  Interval                  int                       `json:"interval,omitempty"`
  UserCode                  string                    `json:"user_code,omitempty"`
  VerificationUri           string                    `json:"verification_uri,omitempty"`
  VerificationUriComplete   string                    `json:"verification_uri_complete,omitempty"`
}
func (b *DeviceResponse) SetStatus(status int) {
  b.StatusCode = status
}

type DeviceType string
const (
  DeviceType_BROWSER              DeviceType           = "BROWSER"
  DeviceType_DESKTOP              DeviceType           = "DESKTOP"
  DeviceType_LAPTOP               DeviceType           = "LAPTOP"
  DeviceType_MOBILE               DeviceType           = "MOBILE"
  DeviceType_OTHER                DeviceType           = "OTHER"
  DeviceType_SERVER               DeviceType           = "SERVER"
  DeviceType_TABLET               DeviceType           = "TABLET"
  DeviceType_TV                   DeviceType           = "TV"
  DeviceType_UNKNOWN              DeviceType           = "UNKNOWN"
)

/**
 * A displayable raw login that includes application name and user loginId.
 *
 * @author Brian Pontarelli
 */
type DisplayableRawLogin struct {
  RawLogin
  ApplicationName           string                    `json:"applicationName,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
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
  Attachments               []Attachment              `json:"attachments,omitempty"`
  Bcc                       []EmailAddress            `json:"bcc,omitempty"`
  Cc                        []EmailAddress            `json:"cc,omitempty"`
  From                      EmailAddress              `json:"from,omitempty"`
  Html                      string                    `json:"html,omitempty"`
  ReplyTo                   EmailAddress              `json:"replyTo,omitempty"`
  Subject                   string                    `json:"subject,omitempty"`
  Text                      string                    `json:"text,omitempty"`
  To                        []EmailAddress            `json:"to,omitempty"`
}

/**
 * An email address.
 *
 * @author Brian Pontarelli
 */
type EmailAddress struct {
  Address                   string                    `json:"address,omitempty"`
  Display                   string                    `json:"display,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type EmailConfiguration struct {
  ForgotPasswordEmailTemplateId string                    `json:"forgotPasswordEmailTemplateId,omitempty"`
  Host                      string                    `json:"host,omitempty"`
  Password                  string                    `json:"password,omitempty"`
  PasswordlessEmailTemplateId string                    `json:"passwordlessEmailTemplateId,omitempty"`
  Port                      int                       `json:"port,omitempty"`
  Properties                string                    `json:"properties,omitempty"`
  Security                  EmailSecurityType         `json:"security,omitempty"`
  SetPasswordEmailTemplateId string                    `json:"setPasswordEmailTemplateId,omitempty"`
  Username                  string                    `json:"username,omitempty"`
  VerificationEmailTemplateId string                    `json:"verificationEmailTemplateId,omitempty"`
  VerifyEmail               bool                      `json:"verifyEmail,omitempty"`
  VerifyEmailWhenChanged    bool                      `json:"verifyEmailWhenChanged,omitempty"`
}

type EmailPlus struct {
  Enableable
  EmailTemplateId           string                    `json:"emailTemplateId,omitempty"`
  MaximumTimeToSendEmailInHours int                       `json:"maximumTimeToSendEmailInHours,omitempty"`
  MinimumTimeToSendEmailInHours int                       `json:"minimumTimeToSendEmailInHours,omitempty"`
}

type EmailSecurityType string
const (
  EmailSecurityType_NONE                 EmailSecurityType    = "NONE"
  EmailSecurityType_SSL                  EmailSecurityType    = "SSL"
  EmailSecurityType_TLS                  EmailSecurityType    = "TLS"
)

/**
 * Stores an email template used to send emails to users.
 *
 * @author Brian Pontarelli
 */
type EmailTemplate struct {
  DefaultFromName           string                    `json:"defaultFromName,omitempty"`
  DefaultHtmlTemplate       string                    `json:"defaultHtmlTemplate,omitempty"`
  DefaultSubject            string                    `json:"defaultSubject,omitempty"`
  DefaultTextTemplate       string                    `json:"defaultTextTemplate,omitempty"`
  FromEmail                 string                    `json:"fromEmail,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  LocalizedFromNames        map[string]string         `json:"localizedFromNames,omitempty"`
  LocalizedHtmlTemplates    map[string]string         `json:"localizedHtmlTemplates,omitempty"`
  LocalizedSubjects         map[string]string         `json:"localizedSubjects,omitempty"`
  LocalizedTextTemplates    map[string]string         `json:"localizedTextTemplates,omitempty"`
  Name                      string                    `json:"name,omitempty"`
}

type EmailTemplateErrors struct {
  ParseErrors               map[string]string         `json:"parseErrors,omitempty"`
  RenderErrors              map[string]string         `json:"renderErrors,omitempty"`
}

/**
 * Email template request.
 *
 * @author Brian Pontarelli
 */
type EmailTemplateRequest struct {
  EmailTemplate             EmailTemplate             `json:"emailTemplate,omitempty"`
}

/**
 * Email template response.
 *
 * @author Brian Pontarelli
 */
type EmailTemplateResponse struct {
  BaseHTTPResponse
  EmailTemplate             EmailTemplate             `json:"emailTemplate,omitempty"`
  EmailTemplates            []EmailTemplate           `json:"emailTemplates,omitempty"`
}
func (b *EmailTemplateResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Something that can be enabled and thus also disabled.
 *
 * @author Daniel DeGroff
 */
type Enableable struct {
  Enabled                   bool                      `json:"enabled,omitempty"`
}

/**
 * Defines an error.
 *
 * @author Brian Pontarelli
 */
type Error struct {
  Code                      string                    `json:"code,omitempty"`
  Message                   string                    `json:"message,omitempty"`
}

/**
 * Standard error domain object that can also be used as the response from an API call.
 *
 * @author Brian Pontarelli
 */
type Errors struct {
  FieldErrors               map[string][]Error        `json:"fieldErrors,omitempty"`
  GeneralErrors             []Error                   `json:"generalErrors,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type EventConfiguration struct {
  Events                    map[EventType]EventConfigurationData `json:"events,omitempty"`
}

type EventConfigurationData struct {
  Enableable
  TransactionType           TransactionType           `json:"transactionType,omitempty"`
}

/**
 * Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
 *
 * @author Brian Pontarelli
 */
type EventLog struct {
  Id                        int64                     `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  Message                   string                    `json:"message,omitempty"`
  Type                      EventLogType              `json:"type,omitempty"`
}

type EventLogConfiguration struct {
  NumberToRetain            int                       `json:"numberToRetain,omitempty"`
}

/**
 * Event log response.
 *
 * @author Daniel DeGroff
 */
type EventLogResponse struct {
  BaseHTTPResponse
  EventLog                  EventLog                  `json:"eventLog,omitempty"`
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
  End                       int64                     `json:"end,omitempty"`
  Message                   string                    `json:"message,omitempty"`
  Start                     int64                     `json:"start,omitempty"`
  Type                      EventLogType              `json:"type,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type EventLogSearchRequest struct {
  Search                    EventLogSearchCriteria    `json:"search,omitempty"`
}

/**
 * Event log response.
 *
 * @author Brian Pontarelli
 */
type EventLogSearchResponse struct {
  BaseHTTPResponse
  EventLogs                 []EventLog                `json:"eventLogs,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
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
const (
  EventLogType_Information          EventLogType         = "Information"
  EventLogType_Debug                EventLogType         = "Debug"
  EventLogType_Error                EventLogType         = "Error"
)

/**
 * Container for the event information. This is the JSON that is sent from FusionAuth to webhooks.
 *
 * @author Brian Pontarelli
 */
type EventRequest struct {
  Event                     BaseEvent                 `json:"event,omitempty"`
}

/**
 * Models the event types that FusionAuth produces.
 *
 * @author Brian Pontarelli
 */
type EventType string
const (
  EventType_UserDelete           EventType            = "UserDelete"
  EventType_UserCreate           EventType            = "UserCreate"
  EventType_UserUpdate           EventType            = "UserUpdate"
  EventType_UserDeactivate       EventType            = "UserDeactivate"
  EventType_UserBulkCreate       EventType            = "UserBulkCreate"
  EventType_UserReactivate       EventType            = "UserReactivate"
  EventType_UserAction           EventType            = "UserAction"
  EventType_JWTRefreshTokenRevoke EventType            = "JWTRefreshTokenRevoke"
  EventType_JWTPublicKeyUpdate   EventType            = "JWTPublicKeyUpdate"
  EventType_UserLoginSuccess     EventType            = "UserLoginSuccess"
  EventType_UserLoginFailed      EventType            = "UserLoginFailed"
  EventType_UserRegistrationCreate EventType            = "UserRegistrationCreate"
  EventType_UserRegistrationUpdate EventType            = "UserRegistrationUpdate"
  EventType_UserRegistrationDelete EventType            = "UserRegistrationDelete"
  EventType_UserRegistrationVerified EventType            = "UserRegistrationVerified"
  EventType_UserEmailVerified    EventType            = "UserEmailVerified"
  EventType_Test                 EventType            = "Test"
)

/**
 * @author Brian Pontarelli
 */
type ExpiryUnit string
const (
  ExpiryUnit_MINUTES              ExpiryUnit           = "MINUTES"
  ExpiryUnit_HOURS                ExpiryUnit           = "HOURS"
  ExpiryUnit_DAYS                 ExpiryUnit           = "DAYS"
  ExpiryUnit_WEEKS                ExpiryUnit           = "WEEKS"
  ExpiryUnit_MONTHS               ExpiryUnit           = "MONTHS"
  ExpiryUnit_YEARS                ExpiryUnit           = "YEARS"
)

/**
 * @author Daniel DeGroff
 */
type ExternalIdentifierConfiguration struct {
  AuthorizationGrantIdTimeToLiveInSeconds int                       `json:"authorizationGrantIdTimeToLiveInSeconds,omitempty"`
  ChangePasswordIdGenerator SecureGeneratorConfiguration `json:"changePasswordIdGenerator,omitempty"`
  ChangePasswordIdTimeToLiveInSeconds int                       `json:"changePasswordIdTimeToLiveInSeconds,omitempty"`
  DeviceCodeTimeToLiveInSeconds int                       `json:"deviceCodeTimeToLiveInSeconds,omitempty"`
  DeviceUserCodeIdGenerator SecureGeneratorConfiguration `json:"deviceUserCodeIdGenerator,omitempty"`
  EmailVerificationIdGenerator SecureGeneratorConfiguration `json:"emailVerificationIdGenerator,omitempty"`
  EmailVerificationIdTimeToLiveInSeconds int                       `json:"emailVerificationIdTimeToLiveInSeconds,omitempty"`
  ExternalAuthenticationIdTimeToLiveInSeconds int                       `json:"externalAuthenticationIdTimeToLiveInSeconds,omitempty"`
  OneTimePasswordTimeToLiveInSeconds int                       `json:"oneTimePasswordTimeToLiveInSeconds,omitempty"`
  PasswordlessLoginGenerator SecureGeneratorConfiguration `json:"passwordlessLoginGenerator,omitempty"`
  PasswordlessLoginTimeToLiveInSeconds int                       `json:"passwordlessLoginTimeToLiveInSeconds,omitempty"`
  RegistrationVerificationIdGenerator SecureGeneratorConfiguration `json:"registrationVerificationIdGenerator,omitempty"`
  RegistrationVerificationIdTimeToLiveInSeconds int                       `json:"registrationVerificationIdTimeToLiveInSeconds,omitempty"`
  SetupPasswordIdGenerator  SecureGeneratorConfiguration `json:"setupPasswordIdGenerator,omitempty"`
  SetupPasswordIdTimeToLiveInSeconds int                       `json:"setupPasswordIdTimeToLiveInSeconds,omitempty"`
  TwoFactorIdTimeToLiveInSeconds int                       `json:"twoFactorIdTimeToLiveInSeconds,omitempty"`
  TwoFactorTrustIdTimeToLiveInSeconds int                       `json:"twoFactorTrustIdTimeToLiveInSeconds,omitempty"`
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
  ClaimMap                  map[string]string         `json:"claimMap,omitempty"`
  Domains                   []string                  `json:"domains,omitempty"`
  HeaderKeyParameter        string                    `json:"headerKeyParameter,omitempty"`
  Keys                      map[string]string         `json:"keys,omitempty"`
  Oauth2                    IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
  UniqueIdentityClaim       string                    `json:"uniqueIdentityClaim,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type FacebookApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  AppId                     string                    `json:"appId,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
  ClientSecret              string                    `json:"client_secret,omitempty"`
  Fields                    string                    `json:"fields,omitempty"`
  Permissions               string                    `json:"permissions,omitempty"`
}

/**
 * Facebook social login provider.
 *
 * @author Brian Pontarelli
 */
type FacebookIdentityProvider struct {
  BaseIdentityProvider
  AppId                     string                    `json:"appId,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
  ClientSecret              string                    `json:"client_secret,omitempty"`
  Fields                    string                    `json:"fields,omitempty"`
  Permissions               string                    `json:"permissions,omitempty"`
}

/**
 * Configuration for the behavior of failed login attempts. This helps us protect against brute force password attacks.
 *
 * @author Daniel DeGroff
 */
type FailedAuthenticationConfiguration struct {
  ActionDuration            int64                     `json:"actionDuration,omitempty"`
  ActionDurationUnit        ExpiryUnit                `json:"actionDurationUnit,omitempty"`
  ResetCountInSeconds       int                       `json:"resetCountInSeconds,omitempty"`
  TooManyAttempts           int                       `json:"tooManyAttempts,omitempty"`
  UserActionId              string                    `json:"userActionId,omitempty"`
}

/**
 * Models a family grouping of users.
 *
 * @author Brian Pontarelli
 */
type Family struct {
  Id                        string                    `json:"id,omitempty"`
  Members                   []FamilyMember            `json:"members,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type FamilyConfiguration struct {
  Enableable
  AllowChildRegistrations   bool                      `json:"allowChildRegistrations,omitempty"`
  ConfirmChildEmailTemplateId string                    `json:"confirmChildEmailTemplateId,omitempty"`
  DeleteOrphanedAccounts    bool                      `json:"deleteOrphanedAccounts,omitempty"`
  DeleteOrphanedAccountsDays int                       `json:"deleteOrphanedAccountsDays,omitempty"`
  FamilyRequestEmailTemplateId string                    `json:"familyRequestEmailTemplateId,omitempty"`
  MaximumChildAge           int                       `json:"maximumChildAge,omitempty"`
  MinimumOwnerAge           int                       `json:"minimumOwnerAge,omitempty"`
  ParentEmailRequired       bool                      `json:"parentEmailRequired,omitempty"`
  ParentRegistrationEmailTemplateId string                    `json:"parentRegistrationEmailTemplateId,omitempty"`
}

/**
 * API request for sending out family requests to parent's.
 *
 * @author Brian Pontarelli
 */
type FamilyEmailRequest struct {
  ParentEmail               string                    `json:"parentEmail,omitempty"`
}

/**
 * Models a single family member.
 *
 * @author Brian Pontarelli
 */
type FamilyMember struct {
  Data                      map[string]interface{}    `json:"data,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  Owner                     bool                      `json:"owner,omitempty"`
  Role                      FamilyRole                `json:"role,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * API request for managing families and members.
 *
 * @author Brian Pontarelli
 */
type FamilyRequest struct {
  FamilyMember              FamilyMember              `json:"familyMember,omitempty"`
}

/**
 * API response for managing families and members.
 *
 * @author Brian Pontarelli
 */
type FamilyResponse struct {
  BaseHTTPResponse
  Families                  []Family                  `json:"families,omitempty"`
  Family                    Family                    `json:"family,omitempty"`
}
func (b *FamilyResponse) SetStatus(status int) {
  b.StatusCode = status
}

type FamilyRole string
const (
  FamilyRole_Child                FamilyRole           = "Child"
  FamilyRole_Teen                 FamilyRole           = "Teen"
  FamilyRole_Adult                FamilyRole           = "Adult"
)

/**
 * Forgot password request object.
 *
 * @author Brian Pontarelli
 */
type ForgotPasswordRequest struct {
  ChangePasswordId          string                    `json:"changePasswordId,omitempty"`
  Email                     string                    `json:"email,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
  SendForgotPasswordEmail   bool                      `json:"sendForgotPasswordEmail,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
  Username                  string                    `json:"username,omitempty"`
}

/**
 * Forgot password response object.
 *
 * @author Daniel DeGroff
 */
type ForgotPasswordResponse struct {
  BaseHTTPResponse
  ChangePasswordId          string                    `json:"changePasswordId,omitempty"`
}
func (b *ForgotPasswordResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type GoogleApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  ButtonText                string                    `json:"buttonText,omitempty"`
  ClientId                  string                    `json:"client_id,omitempty"`
  ClientSecret              string                    `json:"client_secret,omitempty"`
  Scope                     string                    `json:"scope,omitempty"`
}

/**
 * Google social login provider.
 *
 * @author Daniel DeGroff
 */
type GoogleIdentityProvider struct {
  BaseIdentityProvider
  ButtonText                string                    `json:"buttonText,omitempty"`
  ClientId                  string                    `json:"client_id,omitempty"`
  ClientSecret              string                    `json:"client_secret,omitempty"`
  Scope                     string                    `json:"scope,omitempty"`
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
const (
  GrantType_AuthorizationCode    GrantType            = "authorization_code"
  GrantType_Implicit             GrantType            = "implicit"
  GrantType_Password             GrantType            = "password"
  GrantType_ClientCredentials    GrantType            = "client_credentials"
  GrantType_RefreshToken         GrantType            = "refresh_token"
  GrantType_Unknown              GrantType            = "unknown"
  GrantType_DeviceCode           GrantType            = "device_code"
)

/**
 * @author Tyler Scott
 */
type Group struct {
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Roles                     map[string][]ApplicationRole `json:"roles,omitempty"`
  TenantId                  string                    `json:"tenantId,omitempty"`
}

/**
 * A User's membership into a Group
 *
 * @author Daniel DeGroff
 */
type GroupMember struct {
  Data                      map[string]interface{}    `json:"data,omitempty"`
  GroupId                   string                    `json:"groupId,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * Group API request object.
 *
 * @author Daniel DeGroff
 */
type GroupRequest struct {
  Group                     Group                     `json:"group,omitempty"`
  RoleIds                   []string                  `json:"roleIds,omitempty"`
}

/**
 * Group API response object.
 *
 * @author Daniel DeGroff
 */
type GroupResponse struct {
  BaseHTTPResponse
  Group                     Group                     `json:"group,omitempty"`
  Groups                    []Group                   `json:"groups,omitempty"`
}
func (b *GroupResponse) SetStatus(status int) {
  b.StatusCode = status
}

type HistoryItem struct {
  ActionerUserId            string                    `json:"actionerUserId,omitempty"`
  Comment                   string                    `json:"comment,omitempty"`
  CreateInstant             int64                     `json:"createInstant,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type HTTPMethod string
const (
  HTTPMethod_GET                  HTTPMethod           = "GET"
  HTTPMethod_POST                 HTTPMethod           = "POST"
  HTTPMethod_PUT                  HTTPMethod           = "PUT"
  HTTPMethod_DELETE               HTTPMethod           = "DELETE"
  HTTPMethod_HEAD                 HTTPMethod           = "HEAD"
  HTTPMethod_OPTIONS              HTTPMethod           = "OPTIONS"
  HTTPMethod_PATCH                HTTPMethod           = "PATCH"
)

/**
 * @author Daniel DeGroff
 */
type HYPRApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  LicensingEnabled          bool                      `json:"licensingEnabled,omitempty"`
  LicensingEnabledOverride  bool                      `json:"licensingEnabledOverride,omitempty"`
  LicensingURL              string                    `json:"licensingURL,omitempty"`
  RelyingPartyApplicationId string                    `json:"relyingPartyApplicationId,omitempty"`
  RelyingPartyURL           string                    `json:"relyingPartyURL,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type HYPRIdentityProvider struct {
  BaseIdentityProvider
  LicensingEnabled          bool                      `json:"licensingEnabled,omitempty"`
  LicensingURL              string                    `json:"licensingURL,omitempty"`
  RelyingPartyApplicationId string                    `json:"relyingPartyApplicationId,omitempty"`
  RelyingPartyURL           string                    `json:"relyingPartyURL,omitempty"`
}

type IdentityProviderDetails struct {
  Id                        string                    `json:"id,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Oauth2                    IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
  Type                      IdentityProviderType      `json:"type,omitempty"`
}

/**
 * Login API request object used for login to third-party systems (i.e. Login with Facebook).
 *
 * @author Brian Pontarelli
 */
type IdentityProviderLoginRequest struct {
  BaseLoginRequest
  Data                      map[string]string         `json:"data,omitempty"`
  EncodedJWT                string                    `json:"encodedJWT,omitempty"`
  IdentityProviderId        string                    `json:"identityProviderId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderOauth2Configuration struct {
  AuthorizationEndpoint     string                    `json:"authorization_endpoint,omitempty"`
  ClientId                  string                    `json:"client_id,omitempty"`
  ClientSecret              string                    `json:"client_secret,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  Scope                     string                    `json:"scope,omitempty"`
  TokenEndpoint             string                    `json:"token_endpoint,omitempty"`
  UserinfoEndpoint          string                    `json:"userinfo_endpoint,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderRequest struct {
  IdentityProvider          BaseIdentityProvider      `json:"identityProvider,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderResponse struct {
  BaseHTTPResponse
  IdentityProvider          BaseIdentityProvider      `json:"identityProvider,omitempty"`
  IdentityProviders         []BaseIdentityProvider    `json:"identityProviders,omitempty"`
}
func (b *IdentityProviderResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderStartLoginRequest struct {
  BaseLoginRequest
  IdentityProviderId        string                    `json:"identityProviderId,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IdentityProviderStartLoginResponse struct {
  BaseHTTPResponse
  Code                      string                    `json:"code,omitempty"`
}
func (b *IdentityProviderStartLoginResponse) SetStatus(status int) {
  b.StatusCode = status
}

type IdentityProviderType string
const (
  IdentityProviderType_ExternalJWT          IdentityProviderType = "ExternalJWT"
  IdentityProviderType_OpenIDConnect        IdentityProviderType = "OpenIDConnect"
  IdentityProviderType_Facebook             IdentityProviderType = "Facebook"
  IdentityProviderType_Google               IdentityProviderType = "Google"
  IdentityProviderType_Twitter              IdentityProviderType = "Twitter"
  IdentityProviderType_SAMLv2               IdentityProviderType = "SAMLv2"
  IdentityProviderType_HYPR                 IdentityProviderType = "HYPR"
)

/**
 * Import request.
 *
 * @author Brian Pontarelli
 */
type ImportRequest struct {
  EncryptionScheme          string                    `json:"encryptionScheme,omitempty"`
  Factor                    int                       `json:"factor,omitempty"`
  Users                     []User                    `json:"users,omitempty"`
  ValidateDbConstraints     bool                      `json:"validateDbConstraints,omitempty"`
}

/**
 * The Integration Request
 *
 * @author Daniel DeGroff
 */
type IntegrationRequest struct {
  Integrations              Integrations              `json:"integrations,omitempty"`
}

/**
 * The Integration Response
 *
 * @author Daniel DeGroff
 */
type IntegrationResponse struct {
  BaseHTTPResponse
  Integrations              Integrations              `json:"integrations,omitempty"`
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
  Cleanspeak                CleanSpeakConfiguration   `json:"cleanspeak,omitempty"`
  Kafka                     KafkaConfiguration        `json:"kafka,omitempty"`
  Twilio                    TwilioConfiguration       `json:"twilio,omitempty"`
}

/**
 * Counts for a period.
 *
 * @author Brian Pontarelli
 */
type IntervalCount struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Count                     int                       `json:"count,omitempty"`
  DecrementedCount          int                       `json:"decrementedCount,omitempty"`
  Period                    int                       `json:"period,omitempty"`
}

/**
 * A user over an period (for daily and monthly active user calculations).
 *
 * @author Brian Pontarelli
 */
type IntervalUser struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Period                    int                       `json:"period,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type IssueResponse struct {
  BaseHTTPResponse
  RefreshToken              string                    `json:"refreshToken,omitempty"`
  Token                     string                    `json:"token,omitempty"`
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
  Alg                       Algorithm                 `json:"alg,omitempty"`
  Crv                       string                    `json:"crv,omitempty"`
  D                         string                    `json:"d,omitempty"`
  Dp                        string                    `json:"dp,omitempty"`
  Dq                        string                    `json:"dq,omitempty"`
  E                         string                    `json:"e,omitempty"`
  Kid                       string                    `json:"kid,omitempty"`
  Kty                       KeyType                   `json:"kty,omitempty"`
  N                         string                    `json:"n,omitempty"`
  Other                     map[string]interface{}    `json:"other,omitempty"`
  P                         string                    `json:"p,omitempty"`
  Q                         string                    `json:"q,omitempty"`
  Qi                        string                    `json:"qi,omitempty"`
  Use                       string                    `json:"use,omitempty"`
  X                         string                    `json:"x,omitempty"`
  X5c                       []string                  `json:"x5c,omitempty"`
  X5t                       string                    `json:"x5t,omitempty"`
  X5t_S256                  string                    `json:"x5t#S256,omitempty"`
  Y                         string                    `json:"y,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type JWKSResponse struct {
  BaseHTTPResponse
  Keys                      []JSONWebKey              `json:"keys,omitempty"`
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
  Aud                       interface{}               `json:"aud,omitempty"`
  Exp                       int64                     `json:"exp,omitempty"`
  Iat                       int64                     `json:"iat,omitempty"`
  Iss                       string                    `json:"iss,omitempty"`
  Jti                       string                    `json:"jti,omitempty"`
  Nbf                       int64                     `json:"nbf,omitempty"`
  OtherClaims               map[string]interface{}    `json:"otherClaims,omitempty"`
  Sub                       string                    `json:"sub,omitempty"`
}

/**
 * JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
 * may be <code>enabled = false</code>.
 *
 * @author Daniel DeGroff
 */
type JWTConfiguration struct {
  Enableable
  AccessTokenKeyId          string                    `json:"accessTokenKeyId,omitempty"`
  IdTokenKeyId              string                    `json:"idTokenKeyId,omitempty"`
  RefreshTokenTimeToLiveInMinutes int                       `json:"refreshTokenTimeToLiveInMinutes,omitempty"`
  TimeToLiveInSeconds       int                       `json:"timeToLiveInSeconds,omitempty"`
}

/**
 * Models the JWT public key Refresh Token Revoke Event (and can be converted to JSON). This event might be for a single
 * token, a user or an entire application.
 *
 * @author Brian Pontarelli
 */
type JWTPublicKeyUpdateEvent struct {
  BaseEvent
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
}

/**
 * Models the Refresh Token Revoke Event (and can be converted to JSON). This event might be for a single token, a user
 * or an entire application.
 *
 * @author Brian Pontarelli
 */
type JWTRefreshTokenRevokeEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  ApplicationTimeToLiveInSeconds map[string]int            `json:"applicationTimeToLiveInSeconds,omitempty"`
  User                      User                      `json:"user,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type KafkaConfiguration struct {
  Enableable
  DefaultTopic              string                    `json:"defaultTopic,omitempty"`
  Producer                  map[string]string         `json:"producer,omitempty"`
}

/**
 * Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
 *
 * @author Brian Pontarelli
 */
type Key struct {
  Algorithm                 KeyAlgorithm              `json:"algorithm,omitempty"`
  Certificate               string                    `json:"certificate,omitempty"`
  CertificateInformation    CertificateInformation    `json:"certificateInformation,omitempty"`
  ExpirationInstant         int64                     `json:"expirationInstant,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  Kid                       string                    `json:"kid,omitempty"`
  Length                    int                       `json:"length,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Pair                      bool                      `json:"pair,omitempty"`
  PrivateKey                string                    `json:"privateKey,omitempty"`
  PublicKey                 string                    `json:"publicKey,omitempty"`
  Secret                    string                    `json:"secret,omitempty"`
  Type                      KeyType                   `json:"type,omitempty"`
}

type KeyAlgorithm string
const (
  KeyAlgorithm_ES256                KeyAlgorithm         = "ES256"
  KeyAlgorithm_ES384                KeyAlgorithm         = "ES384"
  KeyAlgorithm_ES512                KeyAlgorithm         = "ES512"
  KeyAlgorithm_HS256                KeyAlgorithm         = "HS256"
  KeyAlgorithm_HS384                KeyAlgorithm         = "HS384"
  KeyAlgorithm_HS512                KeyAlgorithm         = "HS512"
  KeyAlgorithm_RS256                KeyAlgorithm         = "RS256"
  KeyAlgorithm_RS384                KeyAlgorithm         = "RS384"
  KeyAlgorithm_RS512                KeyAlgorithm         = "RS512"
)

/**
 * Key API request object.
 *
 * @author Daniel DeGroff
 */
type KeyRequest struct {
  Key                       Key                       `json:"key,omitempty"`
}

/**
 * Key API response object.
 *
 * @author Daniel DeGroff
 */
type KeyResponse struct {
  BaseHTTPResponse
  Key                       Key                       `json:"key,omitempty"`
  Keys                      []Key                     `json:"keys,omitempty"`
}
func (b *KeyResponse) SetStatus(status int) {
  b.StatusCode = status
}

type KeyType string
const (
  KeyType_EC                   KeyType              = "EC"
  KeyType_RSA                  KeyType              = "RSA"
  KeyType_HMAC                 KeyType              = "HMAC"
)

/**
 * A JavaScript lambda function that is executed during certain events inside FusionAuth.
 *
 * @author Brian Pontarelli
 */
type Lambda struct {
  Enableable
  Body                      string                    `json:"body,omitempty"`
  Debug                     bool                      `json:"debug,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Type                      LambdaType                `json:"type,omitempty"`
}

type LambdaConfiguration struct {
  AccessTokenPopulateId     string                    `json:"accessTokenPopulateId,omitempty"`
  IdTokenPopulateId         string                    `json:"idTokenPopulateId,omitempty"`
  Samlv2PopulateId          string                    `json:"samlv2PopulateId,omitempty"`
}

type ProviderLambdaConfiguration struct {
  ReconcileId               string                    `json:"reconcileId,omitempty"`
}

/**
 * Lambda API request object.
 *
 * @author Brian Pontarelli
 */
type LambdaRequest struct {
  Lambda                    Lambda                    `json:"lambda,omitempty"`
}

/**
 * Lambda API response object.
 *
 * @author Brian Pontarelli
 */
type LambdaResponse struct {
  BaseHTTPResponse
  Lambda                    Lambda                    `json:"lambda,omitempty"`
  Lambdas                   []Lambda                  `json:"lambdas,omitempty"`
}
func (b *LambdaResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * The types of lambdas that indicate how they are invoked by FusionAuth.
 *
 * @author Brian Pontarelli
 */
type LambdaType string
const (
  LambdaType_JWTPopulate          LambdaType           = "JWTPopulate"
  LambdaType_OpenIDReconcile      LambdaType           = "OpenIDReconcile"
  LambdaType_SAMLv2Reconcile      LambdaType           = "SAMLv2Reconcile"
  LambdaType_SAMLv2Populate       LambdaType           = "SAMLv2Populate"
)

/**
 * A historical state of a user log event. Since events can be modified, this stores the historical state.
 *
 * @author Brian Pontarelli
 */
type LogHistory struct {
  HistoryItems              []HistoryItem             `json:"historyItems,omitempty"`
}

type LoginConfiguration struct {
  AllowTokenRefresh         bool                      `json:"allowTokenRefresh,omitempty"`
  GenerateRefreshTokens     bool                      `json:"generateRefreshTokens,omitempty"`
  RequireAuthentication     bool                      `json:"requireAuthentication,omitempty"`
}

type LoginIdType string
const (
  LoginIdType_Email                LoginIdType          = "email"
  LoginIdType_Username             LoginIdType          = "username"
)

/**
 * The summary of the action that is preventing login to be returned on the login response.
 *
 * @author Daniel DeGroff
 */
type LoginPreventedResponse struct {
  BaseHTTPResponse
  ActionerUserId            string                    `json:"actionerUserId,omitempty"`
  ActionId                  string                    `json:"actionId,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
  LocalizedName             string                    `json:"localizedName,omitempty"`
  LocalizedOption           string                    `json:"localizedOption,omitempty"`
  LocalizedReason           string                    `json:"localizedReason,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Option                    string                    `json:"option,omitempty"`
  Reason                    string                    `json:"reason,omitempty"`
  ReasonCode                string                    `json:"reasonCode,omitempty"`
}
func (b *LoginPreventedResponse) SetStatus(status int) {
  b.StatusCode = status
}

type LoginRecordConfiguration struct {
  Delete                    DeleteConfiguration       `json:"delete,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordExportRequest struct {
  BaseExportRequest
  Criteria                  LoginRecordSearchCriteria `json:"criteria,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordSearchCriteria struct {
  BaseSearchCriteria
  ApplicationId             string                    `json:"applicationId,omitempty"`
  End                       int64                     `json:"end,omitempty"`
  Start                     int64                     `json:"start,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type LoginRecordSearchRequest struct {
  RetrieveTotal             bool                      `json:"retrieveTotal,omitempty"`
  Search                    LoginRecordSearchCriteria `json:"search,omitempty"`
}

/**
 * A raw login record response
 *
 * @author Daniel DeGroff
 */
type LoginRecordSearchResponse struct {
  BaseHTTPResponse
  Logins                    []DisplayableRawLogin     `json:"logins,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
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
  HourlyCounts              []Count                   `json:"hourlyCounts,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
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
  LoginId                   string                    `json:"loginId,omitempty"`
  OneTimePassword           string                    `json:"oneTimePassword,omitempty"`
  Password                  string                    `json:"password,omitempty"`
  TwoFactorTrustId          string                    `json:"twoFactorTrustId,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type LoginResponse struct {
  BaseHTTPResponse
  Actions                   []LoginPreventedResponse  `json:"actions,omitempty"`
  ChangePasswordId          string                    `json:"changePasswordId,omitempty"`
  RefreshToken              string                    `json:"refreshToken,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
  Token                     string                    `json:"token,omitempty"`
  TwoFactorId               string                    `json:"twoFactorId,omitempty"`
  TwoFactorTrustId          string                    `json:"twoFactorTrustId,omitempty"`
  User                      User                      `json:"user,omitempty"`
}
func (b *LoginResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Matthew Altman
 */
type LogoutBehavior string
const (
  LogoutBehavior_RedirectOnly         LogoutBehavior       = "RedirectOnly"
  LogoutBehavior_AllApplications      LogoutBehavior       = "AllApplications"
)

/**
 * @author Daniel DeGroff
 */
type LookupResponse struct {
  BaseHTTPResponse
  IdentityProvider          IdentityProviderDetails   `json:"identityProvider,omitempty"`
}
func (b *LookupResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type MaximumPasswordAge struct {
  Enableable
  Days                      int                       `json:"days,omitempty"`
}

/**
 * Group Member Delete Request
 *
 * @author Daniel DeGroff
 */
type MemberDeleteRequest struct {
  MemberIds                 []string                  `json:"memberIds,omitempty"`
  Members                   map[string][]string       `json:"members,omitempty"`
}

/**
 * Group Member Request
 *
 * @author Daniel DeGroff
 */
type MemberRequest struct {
  Members                   map[string][]GroupMember  `json:"members,omitempty"`
}

/**
 * Group Member Response
 *
 * @author Daniel DeGroff
 */
type MemberResponse struct {
  BaseHTTPResponse
  Members                   map[string][]GroupMember  `json:"members,omitempty"`
}
func (b *MemberResponse) SetStatus(status int) {
  b.StatusCode = status
}

type MetaData struct {
  Device                    DeviceInfo                `json:"device,omitempty"`
  Scopes                    []string                  `json:"scopes,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type MinimumPasswordAge struct {
  Enableable
  Seconds                   int                       `json:"seconds,omitempty"`
}

/**
 * Response for the daily active user report.
 *
 * @author Brian Pontarelli
 */
type MonthlyActiveUserReportResponse struct {
  BaseHTTPResponse
  MonthlyActiveUsers        []Count                   `json:"monthlyActiveUsers,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
}
func (b *MonthlyActiveUserReportResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Helper methods for normalizing values.
 *
 * @author Brian Pontarelli
 */
type Normalizer struct {
}

/**
 * @author Daniel DeGroff
 */
type OAuth2Configuration struct {
  AuthorizedOriginURLs      []string                  `json:"authorizedOriginURLs,omitempty"`
  AuthorizedRedirectURLs    []string                  `json:"authorizedRedirectURLs,omitempty"`
  ClientId                  string                    `json:"clientId,omitempty"`
  ClientSecret              string                    `json:"clientSecret,omitempty"`
  DeviceVerificationURL     string                    `json:"deviceVerificationURL,omitempty"`
  EnabledGrants             []GrantType               `json:"enabledGrants,omitempty"`
  GenerateRefreshTokens     bool                      `json:"generateRefreshTokens,omitempty"`
  LogoutBehavior            LogoutBehavior            `json:"logoutBehavior,omitempty"`
  LogoutURL                 string                    `json:"logoutURL,omitempty"`
  RequireClientAuthentication bool                      `json:"requireClientAuthentication,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type OAuthConfigurationResponse struct {
  BaseHTTPResponse
  HttpSessionMaxInactiveInterval int                       `json:"httpSessionMaxInactiveInterval,omitempty"`
  LogoutURL                 string                    `json:"logoutURL,omitempty"`
  OauthConfiguration        OAuth2Configuration       `json:"oauthConfiguration,omitempty"`
}
func (b *OAuthConfigurationResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type OAuthError struct {
  ChangePasswordId          string                    `json:"change_password_id,omitempty"`
  Error                     OAuthErrorType            `json:"error,omitempty"`
  ErrorDescription          string                    `json:"error_description,omitempty"`
  ErrorReason               OAuthErrorReason          `json:"error_reason,omitempty"`
  ErrorUri                  string                    `json:"error_uri,omitempty"`
  TwoFactorId               string                    `json:"two_factor_id,omitempty"`
}

type OAuthErrorReason string
const (
  OAuthErrorReason_AuthCodeNotFound     OAuthErrorReason     = "auth_code_not_found"
  OAuthErrorReason_AccessTokenMalformed OAuthErrorReason     = "access_token_malformed"
  OAuthErrorReason_AccessTokenExpired   OAuthErrorReason     = "access_token_expired"
  OAuthErrorReason_AccessTokenUnavailableForProcessing OAuthErrorReason     = "access_token_unavailable_for_processing"
  OAuthErrorReason_AccessTokenFailedProcessing OAuthErrorReason     = "access_token_failed_processing"
  OAuthErrorReason_RefreshTokenNotFound OAuthErrorReason     = "refresh_token_not_found"
  OAuthErrorReason_InvalidClientId      OAuthErrorReason     = "invalid_client_id"
  OAuthErrorReason_InvalidUserCredentials OAuthErrorReason     = "invalid_user_credentials"
  OAuthErrorReason_InvalidGrantType     OAuthErrorReason     = "invalid_grant_type"
  OAuthErrorReason_InvalidOrigin        OAuthErrorReason     = "invalid_origin"
  OAuthErrorReason_InvalidOriginOpaque  OAuthErrorReason     = "invalid_origin_opaque"
  OAuthErrorReason_InvalidPkceCodeVerifier OAuthErrorReason     = "invalid_pkce_code_verifier"
  OAuthErrorReason_InvalidPkceCodeChallenge OAuthErrorReason     = "invalid_pkce_code_challenge"
  OAuthErrorReason_InvalidPkceCodeChallengeMethod OAuthErrorReason     = "invalid_pkce_code_challenge_method"
  OAuthErrorReason_InvalidRedirectUri   OAuthErrorReason     = "invalid_redirect_uri"
  OAuthErrorReason_InvalidResponseMode  OAuthErrorReason     = "invalid_response_mode"
  OAuthErrorReason_InvalidResponseType  OAuthErrorReason     = "invalid_response_type"
  OAuthErrorReason_InvalidIdTokenHint   OAuthErrorReason     = "invalid_id_token_hint"
  OAuthErrorReason_InvalidPostLogoutRedirectUri OAuthErrorReason     = "invalid_post_logout_redirect_uri"
  OAuthErrorReason_InvalidDeviceCode    OAuthErrorReason     = "invalid_device_code"
  OAuthErrorReason_InvalidUserCode      OAuthErrorReason     = "invalid_user_code"
  OAuthErrorReason_InvalidAdditionalClientId OAuthErrorReason     = "invalid_additional_client_id"
  OAuthErrorReason_GrantTypeDisabled    OAuthErrorReason     = "grant_type_disabled"
  OAuthErrorReason_MissingClientId      OAuthErrorReason     = "missing_client_id"
  OAuthErrorReason_MissingCode          OAuthErrorReason     = "missing_code"
  OAuthErrorReason_MissingDeviceCode    OAuthErrorReason     = "missing_device_code"
  OAuthErrorReason_MissingGrantType     OAuthErrorReason     = "missing_grant_type"
  OAuthErrorReason_MissingRedirectUri   OAuthErrorReason     = "missing_redirect_uri"
  OAuthErrorReason_MissingRefreshToken  OAuthErrorReason     = "missing_refresh_token"
  OAuthErrorReason_MissingResponseType  OAuthErrorReason     = "missing_response_type"
  OAuthErrorReason_MissingToken         OAuthErrorReason     = "missing_token"
  OAuthErrorReason_MissingUserCode      OAuthErrorReason     = "missing_user_code"
  OAuthErrorReason_MissingVerificationUri OAuthErrorReason     = "missing_verification_uri"
  OAuthErrorReason_LoginPrevented       OAuthErrorReason     = "login_prevented"
  OAuthErrorReason_UserCodeExpired      OAuthErrorReason     = "user_code_expired"
  OAuthErrorReason_UserExpired          OAuthErrorReason     = "user_expired"
  OAuthErrorReason_UserLocked           OAuthErrorReason     = "user_locked"
  OAuthErrorReason_UserNotFound         OAuthErrorReason     = "user_not_found"
  OAuthErrorReason_ClientAuthenticationMissing OAuthErrorReason     = "client_authentication_missing"
  OAuthErrorReason_InvalidClientAuthenticationScheme OAuthErrorReason     = "invalid_client_authentication_scheme"
  OAuthErrorReason_InvalidClientAuthentication OAuthErrorReason     = "invalid_client_authentication"
  OAuthErrorReason_ClientIdMismatch     OAuthErrorReason     = "client_id_mismatch"
  OAuthErrorReason_Unknown              OAuthErrorReason     = "unknown"
)

type OAuthErrorType string
const (
  OAuthErrorType_InvalidRequest       OAuthErrorType       = "invalid_request"
  OAuthErrorType_InvalidClient        OAuthErrorType       = "invalid_client"
  OAuthErrorType_InvalidGrant         OAuthErrorType       = "invalid_grant"
  OAuthErrorType_InvalidToken         OAuthErrorType       = "invalid_token"
  OAuthErrorType_UnauthorizedClient   OAuthErrorType       = "unauthorized_client"
  OAuthErrorType_InvalidScope         OAuthErrorType       = "invalid_scope"
  OAuthErrorType_ServerError          OAuthErrorType       = "server_error"
  OAuthErrorType_UnsupportedGrantType OAuthErrorType       = "unsupported_grant_type"
  OAuthErrorType_UnsupportedResponseType OAuthErrorType       = "unsupported_response_type"
  OAuthErrorType_ChangePasswordRequired OAuthErrorType       = "change_password_required"
  OAuthErrorType_TwoFactorRequired    OAuthErrorType       = "two_factor_required"
  OAuthErrorType_AuthorizationPending OAuthErrorType       = "authorization_pending"
  OAuthErrorType_ExpiredToken         OAuthErrorType       = "expired_token"
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
 * OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
 * Provider Metadata</a>.
 *
 * @author Daniel DeGroff
 */
type OpenIdConfiguration struct {
  BaseHTTPResponse
  AuthorizationEndpoint     string                    `json:"authorization_endpoint,omitempty"`
  BackchannelLogoutSupported bool                      `json:"backchannel_logout_supported,omitempty"`
  ClaimsSupported           []string                  `json:"claims_supported,omitempty"`
  DeviceAuthorizationEndpoint string                    `json:"device_authorization_endpoint,omitempty"`
  EndSessionEndpoint        string                    `json:"end_session_endpoint,omitempty"`
  FrontchannelLogoutSupported bool                      `json:"frontchannel_logout_supported,omitempty"`
  GrantTypesSupported       []string                  `json:"grant_types_supported,omitempty"`
  IdTokenSigningAlgValuesSupported []string                  `json:"id_token_signing_alg_values_supported,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  JwksUri                   string                    `json:"jwks_uri,omitempty"`
  ResponseModesSupported    []string                  `json:"response_modes_supported,omitempty"`
  ResponseTypesSupported    []string                  `json:"response_types_supported,omitempty"`
  ScopesSupported           []string                  `json:"scopes_supported,omitempty"`
  SubjectTypesSupported     []string                  `json:"subject_types_supported,omitempty"`
  TokenEndpoint             string                    `json:"token_endpoint,omitempty"`
  TokenEndpointAuthMethodsSupported []string                  `json:"token_endpoint_auth_methods_supported,omitempty"`
  UserinfoEndpoint          string                    `json:"userinfo_endpoint,omitempty"`
  UserinfoSigningAlgValuesSupported []string                  `json:"userinfo_signing_alg_values_supported,omitempty"`
}
func (b *OpenIdConfiguration) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type OpenIdConnectApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  ButtonImageURL            string                    `json:"buttonImageURL,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
  Oauth2                    IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type OpenIdConnectIdentityProvider struct {
  BaseIdentityProvider
  ButtonImageURL            string                    `json:"buttonImageURL,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
  Domains                   []string                  `json:"domains,omitempty"`
  LambdaConfiguration       ProviderLambdaConfiguration `json:"lambdaConfiguration,omitempty"`
  Oauth2                    IdentityProviderOauth2Configuration `json:"oauth2,omitempty"`
}

/**
 * Password Encryption Scheme Configuration
 *
 * @author Daniel DeGroff
 */
type PasswordEncryptionConfiguration struct {
  EncryptionScheme          string                    `json:"encryptionScheme,omitempty"`
  EncryptionSchemeFactor    int                       `json:"encryptionSchemeFactor,omitempty"`
  ModifyEncryptionSchemeOnLogin bool                      `json:"modifyEncryptionSchemeOnLogin,omitempty"`
}

type PasswordlessConfiguration struct {
  Enableable
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
  Code                      string                    `json:"code,omitempty"`
  TwoFactorTrustId          string                    `json:"twoFactorTrustId,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessSendRequest struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Code                      string                    `json:"code,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessStartRequest struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  LoginId                   string                    `json:"loginId,omitempty"`
  State                     map[string]interface{}    `json:"state,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordlessStartResponse struct {
  BaseHTTPResponse
  Code                      string                    `json:"code,omitempty"`
}
func (b *PasswordlessStartResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Derek Klatt
 */
type PasswordValidationRules struct {
  MaxLength                 int                       `json:"maxLength,omitempty"`
  MinLength                 int                       `json:"minLength,omitempty"`
  RememberPreviousPasswords RememberPreviousPasswords `json:"rememberPreviousPasswords,omitempty"`
  RequireMixedCase          bool                      `json:"requireMixedCase,omitempty"`
  RequireNonAlpha           bool                      `json:"requireNonAlpha,omitempty"`
  RequireNumber             bool                      `json:"requireNumber,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type PasswordValidationRulesResponse struct {
  BaseHTTPResponse
  PasswordValidationRules   PasswordValidationRules   `json:"passwordValidationRules,omitempty"`
}
func (b *PasswordValidationRulesResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type PendingResponse struct {
  BaseHTTPResponse
  Users                     []User                    `json:"users,omitempty"`
}
func (b *PendingResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Brian Pontarelli
 */
type PreviewRequest struct {
  EmailTemplate             EmailTemplate             `json:"emailTemplate,omitempty"`
  Locale                    string                    `json:"locale,omitempty"`
}

/**
 * @author Seth Musselman
 */
type PreviewResponse struct {
  BaseHTTPResponse
  Email                     Email                     `json:"email,omitempty"`
  Errors                    Errors                    `json:"errors,omitempty"`
}
func (b *PreviewResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * JWT Public Key Response Object
 *
 * @author Daniel DeGroff
 */
type PublicKeyResponse struct {
  BaseHTTPResponse
  PublicKey                 string                    `json:"publicKey,omitempty"`
  PublicKeys                map[string]string         `json:"publicKeys,omitempty"`
}
func (b *PublicKeyResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Raw login information for each time a user logs into an application.
 *
 * @author Brian Pontarelli
 */
type RawLogin struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Instant                   int64                     `json:"instant,omitempty"`
  IpAddress                 string                    `json:"ipAddress,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * Response for the user login report.
 *
 * @author Seth Musselman
 */
type RecentLoginResponse struct {
  BaseHTTPResponse
  Logins                    []DisplayableRawLogin     `json:"logins,omitempty"`
}
func (b *RecentLoginResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type RefreshRequest struct {
  RefreshToken              string                    `json:"refreshToken,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RefreshResponse struct {
  BaseHTTPResponse
  RefreshTokens             []RefreshToken            `json:"refreshTokens,omitempty"`
  Token                     string                    `json:"token,omitempty"`
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
  ApplicationId             string                    `json:"applicationId,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  MetaData                  MetaData                  `json:"metaData,omitempty"`
  StartInstant              int64                     `json:"startInstant,omitempty"`
  Token                     string                    `json:"token,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

type RegistrationConfiguration struct {
  Enableable
  BirthDate                 Requirable                `json:"birthDate,omitempty"`
  ConfirmPassword           bool                      `json:"confirmPassword,omitempty"`
  FirstName                 Requirable                `json:"firstName,omitempty"`
  FullName                  Requirable                `json:"fullName,omitempty"`
  LastName                  Requirable                `json:"lastName,omitempty"`
  LoginIdType               LoginIdType               `json:"loginIdType,omitempty"`
  MiddleName                Requirable                `json:"middleName,omitempty"`
  MobilePhone               Requirable                `json:"mobilePhone,omitempty"`
}

/**
 * Response for the registration report.
 *
 * @author Brian Pontarelli
 */
type RegistrationReportResponse struct {
  BaseHTTPResponse
  HourlyCounts              []Count                   `json:"hourlyCounts,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
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
  GenerateAuthenticationToken bool                      `json:"generateAuthenticationToken,omitempty"`
  Registration              UserRegistration          `json:"registration,omitempty"`
  SendSetPasswordEmail      bool                      `json:"sendSetPasswordEmail,omitempty"`
  SkipRegistrationVerification bool                      `json:"skipRegistrationVerification,omitempty"`
  SkipVerification          bool                      `json:"skipVerification,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * Registration API request object.
 *
 * @author Brian Pontarelli
 */
type RegistrationResponse struct {
  BaseHTTPResponse
  Registration              UserRegistration          `json:"registration,omitempty"`
  User                      User                      `json:"user,omitempty"`
}
func (b *RegistrationResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type ReloadRequest struct {
  Names                     []string                  `json:"names,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type RememberPreviousPasswords struct {
  Enableable
  Count                     int                       `json:"count,omitempty"`
}

/**
 * Something that can be required and thus also optional. This currently extends Enableable because anything that is
 * require/optional is almost always enableable as well.
 *
 * @author Brian Pontarelli
 */
type Requirable struct {
  Enableable
  Required                  bool                      `json:"required,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type SAMLv2ApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  ButtonImageURL            string                    `json:"buttonImageURL,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
}

type SAMLv2Configuration struct {
  Enableable
  Audience                  string                    `json:"audience,omitempty"`
  CallbackURL               string                    `json:"callbackURL,omitempty"`
  Debug                     bool                      `json:"debug,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  KeyId                     string                    `json:"keyId,omitempty"`
  LogoutURL                 string                    `json:"logoutURL,omitempty"`
  XmlSignatureC14nMethod    CanonicalizationMethod    `json:"xmlSignatureC14nMethod,omitempty"`
}

/**
 * SAML v2 identity provider configuration.
 *
 * @author Brian Pontarelli
 */
type SAMLv2IdentityProvider struct {
  BaseIdentityProvider
  ButtonImageURL            string                    `json:"buttonImageURL,omitempty"`
  ButtonText                string                    `json:"buttonText,omitempty"`
  Domains                   []string                  `json:"domains,omitempty"`
  EmailClaim                string                    `json:"emailClaim,omitempty"`
  IdpEndpoint               string                    `json:"idpEndpoint,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  KeyId                     string                    `json:"keyId,omitempty"`
  LambdaConfiguration       ProviderLambdaConfiguration `json:"lambdaConfiguration,omitempty"`
  UseNameIdForEmail         bool                      `json:"useNameIdForEmail,omitempty"`
}

/**
 * Search API request.
 *
 * @author Brian Pontarelli
 */
type SearchRequest struct {
  Search                    UserSearchCriteria        `json:"search,omitempty"`
}

/**
 * Search API response.
 *
 * @author Brian Pontarelli
 */
type SearchResponse struct {
  BaseHTTPResponse
  Total                     int64                     `json:"total,omitempty"`
  Users                     []User                    `json:"users,omitempty"`
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
  Results                   []interface{}             `json:"results,omitempty"`
  Total                     int64                     `json:"total,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SecretResponse struct {
  BaseHTTPResponse
  Secret                    string                    `json:"secret,omitempty"`
  SecretBase32Encoded       string                    `json:"secretBase32Encoded,omitempty"`
}
func (b *SecretResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type SecureGeneratorConfiguration struct {
  Length                    int                       `json:"length,omitempty"`
  Type                      SecureGeneratorType       `json:"type,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SecureGeneratorType string
const (
  SecureGeneratorType_RandomDigits         SecureGeneratorType  = "randomDigits"
  SecureGeneratorType_RandomBytes          SecureGeneratorType  = "randomBytes"
  SecureGeneratorType_RandomAlpha          SecureGeneratorType  = "randomAlpha"
  SecureGeneratorType_RandomAlphaNumeric   SecureGeneratorType  = "randomAlphaNumeric"
)

/**
 * @author Daniel DeGroff
 */
type SecureIdentity struct {
  EncryptionScheme          string                    `json:"encryptionScheme,omitempty"`
  Factor                    int                       `json:"factor,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  Password                  string                    `json:"password,omitempty"`
  PasswordChangeRequired    bool                      `json:"passwordChangeRequired,omitempty"`
  PasswordLastUpdateInstant int64                     `json:"passwordLastUpdateInstant,omitempty"`
  Salt                      string                    `json:"salt,omitempty"`
  Verified                  bool                      `json:"verified,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SendRequest struct {
  BccAddresses              []string                  `json:"bccAddresses,omitempty"`
  CcAddresses               []string                  `json:"ccAddresses,omitempty"`
  RequestData               map[string]interface{}    `json:"requestData,omitempty"`
  UserIds                   []string                  `json:"userIds,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type SendResponse struct {
  BaseHTTPResponse
  Results                   map[string]EmailTemplateErrors `json:"results,omitempty"`
}
func (b *SendResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type Sort string
const (
  Sort_Asc                  Sort                 = "asc"
  Sort_Desc                 Sort                 = "desc"
)

/**
 * @author Daniel DeGroff
 */
type SortField struct {
  Missing                   string                    `json:"missing,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Order                     Sort                      `json:"order,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type SystemConfiguration struct {
  AuditLogConfiguration     AuditLogConfiguration     `json:"auditLogConfiguration,omitempty"`
  CookieEncryptionIV        string                    `json:"cookieEncryptionIV,omitempty"`
  CookieEncryptionKey       string                    `json:"cookieEncryptionKey,omitempty"`
  CorsConfiguration         CORSConfiguration         `json:"corsConfiguration,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  EventLogConfiguration     EventLogConfiguration     `json:"eventLogConfiguration,omitempty"`
  LoginRecordConfiguration  LoginRecordConfiguration  `json:"loginRecordConfiguration,omitempty"`
  ReportTimezone            string                    `json:"reportTimezone,omitempty"`
  UiConfiguration           UIConfiguration           `json:"uiConfiguration,omitempty"`
}

/**
 * Request for the system configuration API.
 *
 * @author Brian Pontarelli
 */
type SystemConfigurationRequest struct {
  SystemConfiguration       SystemConfiguration       `json:"systemConfiguration,omitempty"`
}

/**
 * Response for the system configuration API.
 *
 * @author Brian Pontarelli
 */
type SystemConfigurationResponse struct {
  BaseHTTPResponse
  SystemConfiguration       SystemConfiguration       `json:"systemConfiguration,omitempty"`
}
func (b *SystemConfigurationResponse) SetStatus(status int) {
  b.StatusCode = status
}

type Templates struct {
  EmailComplete             string                    `json:"emailComplete,omitempty"`
  EmailSend                 string                    `json:"emailSend,omitempty"`
  EmailVerify               string                    `json:"emailVerify,omitempty"`
  Helpers                   string                    `json:"helpers,omitempty"`
  Oauth2Authorize           string                    `json:"oauth2Authorize,omitempty"`
  Oauth2ChildRegistrationNotAllowed string                    `json:"oauth2ChildRegistrationNotAllowed,omitempty"`
  Oauth2ChildRegistrationNotAllowedComplete string                    `json:"oauth2ChildRegistrationNotAllowedComplete,omitempty"`
  Oauth2CompleteRegistration string                    `json:"oauth2CompleteRegistration,omitempty"`
  Oauth2Device              string                    `json:"oauth2Device,omitempty"`
  Oauth2DeviceComplete      string                    `json:"oauth2DeviceComplete,omitempty"`
  Oauth2Error               string                    `json:"oauth2Error,omitempty"`
  Oauth2Logout              string                    `json:"oauth2Logout,omitempty"`
  Oauth2Passwordless        string                    `json:"oauth2Passwordless,omitempty"`
  Oauth2Register            string                    `json:"oauth2Register,omitempty"`
  Oauth2TwoFactor           string                    `json:"oauth2TwoFactor,omitempty"`
  Oauth2Wait                string                    `json:"oauth2Wait,omitempty"`
  PasswordChange            string                    `json:"passwordChange,omitempty"`
  PasswordComplete          string                    `json:"passwordComplete,omitempty"`
  PasswordForgot            string                    `json:"passwordForgot,omitempty"`
  PasswordSent              string                    `json:"passwordSent,omitempty"`
  RegistrationComplete      string                    `json:"registrationComplete,omitempty"`
  RegistrationSend          string                    `json:"registrationSend,omitempty"`
  RegistrationVerify        string                    `json:"registrationVerify,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type Tenant struct {
  Configured                bool                      `json:"configured,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  EmailConfiguration        EmailConfiguration        `json:"emailConfiguration,omitempty"`
  EventConfiguration        EventConfiguration        `json:"eventConfiguration,omitempty"`
  ExternalIdentifierConfiguration ExternalIdentifierConfiguration `json:"externalIdentifierConfiguration,omitempty"`
  FailedAuthenticationConfiguration FailedAuthenticationConfiguration `json:"failedAuthenticationConfiguration,omitempty"`
  FamilyConfiguration       FamilyConfiguration       `json:"familyConfiguration,omitempty"`
  HttpSessionMaxInactiveInterval int                       `json:"httpSessionMaxInactiveInterval,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  Issuer                    string                    `json:"issuer,omitempty"`
  JwtConfiguration          JWTConfiguration          `json:"jwtConfiguration,omitempty"`
  LogoutURL                 string                    `json:"logoutURL,omitempty"`
  MaximumPasswordAge        MaximumPasswordAge        `json:"maximumPasswordAge,omitempty"`
  MinimumPasswordAge        MinimumPasswordAge        `json:"minimumPasswordAge,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  PasswordEncryptionConfiguration PasswordEncryptionConfiguration `json:"passwordEncryptionConfiguration,omitempty"`
  PasswordValidationRules   PasswordValidationRules   `json:"passwordValidationRules,omitempty"`
  ThemeId                   string                    `json:"themeId,omitempty"`
  UserDeletePolicy          TenantUserDeletePolicy    `json:"userDeletePolicy,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type Tenantable struct {
}

/**
 * @author Daniel DeGroff
 */
type TenantRequest struct {
  SourceTenantId            string                    `json:"sourceTenantId,omitempty"`
  Tenant                    Tenant                    `json:"tenant,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TenantResponse struct {
  BaseHTTPResponse
  Tenant                    Tenant                    `json:"tenant,omitempty"`
  Tenants                   []Tenant                  `json:"tenants,omitempty"`
}
func (b *TenantResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * A Tenant-level policy for deleting Users.
 *
 * @author Trevor Smith
 */
type TenantUserDeletePolicy struct {
  Unverified                TimeBasedDeletePolicy     `json:"unverified,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TestEvent struct {
  BaseEvent
  Message                   string                    `json:"message,omitempty"`
}

/**
 * @author Trevor Smith
 */
type Theme struct {
  Data                      map[string]interface{}    `json:"data,omitempty"`
  DefaultMessages           string                    `json:"defaultMessages,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  LastUpdateInstant         int64                     `json:"lastUpdateInstant,omitempty"`
  LocalizedMessages         map[string]string         `json:"localizedMessages,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Stylesheet                string                    `json:"stylesheet,omitempty"`
  Templates                 Templates                 `json:"templates,omitempty"`
}

/**
 * Theme API request object.
 *
 * @author Trevor Smith
 */
type ThemeRequest struct {
  SourceThemeId             string                    `json:"sourceThemeId,omitempty"`
  Theme                     Theme                     `json:"theme,omitempty"`
}

/**
 * Theme API response object.
 *
 * @author Trevor Smith
 */
type ThemeResponse struct {
  BaseHTTPResponse
  Theme                     Theme                     `json:"theme,omitempty"`
  Themes                    []Theme                   `json:"themes,omitempty"`
}
func (b *ThemeResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * A policy for deleting Users.
 *
 * @author Trevor Smith
 */
type TimeBasedDeletePolicy struct {
  Enableable
  NumberOfDaysToRetain      int                       `json:"numberOfDaysToRetain,omitempty"`
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
const (
  TokenType_Bearer               TokenType            = "Bearer"
  TokenType_MAC                  TokenType            = "MAC"
)

type Totals struct {
  Logins                    int64                     `json:"logins,omitempty"`
  Registrations             int64                     `json:"registrations,omitempty"`
  TotalRegistrations        int64                     `json:"totalRegistrations,omitempty"`
}

/**
 * The response from the total report. This report stores the total numbers for each application.
 *
 * @author Brian Pontarelli
 */
type TotalsReportResponse struct {
  BaseHTTPResponse
  ApplicationTotals         map[string]Totals         `json:"applicationTotals,omitempty"`
  GlobalRegistrations       int64                     `json:"globalRegistrations,omitempty"`
  TotalGlobalRegistrations  int64                     `json:"totalGlobalRegistrations,omitempty"`
}
func (b *TotalsReportResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * The transaction types for Webhooks and other event systems within FusionAuth.
 *
 * @author Brian Pontarelli
 */
type TransactionType string
const (
  TransactionType_None                 TransactionType      = "None"
  TransactionType_Any                  TransactionType      = "Any"
  TransactionType_SimpleMajority       TransactionType      = "SimpleMajority"
  TransactionType_SuperMajority        TransactionType      = "SuperMajority"
  TransactionType_AbsoluteMajority     TransactionType      = "AbsoluteMajority"
)

/**
 * Twilio Service Configuration.
 *
 * @author Daniel DeGroff
 */
type TwilioConfiguration struct {
  Enableable
  AccountSID                string                    `json:"accountSID,omitempty"`
  AuthToken                 string                    `json:"authToken,omitempty"`
  FromPhoneNumber           string                    `json:"fromPhoneNumber,omitempty"`
  MessagingServiceSid       string                    `json:"messagingServiceSid,omitempty"`
  Url                       string                    `json:"url,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwitterApplicationConfiguration struct {
  BaseIdentityProviderApplicationConfiguration
  ButtonText                string                    `json:"buttonText,omitempty"`
  ConsumerKey               string                    `json:"consumerKey,omitempty"`
  ConsumerSecret            string                    `json:"consumerSecret,omitempty"`
}

/**
 * Twitter social login provider.
 *
 * @author Daniel DeGroff
 */
type TwitterIdentityProvider struct {
  BaseIdentityProvider
  ButtonText                string                    `json:"buttonText,omitempty"`
  ConsumerKey               string                    `json:"consumerKey,omitempty"`
  ConsumerSecret            string                    `json:"consumerSecret,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorDelivery string
const (
  TwoFactorDelivery_None                 TwoFactorDelivery    = "None"
  TwoFactorDelivery_TextMessage          TwoFactorDelivery    = "TextMessage"
)

/**
 * @author Daniel DeGroff
 */
type TwoFactorLoginRequest struct {
  BaseLoginRequest
  Code                      string                    `json:"code,omitempty"`
  TrustComputer             bool                      `json:"trustComputer,omitempty"`
  TwoFactorId               string                    `json:"twoFactorId,omitempty"`
}

/**
 * @author Brian Pontarelli
 */
type TwoFactorRequest struct {
  Code                      string                    `json:"code,omitempty"`
  Delivery                  TwoFactorDelivery         `json:"delivery,omitempty"`
  Secret                    string                    `json:"secret,omitempty"`
  SecretBase32Encoded       string                    `json:"secretBase32Encoded,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type TwoFactorSendRequest struct {
  MobilePhone               string                    `json:"mobilePhone,omitempty"`
  Secret                    string                    `json:"secret,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

type UIConfiguration struct {
  HeaderColor               string                    `json:"headerColor,omitempty"`
  LogoURL                   string                    `json:"logoURL,omitempty"`
  MenuFontColor             string                    `json:"menuFontColor,omitempty"`
}

/**
 * The global view of a User. This object contains all global information about the user including birth date, registration information
 * preferred languages, global attributes, etc.
 *
 * @author Seth Musselman
 */
type User struct {
  SecureIdentity
  Active                    bool                      `json:"active,omitempty"`
  BirthDate                 string                    `json:"birthDate,omitempty"`
  CleanSpeakId              string                    `json:"cleanSpeakId,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Email                     string                    `json:"email,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
  FirstName                 string                    `json:"firstName,omitempty"`
  FullName                  string                    `json:"fullName,omitempty"`
  ImageUrl                  string                    `json:"imageUrl,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  LastLoginInstant          int64                     `json:"lastLoginInstant,omitempty"`
  LastName                  string                    `json:"lastName,omitempty"`
  Memberships               []GroupMember             `json:"memberships,omitempty"`
  MiddleName                string                    `json:"middleName,omitempty"`
  MobilePhone               string                    `json:"mobilePhone,omitempty"`
  ParentEmail               string                    `json:"parentEmail,omitempty"`
  PreferredLanguages        []string                  `json:"preferredLanguages,omitempty"`
  Registrations             []UserRegistration        `json:"registrations,omitempty"`
  TenantId                  string                    `json:"tenantId,omitempty"`
  Timezone                  string                    `json:"timezone,omitempty"`
  TwoFactorDelivery         TwoFactorDelivery         `json:"twoFactorDelivery,omitempty"`
  TwoFactorEnabled          bool                      `json:"twoFactorEnabled,omitempty"`
  TwoFactorSecret           string                    `json:"twoFactorSecret,omitempty"`
  Username                  string                    `json:"username,omitempty"`
  UsernameStatus            ContentStatus             `json:"usernameStatus,omitempty"`
}

/**
 * An action that can be executed on a user (discipline or reward potentially).
 *
 * @author Brian Pontarelli
 */
type UserAction struct {
  Active                    bool                      `json:"active,omitempty"`
  CancelEmailTemplateId     string                    `json:"cancelEmailTemplateId,omitempty"`
  EndEmailTemplateId        string                    `json:"endEmailTemplateId,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  IncludeEmailInEventJSON   bool                      `json:"includeEmailInEventJSON,omitempty"`
  LocalizedNames            map[string]string         `json:"localizedNames,omitempty"`
  ModifyEmailTemplateId     string                    `json:"modifyEmailTemplateId,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  Options                   []UserActionOption        `json:"options,omitempty"`
  PreventLogin              bool                      `json:"preventLogin,omitempty"`
  SendEndEvent              bool                      `json:"sendEndEvent,omitempty"`
  StartEmailTemplateId      string                    `json:"startEmailTemplateId,omitempty"`
  Temporal                  bool                      `json:"temporal,omitempty"`
  TransactionType           TransactionType           `json:"transactionType,omitempty"`
  UserEmailingEnabled       bool                      `json:"userEmailingEnabled,omitempty"`
  UserNotificationsEnabled  bool                      `json:"userNotificationsEnabled,omitempty"`
}

/**
 * Models the user action event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserActionEvent struct {
  BaseEvent
  Action                    string                    `json:"action,omitempty"`
  ActioneeUserId            string                    `json:"actioneeUserId,omitempty"`
  ActionerUserId            string                    `json:"actionerUserId,omitempty"`
  ActionId                  string                    `json:"actionId,omitempty"`
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
  Comment                   string                    `json:"comment,omitempty"`
  Email                     Email                     `json:"email,omitempty"`
  EmailedUser               bool                      `json:"emailedUser,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
  LocalizedAction           string                    `json:"localizedAction,omitempty"`
  LocalizedDuration         string                    `json:"localizedDuration,omitempty"`
  LocalizedOption           string                    `json:"localizedOption,omitempty"`
  LocalizedReason           string                    `json:"localizedReason,omitempty"`
  NotifyUser                bool                      `json:"notifyUser,omitempty"`
  Option                    string                    `json:"option,omitempty"`
  Phase                     UserActionPhase           `json:"phase,omitempty"`
  Reason                    string                    `json:"reason,omitempty"`
  ReasonCode                string                    `json:"reasonCode,omitempty"`
}

/**
 * A log for an action that was taken on a User.
 *
 * @author Brian Pontarelli
 */
type UserActionLog struct {
  ActioneeUserId            string                    `json:"actioneeUserId,omitempty"`
  ActionerUserId            string                    `json:"actionerUserId,omitempty"`
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
  Comment                   string                    `json:"comment,omitempty"`
  CreateInstant             int64                     `json:"createInstant,omitempty"`
  EmailUserOnEnd            bool                      `json:"emailUserOnEnd,omitempty"`
  EndEventSent              bool                      `json:"endEventSent,omitempty"`
  Expiry                    int64                     `json:"expiry,omitempty"`
  History                   LogHistory                `json:"history,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  LocalizedName             string                    `json:"localizedName,omitempty"`
  LocalizedOption           string                    `json:"localizedOption,omitempty"`
  LocalizedReason           string                    `json:"localizedReason,omitempty"`
  Name                      string                    `json:"name,omitempty"`
  NotifyUserOnEnd           bool                      `json:"notifyUserOnEnd,omitempty"`
  Option                    string                    `json:"option,omitempty"`
  Reason                    string                    `json:"reason,omitempty"`
  ReasonCode                string                    `json:"reasonCode,omitempty"`
  UserActionId              string                    `json:"userActionId,omitempty"`
}

/**
 * Models content user action options.
 *
 * @author Brian Pontarelli
 */
type UserActionOption struct {
  LocalizedNames            map[string]string         `json:"localizedNames,omitempty"`
  Name                      string                    `json:"name,omitempty"`
}

/**
 * The phases of a time-based user action.
 *
 * @author Brian Pontarelli
 */
type UserActionPhase string
const (
  UserActionPhase_Start                UserActionPhase      = "start"
  UserActionPhase_Modify               UserActionPhase      = "modify"
  UserActionPhase_Cancel               UserActionPhase      = "cancel"
  UserActionPhase_End                  UserActionPhase      = "end"
)

/**
 * Models action reasons.
 *
 * @author Brian Pontarelli
 */
type UserActionReason struct {
  Code                      string                    `json:"code,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  LocalizedTexts            map[string]string         `json:"localizedTexts,omitempty"`
  Text                      string                    `json:"text,omitempty"`
}

/**
 * User Action Reason API request object.
 *
 * @author Brian Pontarelli
 */
type UserActionReasonRequest struct {
  UserActionReason          UserActionReason          `json:"userActionReason,omitempty"`
}

/**
 * User Action Reason API response object.
 *
 * @author Brian Pontarelli
 */
type UserActionReasonResponse struct {
  BaseHTTPResponse
  UserActionReason          UserActionReason          `json:"userActionReason,omitempty"`
  UserActionReasons         []UserActionReason        `json:"userActionReasons,omitempty"`
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
  UserAction                UserAction                `json:"userAction,omitempty"`
}

/**
 * User Action API response object.
 *
 * @author Brian Pontarelli
 */
type UserActionResponse struct {
  BaseHTTPResponse
  UserAction                UserAction                `json:"userAction,omitempty"`
  UserActions               []UserAction              `json:"userActions,omitempty"`
}
func (b *UserActionResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Models the User Bulk Create Event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserBulkCreateEvent struct {
  BaseEvent
  Users                     []User                    `json:"users,omitempty"`
}

/**
 * A log for an event that happened to a User.
 *
 * @author Brian Pontarelli
 */
type UserComment struct {
  Comment                   string                    `json:"comment,omitempty"`
  CommenterId               string                    `json:"commenterId,omitempty"`
  CreateInstant             int64                     `json:"createInstant,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
}

/**
 * @author Seth Musselman
 */
type UserCommentRequest struct {
  UserComment               UserComment               `json:"userComment,omitempty"`
}

/**
 * User Comment Response
 *
 * @author Seth Musselman
 */
type UserCommentResponse struct {
  BaseHTTPResponse
  UserComment               UserComment               `json:"userComment,omitempty"`
  UserComments              []UserComment             `json:"userComments,omitempty"`
}
func (b *UserCommentResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Models a User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsent struct {
  Consent                   Consent                   `json:"consent,omitempty"`
  ConsentId                 string                    `json:"consentId,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  GiverUserId               string                    `json:"giverUserId,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  LastUpdateInstant         int64                     `json:"lastUpdateInstant,omitempty"`
  Status                    ConsentStatus             `json:"status,omitempty"`
  UserId                    string                    `json:"userId,omitempty"`
  Values                    []string                  `json:"values,omitempty"`
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsentRequest struct {
  UserConsent               UserConsent               `json:"userConsent,omitempty"`
}

/**
 * API response for User consent.
 *
 * @author Daniel DeGroff
 */
type UserConsentResponse struct {
  BaseHTTPResponse
  UserConsent               UserConsent               `json:"userConsent,omitempty"`
  UserConsents              []UserConsent             `json:"userConsents,omitempty"`
}
func (b *UserConsentResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Models the User Create Event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserCreateEvent struct {
  BaseEvent
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Deactivate Event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserDeactivateEvent struct {
  BaseEvent
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
 * delete).
 *
 * @author Brian Pontarelli
 */
type UserDeleteEvent struct {
  BaseEvent
  User                      User                      `json:"user,omitempty"`
}

/**
 * User API delete request object.
 *
 * @author Daniel DeGroff
 */
type UserDeleteRequest struct {
  DryRun                    bool                      `json:"dryRun,omitempty"`
  HardDelete                bool                      `json:"hardDelete,omitempty"`
  Query                     string                    `json:"query,omitempty"`
  QueryString               string                    `json:"queryString,omitempty"`
  UserIds                   []string                  `json:"userIds,omitempty"`
}

/**
 * User API bulk response object.
 *
 * @author Trevor Smith
 */
type UserDeleteResponse struct {
  BaseHTTPResponse
  DryRun                    bool                      `json:"dryRun,omitempty"`
  HardDelete                bool                      `json:"hardDelete,omitempty"`
  Total                     int                       `json:"total,omitempty"`
  UserIds                   []string                  `json:"userIds,omitempty"`
}
func (b *UserDeleteResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * Models the User Email Verify Event (and can be converted to JSON).
 *
 * @author Trevor Smith
 */
type UserEmailVerifiedEvent struct {
  BaseEvent
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Login Failed Event.
 *
 * @author Daniel DeGroff
 */
type UserLoginFailedEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  AuthenticationType        string                    `json:"authenticationType,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Login Success Event.
 *
 * @author Daniel DeGroff
 */
type UserLoginSuccessEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  AuthenticationType        string                    `json:"authenticationType,omitempty"`
  IdentityProviderId        string                    `json:"identityProviderId,omitempty"`
  IdentityProviderName      string                    `json:"identityProviderName,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

type UsernameModeration struct {
  Enableable
  ApplicationId             string                    `json:"applicationId,omitempty"`
}

/**
 * Models the User Reactivate Event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserReactivateEvent struct {
  BaseEvent
  User                      User                      `json:"user,omitempty"`
}

/**
 * User registration information for a single application.
 *
 * @author Brian Pontarelli
 */
type UserRegistration struct {
  ApplicationId             string                    `json:"applicationId,omitempty"`
  AuthenticationToken       string                    `json:"authenticationToken,omitempty"`
  CleanSpeakId              string                    `json:"cleanSpeakId,omitempty"`
  Data                      map[string]interface{}    `json:"data,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  InsertInstant             int64                     `json:"insertInstant,omitempty"`
  LastLoginInstant          int64                     `json:"lastLoginInstant,omitempty"`
  PreferredLanguages        []string                  `json:"preferredLanguages,omitempty"`
  Roles                     []string                  `json:"roles,omitempty"`
  Timezone                  string                    `json:"timezone,omitempty"`
  Tokens                    map[string]string         `json:"tokens,omitempty"`
  Username                  string                    `json:"username,omitempty"`
  UsernameStatus            ContentStatus             `json:"usernameStatus,omitempty"`
  Verified                  bool                      `json:"verified,omitempty"`
}

/**
 * Models the User Create Registration Event (and can be converted to JSON).
 *
 * @author Daniel DeGroff
 */
type UserRegistrationCreateEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Registration              UserRegistration          `json:"registration,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Delete Registration Event (and can be converted to JSON).
 *
 * @author Daniel DeGroff
 */
type UserRegistrationDeleteEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Registration              UserRegistration          `json:"registration,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Update Registration Event (and can be converted to JSON).
 *
 * @author Daniel DeGroff
 */
type UserRegistrationUpdateEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Original                  UserRegistration          `json:"original,omitempty"`
  Registration              UserRegistration          `json:"registration,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * Models the User Registration Verified Event (and can be converted to JSON).
 *
 * @author Trevor Smith
 */
type UserRegistrationVerifiedEvent struct {
  BaseEvent
  ApplicationId             string                    `json:"applicationId,omitempty"`
  Registration              UserRegistration          `json:"registration,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * User API request object.
 *
 * @author Brian Pontarelli
 */
type UserRequest struct {
  SendSetPasswordEmail      bool                      `json:"sendSetPasswordEmail,omitempty"`
  SkipVerification          bool                      `json:"skipVerification,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * User API response object.
 *
 * @author Brian Pontarelli
 */
type UserResponse struct {
  BaseHTTPResponse
  User                      User                      `json:"user,omitempty"`
}
func (b *UserResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
 *
 * @author Brian Pontarelli
 */
type UserSearchCriteria struct {
  BaseSearchCriteria
  Ids                       []string                  `json:"ids,omitempty"`
  Query                     string                    `json:"query,omitempty"`
  QueryString               string                    `json:"queryString,omitempty"`
  SortFields                []SortField               `json:"sortFields,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type UserState string
const (
  UserState_Authenticated        UserState            = "Authenticated"
  UserState_AuthenticatedNotRegistered UserState            = "AuthenticatedNotRegistered"
)

/**
 * Models the User Update Event (and can be converted to JSON).
 *
 * @author Brian Pontarelli
 */
type UserUpdateEvent struct {
  BaseEvent
  Original                  User                      `json:"original,omitempty"`
  User                      User                      `json:"user,omitempty"`
}

/**
 * @author Daniel DeGroff
 */
type ValidateResponse struct {
  BaseHTTPResponse
  Jwt                       JWT                       `json:"jwt,omitempty"`
}
func (b *ValidateResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VerifyEmailResponse struct {
  BaseHTTPResponse
  VerificationId            string                    `json:"verificationId,omitempty"`
}
func (b *VerifyEmailResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * @author Daniel DeGroff
 */
type VerifyRegistrationResponse struct {
  BaseHTTPResponse
  VerificationId            string                    `json:"verificationId,omitempty"`
}
func (b *VerifyRegistrationResponse) SetStatus(status int) {
  b.StatusCode = status
}

/**
 * A server where events are sent. This includes user action events and any other events sent by FusionAuth.
 *
 * @author Brian Pontarelli
 */
type Webhook struct {
  ApplicationIds            []string                  `json:"applicationIds,omitempty"`
  ConnectTimeout            int                       `json:"connectTimeout,omitempty"`
  Data                      WebhookData               `json:"data,omitempty"`
  Description               string                    `json:"description,omitempty"`
  Global                    bool                      `json:"global,omitempty"`
  Headers                   map[string]string         `json:"headers,omitempty"`
  HttpAuthenticationPassword string                    `json:"httpAuthenticationPassword,omitempty"`
  HttpAuthenticationUsername string                    `json:"httpAuthenticationUsername,omitempty"`
  Id                        string                    `json:"id,omitempty"`
  ReadTimeout               int                       `json:"readTimeout,omitempty"`
  SslCertificate            string                    `json:"sslCertificate,omitempty"`
  Url                       string                    `json:"url,omitempty"`
}

type WebhookData struct {
  EventsEnabled             map[EventType]bool        `json:"eventsEnabled,omitempty"`
}

/**
 * Webhook API request object.
 *
 * @author Brian Pontarelli
 */
type WebhookRequest struct {
  Webhook                   Webhook                   `json:"webhook,omitempty"`
}

/**
 * Webhook API response object.
 *
 * @author Brian Pontarelli
 */
type WebhookResponse struct {
  BaseHTTPResponse
  Webhook                   Webhook                   `json:"webhook,omitempty"`
  Webhooks                  []Webhook                 `json:"webhooks,omitempty"`
}
func (b *WebhookResponse) SetStatus(status int) {
  b.StatusCode = status
}

