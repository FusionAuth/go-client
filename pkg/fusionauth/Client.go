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

import (
  "bytes"
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "net/http/httputil"
  "net/url"
  "path"
  "strconv"
  "strings"
)

// NewClient creates a new FusionAuthClient
// if httpClient is nil then a DefaultClient is used
func NewClient(httpClient *http.Client, baseURL *url.URL, apiKey string) *FusionAuthClient {
  if httpClient == nil {
    httpClient = http.DefaultClient
  }
  c := &FusionAuthClient{
    HTTPClient: httpClient,
    BaseURL:    baseURL,
    APIKey:     apiKey}

  return c
}

// SetTenantId sets the tenantId on the client
func (c *FusionAuthClient) SetTenantId(tenantId string)  {
  c.TenantId = tenantId
}

// FusionAuthClient describes the Go Client for interacting with FusionAuth's RESTful API
type FusionAuthClient struct {
  HTTPClient *http.Client
  BaseURL    *url.URL
  APIKey     string
  Debug      bool
  TenantId   string
}

type restClient struct {
  Body        io.Reader
  Debug       bool
  ErrorRef    interface{}
  Headers     map[string]string
  HTTPClient  *http.Client
  Method      string
  ResponseRef interface{}
  Uri         *url.URL
}

func (c *FusionAuthClient) Start(responseRef interface{}, errorRef interface{}) *restClient {
  return c.StartAnonymous(responseRef, errorRef).WithAuthorization(c.APIKey)
}

func (c *FusionAuthClient) StartAnonymous(responseRef interface{}, errorRef interface{}) *restClient {
  rc := &restClient{
    Debug:       c.Debug,
    ErrorRef:    errorRef,
    Headers:     make(map[string]string),
    HTTPClient:  c.HTTPClient,
    ResponseRef: responseRef,
  }
  rc.Uri, _ = url.Parse(c.BaseURL.String())
  if c.TenantId != "" {
    rc.WithHeader("X-FusionAuth-TenantId", c.TenantId)
  }
  rc.WithHeader("Content-Type", "text/plain")
  rc.WithHeader("Accept", "application/json")
  return rc
}

func (rc *restClient) Do() error {
  req, err := http.NewRequest(rc.Method, rc.Uri.String(), rc.Body)
  if err != nil {
    return err
  }
  for key, val := range rc.Headers {
    req.Header.Set(key, val)
  }
  resp, err := rc.HTTPClient.Do(req)
  if err != nil {
    return err
  }
  defer resp.Body.Close()
  if rc.Debug {
    responseDump, _ := httputil.DumpResponse(resp, true)
    fmt.Println(string(responseDump))
  }
  if resp.StatusCode < 200 || resp.StatusCode > 299 {
    if rc.ErrorRef != nil {
      err = json.NewDecoder(resp.Body).Decode(rc.ErrorRef)
    }
  } else {
    rc.ErrorRef = nil
    if _, ok := rc.ResponseRef.(*BaseHTTPResponse); !ok {
      err = json.NewDecoder(resp.Body).Decode(rc.ResponseRef)
    }
  }
  rc.ResponseRef.(StatusAble).SetStatus(resp.StatusCode)
  return err
}

func (rc *restClient) WithAuthorization(key string) *restClient {
  if key != "" {
    rc.WithHeader("Authorization", key)
  }
  return rc
}

func (rc *restClient) WithFormData(formBody url.Values) *restClient {
  rc.WithHeader("Content-Type", "application/x-www-form-urlencoded")
  rc.Body = strings.NewReader(formBody.Encode())
  return rc
}

func (rc *restClient) WithHeader(key string, value string) *restClient {
  rc.Headers[key] = value
  return rc
}

func (rc *restClient) WithJSONBody(body interface{}) *restClient {
  rc.WithHeader("Content-Type", "application/json")
  buf := new(bytes.Buffer)
  json.NewEncoder(buf).Encode(body)
  rc.Body = buf
  return rc
}

func (rc *restClient) WithMethod(method string) *restClient {
  rc.Method = method
  return rc
}

func (rc *restClient) WithParameter(key string, value interface{}) *restClient {
  q := rc.Uri.Query()
  if x, ok := value.([]string); ok {
    for _, i := range x {
      q.Add(key, i)
    }
  } else {
    q.Add(key, fmt.Sprintf("%v", value))
  }
  rc.Uri.RawQuery = q.Encode()
  return rc
}

func (rc *restClient) WithUri(uri string) *restClient {
  rc.Uri.Path = path.Join(rc.Uri.Path, uri)
  return rc
}

func (rc *restClient) WithUriSegment(segment string) *restClient {
  if segment != "" {
    rc.Uri.Path = path.Join(rc.Uri.Path, "/"+segment)
  }
  return rc
}

// ActionUser
// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
// "actioner". Both user ids are required. You pass the actionee's user id into the method and the actioner's is put into the
// request object.
//   string actioneeUserId The actionee's user id.
//   ActionRequest request The action request that includes all of the information about the action being taken including
//   the id of the action, any options and the duration (if applicable).
func (c *FusionAuthClient) ActionUser(actioneeUserId string, request ActionRequest) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithUriSegment(actioneeUserId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// AddUserToFamily
// Adds a user to an existing family. The family id must be specified.
//   string familyId The id of the family.
//   FamilyRequest request The request object that contains all of the information used to determine which user to add to the family.
func (c *FusionAuthClient) AddUserToFamily(familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
    var resp FamilyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/family").
             WithUriSegment(familyId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CancelAction
// Cancels the user action.
//   string actionId The action id of the action to cancel.
//   ActionRequest request The action request that contains the information about the cancellation.
func (c *FusionAuthClient) CancelAction(actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithUriSegment(actionId).
             WithJSONBody(request).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ChangePassword
// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
// and they clicked on a link to reset their password.
//   string changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
//   ChangePasswordRequest request The change password request that contains all of the information used to change the password.
func (c *FusionAuthClient) ChangePassword(changePasswordId string, request ChangePasswordRequest) (*ChangePasswordResponse, *Errors, error) {
    var resp ChangePasswordResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/change-password").
             WithUriSegment(changePasswordId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ChangePasswordByIdentity
// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
// method.
//   ChangePasswordRequest request The change password request that contains all of the information used to change the password.
func (c *FusionAuthClient) ChangePasswordByIdentity(request ChangePasswordRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/change-password").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CommentOnUser
// Adds a comment to the user's account.
//   UserCommentRequest request The request object that contains all of the information used to create the user comment.
func (c *FusionAuthClient) CommentOnUser(request UserCommentRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/comment").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateApplication
// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
//   string applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
//   ApplicationRequest request The request object that contains all of the information used to create the application.
func (c *FusionAuthClient) CreateApplication(applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateApplicationRole
// Creates a new role for an application. You must specify the id of the application you are creating the role for.
// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
//   string applicationId The Id of the application to create the role on.
//   string roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
//   ApplicationRequest request The request object that contains all of the information used to create the application role.
func (c *FusionAuthClient) CreateApplicationRole(applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithUriSegment("role").
             WithUriSegment(roleId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateAuditLog
// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
//   AuditLogRequest request The request object that contains all of the information used to create the audit log entry.
func (c *FusionAuthClient) CreateAuditLog(request AuditLogRequest) (*AuditLogResponse, *Errors, error) {
    var resp AuditLogResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/system/audit-log").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateConsent
// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
//   string consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
//   ConsentRequest request The request object that contains all of the information used to create the consent.
func (c *FusionAuthClient) CreateConsent(consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
    var resp ConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/consent").
             WithUriSegment(consentId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateEmailTemplate
// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
//   string emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
//   EmailTemplateRequest request The request object that contains all of the information used to create the email template.
func (c *FusionAuthClient) CreateEmailTemplate(emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
    var resp EmailTemplateResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/template").
             WithUriSegment(emailTemplateId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateFamily
// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
// family, if not provided one will be generated.
//   string familyId (Optional) The id for the family. If not provided a secure random UUID will be generated.
//   FamilyRequest request The request object that contains all of the information used to create the family.
func (c *FusionAuthClient) CreateFamily(familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
    var resp FamilyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/family").
             WithUriSegment(familyId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateGroup
// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
//   string groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
//   GroupRequest request The request object that contains all of the information used to create the group.
func (c *FusionAuthClient) CreateGroup(groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
    var resp GroupResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group").
             WithUriSegment(groupId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateGroupMembers
// Creates a member in a group.
//   MemberRequest request The request object that contains all of the information used to create the group member(s).
func (c *FusionAuthClient) CreateGroupMembers(request MemberRequest) (*MemberResponse, *Errors, error) {
    var resp MemberResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group/member").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateLambda
// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
//   string lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
//   LambdaRequest request The request object that contains all of the information used to create the lambda.
func (c *FusionAuthClient) CreateLambda(lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
    var resp LambdaResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/lambda").
             WithUriSegment(lambdaId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateTenant
// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
//   string tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
//   TenantRequest request The request object that contains all of the information used to create the tenant.
func (c *FusionAuthClient) CreateTenant(tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
    var resp TenantResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/tenant").
             WithUriSegment(tenantId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateTheme
// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
//   string themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
//   ThemeRequest request The request object that contains all of the information used to create the theme.
func (c *FusionAuthClient) CreateTheme(themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
    var resp ThemeResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/theme").
             WithUriSegment(themeId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateUser
// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
//   string userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
//   UserRequest request The request object that contains all of the information used to create the user.
func (c *FusionAuthClient) CreateUser(userId string, request UserRequest) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateUserAction
// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
// that the user action can be applied to any user.
//   string userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
//   UserActionRequest request The request object that contains all of the information used to create the user action.
func (c *FusionAuthClient) CreateUserAction(userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
    var resp UserActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateUserActionReason
// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
// successfully. Anytime after that the user action reason can be used.
//   string userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
//   UserActionReasonRequest request The request object that contains all of the information used to create the user action reason.
func (c *FusionAuthClient) CreateUserActionReason(userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
    var resp UserActionReasonResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action-reason").
             WithUriSegment(userActionReasonId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateUserConsent
// Creates a single User consent.
//   string userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
//   UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) CreateUserConsent(userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
    var resp UserConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/consent").
             WithUriSegment(userConsentId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// CreateWebhook
// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
//   string webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
//   WebhookRequest request The request object that contains all of the information used to create the webhook.
func (c *FusionAuthClient) CreateWebhook(webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
    var resp WebhookResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/webhook").
             WithUriSegment(webhookId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeactivateApplication
// Deactivates the application with the given Id.
//   string applicationId The Id of the application to deactivate.
func (c *FusionAuthClient) DeactivateApplication(applicationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeactivateUser
// Deactivates the user with the given Id.
//   string userId The Id of the user to deactivate.
func (c *FusionAuthClient) DeactivateUser(userId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeactivateUserAction
// Deactivates the user action with the given Id.
//   string userActionId The Id of the user action to deactivate.
func (c *FusionAuthClient) DeactivateUserAction(userActionId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeactivateUsers
// Deactivates the users with the given ids.
//   []string userIds The ids of the users to deactivate.
//
// Deprecated: This method has been renamed to DeactivateUsersByIds, use that method instead.
func (c *FusionAuthClient) DeactivateUsers(userIds []string) (*UserDeleteResponse, *Errors, error) {
    var resp UserDeleteResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/bulk").
             WithParameter("userId", userIds).
             WithParameter("dryRun", strconv.FormatBool(false)).
             WithParameter("hardDelete", strconv.FormatBool(false)).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeactivateUsersByIds
// Deactivates the users with the given ids.
//   []string userIds The ids of the users to deactivate.
func (c *FusionAuthClient) DeactivateUsersByIds(userIds []string) (*UserDeleteResponse, *Errors, error) {
    var resp UserDeleteResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/bulk").
             WithParameter("userId", userIds).
             WithParameter("dryRun", strconv.FormatBool(false)).
             WithParameter("hardDelete", strconv.FormatBool(false)).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteApplication
// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
// delete the application, any registrations for that application, metrics and reports for the application, all the
// roles for the application, and any other data associated with the application. This operation could take a very
// long time, depending on the amount of data in your database.
//   string applicationId The Id of the application to delete.
func (c *FusionAuthClient) DeleteApplication(applicationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithParameter("hardDelete", strconv.FormatBool(true)).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteApplicationRole
// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
// permanently removes the given role from all users that had it.
//   string applicationId The Id of the application to deactivate.
//   string roleId The Id of the role to delete.
func (c *FusionAuthClient) DeleteApplicationRole(applicationId string, roleId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithUriSegment("role").
             WithUriSegment(roleId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteConsent
// Deletes the consent for the given Id.
//   string consentId The Id of the consent to delete.
func (c *FusionAuthClient) DeleteConsent(consentId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/consent").
             WithUriSegment(consentId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteEmailTemplate
// Deletes the email template for the given Id.
//   string emailTemplateId The Id of the email template to delete.
func (c *FusionAuthClient) DeleteEmailTemplate(emailTemplateId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/template").
             WithUriSegment(emailTemplateId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteGroup
// Deletes the group for the given Id.
//   string groupId The Id of the group to delete.
func (c *FusionAuthClient) DeleteGroup(groupId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group").
             WithUriSegment(groupId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteGroupMembers
// Removes users as members of a group.
//   MemberDeleteRequest request The member request that contains all of the information used to remove members to the group.
func (c *FusionAuthClient) DeleteGroupMembers(request MemberDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group/member").
             WithJSONBody(request).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteIdentityProvider
// Deletes the identity provider for the given Id.
//   string identityProviderId The Id of the identity provider to delete.
func (c *FusionAuthClient) DeleteIdentityProvider(identityProviderId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/identity-provider").
             WithUriSegment(identityProviderId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteKey
// Deletes the key for the given Id.
//   string keyOd The Id of the key to delete.
func (c *FusionAuthClient) DeleteKey(keyOd string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/key").
             WithUriSegment(keyOd).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteLambda
// Deletes the lambda for the given Id.
//   string lambdaId The Id of the lambda to delete.
func (c *FusionAuthClient) DeleteLambda(lambdaId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/lambda").
             WithUriSegment(lambdaId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteRegistration
// Deletes the user registration for the given user and application.
//   string userId The Id of the user whose registration is being deleted.
//   string applicationId The Id of the application to remove the registration for.
func (c *FusionAuthClient) DeleteRegistration(userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/registration").
             WithUriSegment(userId).
             WithUriSegment(applicationId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteTenant
// Deletes the tenant for the given Id.
//   string tenantId The Id of the tenant to delete.
func (c *FusionAuthClient) DeleteTenant(tenantId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/tenant").
             WithUriSegment(tenantId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteTheme
// Deletes the theme for the given Id.
//   string themeId The Id of the theme to delete.
func (c *FusionAuthClient) DeleteTheme(themeId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/theme").
             WithUriSegment(themeId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteUser
// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
// with the user.
//   string userId The Id of the user to delete.
func (c *FusionAuthClient) DeleteUser(userId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithParameter("hardDelete", strconv.FormatBool(true)).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteUserAction
// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
// the action being applied to any users.
//   string userActionId The Id of the user action to delete.
func (c *FusionAuthClient) DeleteUserAction(userActionId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithParameter("hardDelete", strconv.FormatBool(true)).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteUserActionReason
// Deletes the user action reason for the given Id.
//   string userActionReasonId The Id of the user action reason to delete.
func (c *FusionAuthClient) DeleteUserActionReason(userActionReasonId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action-reason").
             WithUriSegment(userActionReasonId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteUsers
// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
// 
// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
//   UserDeleteRequest request The UserDeleteRequest.
//
// Deprecated: This method has been renamed to DeleteUsersByQuery, use that method instead.
func (c *FusionAuthClient) DeleteUsers(request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
    var resp UserDeleteResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/bulk").
             WithJSONBody(request).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteUsersByQuery
// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
// 
// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
//   UserDeleteRequest request The UserDeleteRequest.
func (c *FusionAuthClient) DeleteUsersByQuery(request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
    var resp UserDeleteResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/bulk").
             WithJSONBody(request).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DeleteWebhook
// Deletes the webhook for the given Id.
//   string webhookId The Id of the webhook to delete.
func (c *FusionAuthClient) DeleteWebhook(webhookId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/webhook").
             WithUriSegment(webhookId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// DisableTwoFactor
// Disable Two Factor authentication for a user.
//   string userId The Id of the User for which you're disabling Two Factor authentication.
//   string code The Two Factor code used verify the the caller knows the Two Factor secret.
func (c *FusionAuthClient) DisableTwoFactor(userId string, code string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/two-factor").
             WithParameter("userId", userId).
             WithParameter("code", code).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// EnableTwoFactor
// Enable Two Factor authentication for a user.
//   string userId The Id of the user to enable Two Factor authentication.
//   TwoFactorRequest request The two factor enable request information.
func (c *FusionAuthClient) EnableTwoFactor(userId string, request TwoFactorRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/two-factor").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ExchangeOAuthCodeForAccessToken
// Exchanges an OAuth authorization code for an access token.
// If you will be using the Authorization Code grant, you will make a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
//   string code The authorization code returned on the /oauth2/authorize response.
//   string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//   string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//   string redirectUri The URI to redirect to upon a successful request.
func (c *FusionAuthClient) ExchangeOAuthCodeForAccessToken(code string, clientId string, clientSecret string, redirectUri string) (*AccessToken, *OAuthError, error) {
    var resp AccessToken
    var errors OAuthError
    formBody := url.Values{}
    formBody.Set("code", code)
    formBody.Set("client_id", clientId)
    formBody.Set("client_secret", clientSecret)
    formBody.Set("grant_type", "authorization_code")
    formBody.Set("redirect_uri", redirectUri)

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/oauth2/token").
             WithFormData(formBody).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ExchangeRefreshTokenForAccessToken
// Exchange a Refresh Token for an Access Token.
// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
//   string refreshToken The refresh token that you would like to use to exchange for an access token.
//   string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//   string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//   string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//   string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeRefreshTokenForAccessToken(refreshToken string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
    var resp AccessToken
    var errors OAuthError
    formBody := url.Values{}
    formBody.Set("refresh_token", refreshToken)
    formBody.Set("client_id", clientId)
    formBody.Set("client_secret", clientSecret)
    formBody.Set("grant_type", "refresh_token")
    formBody.Set("scope", scope)
    formBody.Set("user_code", userCode)

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/oauth2/token").
             WithFormData(formBody).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ExchangeRefreshTokenForJWT
// Exchange a refresh token for a new JWT.
//   RefreshRequest request The refresh request.
func (c *FusionAuthClient) ExchangeRefreshTokenForJWT(request RefreshRequest) (*RefreshResponse, *Errors, error) {
    var resp RefreshResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/jwt/refresh").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ExchangeUserCredentialsForAccessToken
// Exchange User Credentials for a Token.
// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
//   string username The login identifier of the user. The login identifier can be either the email or the username.
//   string password The user’s password.
//   string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//   string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//   string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//   string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeUserCredentialsForAccessToken(username string, password string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
    var resp AccessToken
    var errors OAuthError
    formBody := url.Values{}
    formBody.Set("username", username)
    formBody.Set("password", password)
    formBody.Set("client_id", clientId)
    formBody.Set("client_secret", clientSecret)
    formBody.Set("grant_type", "password")
    formBody.Set("scope", scope)
    formBody.Set("user_code", userCode)

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/oauth2/token").
             WithFormData(formBody).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ForgotPassword
// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
//   ForgotPasswordRequest request The request that contains the information about the user so that they can be emailed.
func (c *FusionAuthClient) ForgotPassword(request ForgotPasswordRequest) (*ForgotPasswordResponse, *Errors, error) {
    var resp ForgotPasswordResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/forgot-password").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// GenerateEmailVerificationId
// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//   string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) GenerateEmailVerificationId(email string) (*VerifyEmailResponse, error) {
    var resp VerifyEmailResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/verify-email").
             WithParameter("email", email).
             WithParameter("sendVerifyEmail", strconv.FormatBool(false)).
             WithMethod(http.MethodPut).
             Do()
    return &resp, err
}

// GenerateKey
// Generate a new RSA or EC key pair or an HMAC secret.
//   string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//   KeyRequest request The request object that contains all of the information used to create the key.
func (c *FusionAuthClient) GenerateKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
    var resp KeyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/key/generate").
             WithUriSegment(keyId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// GenerateRegistrationVerificationId
// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//   string email The email address of the user that needs a new verification email.
//   string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) GenerateRegistrationVerificationId(email string, applicationId string) (*VerifyRegistrationResponse, error) {
    var resp VerifyRegistrationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/verify-registration").
             WithParameter("email", email).
             WithParameter("sendVerifyPasswordEmail", strconv.FormatBool(false)).
             WithParameter("applicationId", applicationId).
             WithMethod(http.MethodPut).
             Do()
    return &resp, err
}

// GenerateTwoFactorSecret
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
func (c *FusionAuthClient) GenerateTwoFactorSecret() (*SecretResponse, error) {
    var resp SecretResponse

    err := c.Start(&resp, nil).
             WithUri("/api/two-factor/secret").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// GenerateTwoFactorSecretUsingJWT
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
//   string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) GenerateTwoFactorSecretUsingJWT(encodedJWT string) (*SecretResponse, error) {
    var resp SecretResponse

    err := c.Start(&resp, nil).
             WithUri("/api/two-factor/secret").
             WithAuthorization("JWT " + encodedJWT).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// IdentityProviderLogin
// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
// login systems.
//   IdentityProviderLoginRequest request The third-party login request that contains information from the third-party login
//   providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) IdentityProviderLogin(request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
    var resp LoginResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/identity-provider/login").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ImportKey
// Import an existing RSA or EC key pair or an HMAC secret.
//   string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//   KeyRequest request The request object that contains all of the information used to create the key.
func (c *FusionAuthClient) ImportKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
    var resp KeyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/key/import").
             WithUriSegment(keyId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ImportUsers
// Bulk imports multiple users. This does some validation, but then tries to run batch inserts of users. This reduces
// latency when inserting lots of users. Therefore, the error response might contain some information about failures,
// but it will likely be pretty generic.
//   ImportRequest request The request that contains all of the information about all of the users to import.
func (c *FusionAuthClient) ImportUsers(request ImportRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/import").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// IssueJWT
// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
// access token is properly signed and not expired.
// <p>
// This API may be used in an SSO configuration to issue new tokens for another application after the user has
// obtained a valid token from authentication.
//   string applicationId The Application Id for which you are requesting a new access token be issued.
//   string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) IssueJWT(applicationId string, encodedJWT string) (*IssueResponse, *Errors, error) {
    var resp IssueResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/jwt/issue").
             WithAuthorization("JWT " + encodedJWT).
             WithParameter("applicationId", applicationId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// Login
// Authenticates a user to FusionAuth. 
// 
// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
//   LoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) Login(request LoginRequest) (*LoginResponse, *Errors, error) {
    var resp LoginResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/login").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// LoginPing
// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
// application where they no longer have a session. This helps correctly track login counts, times and helps with
// reporting.
//   string userId The Id of the user that was logged in.
//   string applicationId The Id of the application that they logged into.
//   string callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
//   the IP address will be that of the client or last proxy that sent the request.
func (c *FusionAuthClient) LoginPing(userId string, applicationId string, callerIPAddress string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/login").
             WithUriSegment(userId).
             WithUriSegment(applicationId).
             WithParameter("ipAddress", callerIPAddress).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// Logout
// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
// token or refresh token cookies.
//   bool global When this value is set to true all of the refresh tokens issued to the owner of the
//   provided token will be revoked.
//   string refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
//   If provided this takes precedence over the cookie.
func (c *FusionAuthClient) Logout(global bool, refreshToken string) (*BaseHTTPResponse, error) {
    var resp BaseHTTPResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/logout").
             WithParameter("global", strconv.FormatBool(global)).
             WithParameter("refreshToken", refreshToken).
             WithMethod(http.MethodPost).
             Do()
    return &resp, err
}

// LookupIdentityProvider
// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
// by a registered identity provider. A 404 indicates the domain is not managed.
//   string domain The domain or email address to lookup.
func (c *FusionAuthClient) LookupIdentityProvider(domain string) (*LookupResponse, error) {
    var resp LookupResponse

    err := c.Start(&resp, nil).
             WithUri("/api/identity-provider/lookup").
             WithParameter("domain", domain).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// ModifyAction
// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
// action.
//   string actionId The Id of the action to modify. This is technically the user action log id.
//   ActionRequest request The request that contains all of the information about the modification.
func (c *FusionAuthClient) ModifyAction(actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithUriSegment(actionId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PasswordlessLogin
// Complete a login request using a passwordless code
//   PasswordlessLoginRequest request The passwordless login request that contains all of the information used to complete login.
func (c *FusionAuthClient) PasswordlessLogin(request PasswordlessLoginRequest) (*LoginResponse, *Errors, error) {
    var resp LoginResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/passwordless/login").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchApplication
// Updates, via PATCH, the application with the given Id.
//   string applicationId The Id of the application to update.
//   ApplicationRequest request The request that contains just the new application information.
func (c *FusionAuthClient) PatchApplication(applicationId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchApplicationRole
// Updates, via PATCH, the application role with the given id for the application.
//   string applicationId The Id of the application that the role belongs to.
//   string roleId The Id of the role to update.
//   ApplicationRequest request The request that contains just the new role information.
func (c *FusionAuthClient) PatchApplicationRole(applicationId string, roleId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithUriSegment("role").
             WithUriSegment(roleId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchConsent
// Updates, via PATCH, the consent with the given Id.
//   string consentId The Id of the consent to update.
//   ConsentRequest request The request that contains just the new consent information.
func (c *FusionAuthClient) PatchConsent(consentId string, request map[string]interface{}) (*ConsentResponse, *Errors, error) {
    var resp ConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/consent").
             WithUriSegment(consentId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchEmailTemplate
// Updates, via PATCH, the email template with the given Id.
//   string emailTemplateId The Id of the email template to update.
//   EmailTemplateRequest request The request that contains just the new email template information.
func (c *FusionAuthClient) PatchEmailTemplate(emailTemplateId string, request map[string]interface{}) (*EmailTemplateResponse, *Errors, error) {
    var resp EmailTemplateResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/template").
             WithUriSegment(emailTemplateId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchGroup
// Updates, via PATCH, the group with the given Id.
//   string groupId The Id of the group to update.
//   GroupRequest request The request that contains just the new group information.
func (c *FusionAuthClient) PatchGroup(groupId string, request map[string]interface{}) (*GroupResponse, *Errors, error) {
    var resp GroupResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group").
             WithUriSegment(groupId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchIdentityProvider
// Updates, via PATCH, the identity provider with the given Id.
//   string identityProviderId The Id of the identity provider to update.
//   IdentityProviderRequest request The request object that contains just the updated identity provider information.
func (c *FusionAuthClient) PatchIdentityProvider(identityProviderId string, request map[string]interface{}) (*IdentityProviderResponse, *Errors, error) {
    var resp IdentityProviderResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/identity-provider").
             WithUriSegment(identityProviderId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchIntegrations
// Updates, via PATCH, the available integrations.
//   IntegrationRequest request The request that contains just the new integration information.
func (c *FusionAuthClient) PatchIntegrations(request map[string]interface{}) (*IntegrationResponse, *Errors, error) {
    var resp IntegrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/integration").
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchLambda
// Updates, via PATCH, the lambda with the given Id.
//   string lambdaId The Id of the lambda to update.
//   LambdaRequest request The request that contains just the new lambda information.
func (c *FusionAuthClient) PatchLambda(lambdaId string, request map[string]interface{}) (*LambdaResponse, *Errors, error) {
    var resp LambdaResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/lambda").
             WithUriSegment(lambdaId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchRegistration
// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
//   string userId The Id of the user whose registration is going to be updated.
//   RegistrationRequest request The request that contains just the new registration information.
func (c *FusionAuthClient) PatchRegistration(userId string, request map[string]interface{}) (*RegistrationResponse, *Errors, error) {
    var resp RegistrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/registration").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchSystemConfiguration
// Updates, via PATCH, the system configuration.
//   SystemConfigurationRequest request The request that contains just the new system configuration information.
func (c *FusionAuthClient) PatchSystemConfiguration(request map[string]interface{}) (*SystemConfigurationResponse, *Errors, error) {
    var resp SystemConfigurationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/system-configuration").
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchTenant
// Updates, via PATCH, the tenant with the given Id.
//   string tenantId The Id of the tenant to update.
//   TenantRequest request The request that contains just the new tenant information.
func (c *FusionAuthClient) PatchTenant(tenantId string, request map[string]interface{}) (*TenantResponse, *Errors, error) {
    var resp TenantResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/tenant").
             WithUriSegment(tenantId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchTheme
// Updates, via PATCH, the theme with the given Id.
//   string themeId The Id of the theme to update.
//   ThemeRequest request The request that contains just the new theme information.
func (c *FusionAuthClient) PatchTheme(themeId string, request map[string]interface{}) (*ThemeResponse, *Errors, error) {
    var resp ThemeResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/theme").
             WithUriSegment(themeId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchUser
// Updates, via PATCH, the user with the given Id.
//   string userId The Id of the user to update.
//   UserRequest request The request that contains just the new user information.
func (c *FusionAuthClient) PatchUser(userId string, request map[string]interface{}) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchUserAction
// Updates, via PATCH, the user action with the given Id.
//   string userActionId The Id of the user action to update.
//   UserActionRequest request The request that contains just the new user action information.
func (c *FusionAuthClient) PatchUserAction(userActionId string, request map[string]interface{}) (*UserActionResponse, *Errors, error) {
    var resp UserActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchUserActionReason
// Updates, via PATCH, the user action reason with the given Id.
//   string userActionReasonId The Id of the user action reason to update.
//   UserActionReasonRequest request The request that contains just the new user action reason information.
func (c *FusionAuthClient) PatchUserActionReason(userActionReasonId string, request map[string]interface{}) (*UserActionReasonResponse, *Errors, error) {
    var resp UserActionReasonResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action-reason").
             WithUriSegment(userActionReasonId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// PatchUserConsent
// Updates, via PATCH, a single User consent by Id.
//   string userConsentId The User Consent Id
//   UserConsentRequest request The request that contains just the new user consent information.
func (c *FusionAuthClient) PatchUserConsent(userConsentId string, request map[string]interface{}) (*UserConsentResponse, *Errors, error) {
    var resp UserConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/consent").
             WithUriSegment(userConsentId).
             WithJSONBody(request).
             WithMethod(http.MethodPatch).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ReactivateApplication
// Reactivates the application with the given Id.
//   string applicationId The Id of the application to reactivate.
func (c *FusionAuthClient) ReactivateApplication(applicationId string) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithParameter("reactivate", strconv.FormatBool(true)).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ReactivateUser
// Reactivates the user with the given Id.
//   string userId The Id of the user to reactivate.
func (c *FusionAuthClient) ReactivateUser(userId string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithParameter("reactivate", strconv.FormatBool(true)).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ReactivateUserAction
// Reactivates the user action with the given Id.
//   string userActionId The Id of the user action to reactivate.
func (c *FusionAuthClient) ReactivateUserAction(userActionId string) (*UserActionResponse, *Errors, error) {
    var resp UserActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithParameter("reactivate", strconv.FormatBool(true)).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ReconcileJWT
// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
//   IdentityProviderLoginRequest request The reconcile request that contains the data to reconcile the User.
func (c *FusionAuthClient) ReconcileJWT(request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
    var resp LoginResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/jwt/reconcile").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RefreshUserSearchIndex
// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
//  ensure the index immediately current before making a query request to the search index.
func (c *FusionAuthClient) RefreshUserSearchIndex() (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/search").
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// Register
// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
// will create the user as well as register them for the application. This is called a Full Registration. However, if
// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
// application. The user id can also be provided and it will either be used to look up an existing user or it will be
// used for the newly created User.
//   string userId (Optional) The Id of the user being registered for the application and optionally created.
//   RegistrationRequest request The request that optionally contains the User and must contain the UserRegistration.
func (c *FusionAuthClient) Register(userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
    var resp RegistrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/registration").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RemoveUserFromFamily
// Removes a user from the family with the given id.
//   string familyId The id of the family to remove the user from.
//   string userId The id of the user to remove from the family.
func (c *FusionAuthClient) RemoveUserFromFamily(familyId string, userId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/family").
             WithUriSegment(familyId).
             WithUriSegment(userId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ResendEmailVerification
// Re-sends the verification email to the user.
//   string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) ResendEmailVerification(email string) (*VerifyEmailResponse, *Errors, error) {
    var resp VerifyEmailResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/verify-email").
             WithParameter("email", email).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ResendRegistrationVerification
// Re-sends the application registration verification email to the user.
//   string email The email address of the user that needs a new verification email.
//   string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) ResendRegistrationVerification(email string, applicationId string) (*VerifyRegistrationResponse, *Errors, error) {
    var resp VerifyRegistrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/verify-registration").
             WithParameter("email", email).
             WithParameter("applicationId", applicationId).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveAction
// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
//   string actionId The Id of the action to retrieve.
func (c *FusionAuthClient) RetrieveAction(actionId string) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithUriSegment(actionId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveActions
// Retrieves all of the actions for the user with the given Id. This will return all time based actions that are active,
// and inactive as well as non-time based actions.
//   string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActions(userId string) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithParameter("userId", userId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveActionsPreventingLogin
// Retrieves all of the actions for the user with the given Id that are currently preventing the User from logging in.
//   string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActionsPreventingLogin(userId string) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithParameter("userId", userId).
             WithParameter("preventingLogin", strconv.FormatBool(true)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveActiveActions
// Retrieves all of the actions for the user with the given Id that are currently active.
// An active action means one that is time based and has not been canceled, and has not ended.
//   string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActiveActions(userId string) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithParameter("userId", userId).
             WithParameter("active", strconv.FormatBool(true)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveApplication
// Retrieves the application for the given id or all of the applications if the id is null.
//   string applicationId (Optional) The application id.
func (c *FusionAuthClient) RetrieveApplication(applicationId string) (*ApplicationResponse, error) {
    var resp ApplicationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/application").
             WithUriSegment(applicationId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveApplications
// Retrieves all of the applications.
func (c *FusionAuthClient) RetrieveApplications() (*ApplicationResponse, error) {
    var resp ApplicationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/application").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveAuditLog
// Retrieves a single audit log for the given Id.
//   int auditLogId The Id of the audit log to retrieve.
func (c *FusionAuthClient) RetrieveAuditLog(auditLogId int) (*AuditLogResponse, *Errors, error) {
    var resp AuditLogResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/system/audit-log").
             WithUriSegment(string(auditLogId)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveConsent
// Retrieves the Consent for the given Id.
//   string consentId The Id of the consent.
func (c *FusionAuthClient) RetrieveConsent(consentId string) (*ConsentResponse, error) {
    var resp ConsentResponse

    err := c.Start(&resp, nil).
             WithUri("/api/consent").
             WithUriSegment(consentId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveConsents
// Retrieves all of the consent.
func (c *FusionAuthClient) RetrieveConsents() (*ConsentResponse, error) {
    var resp ConsentResponse

    err := c.Start(&resp, nil).
             WithUri("/api/consent").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveDailyActiveReport
// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
// return the daily active counts for that application.
//   string applicationId (Optional) The application id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveDailyActiveReport(applicationId string, start int64, end int64) (*DailyActiveUserReportResponse, *Errors, error) {
    var resp DailyActiveUserReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/daily-active-user").
             WithParameter("applicationId", applicationId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveEmailTemplate
// Retrieves the email template for the given Id. If you don't specify the id, this will return all of the email templates.
//   string emailTemplateId (Optional) The Id of the email template.
func (c *FusionAuthClient) RetrieveEmailTemplate(emailTemplateId string) (*EmailTemplateResponse, error) {
    var resp EmailTemplateResponse

    err := c.Start(&resp, nil).
             WithUri("/api/email/template").
             WithUriSegment(emailTemplateId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveEmailTemplatePreview
// Creates a preview of the email template provided in the request. This allows you to preview an email template that
// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
// will create the preview based on whatever is given.
//   PreviewRequest request The request that contains the email template and optionally a locale to render it in.
func (c *FusionAuthClient) RetrieveEmailTemplatePreview(request PreviewRequest) (*PreviewResponse, *Errors, error) {
    var resp PreviewResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/template/preview").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveEmailTemplates
// Retrieves all of the email templates.
func (c *FusionAuthClient) RetrieveEmailTemplates() (*EmailTemplateResponse, error) {
    var resp EmailTemplateResponse

    err := c.Start(&resp, nil).
             WithUri("/api/email/template").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveEventLog
// Retrieves a single event log for the given Id.
//   int eventLogId The Id of the event log to retrieve.
func (c *FusionAuthClient) RetrieveEventLog(eventLogId int) (*EventLogResponse, *Errors, error) {
    var resp EventLogResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/system/event-log").
             WithUriSegment(string(eventLogId)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveFamilies
// Retrieves all of the families that a user belongs to.
//   string userId The User's id
func (c *FusionAuthClient) RetrieveFamilies(userId string) (*FamilyResponse, error) {
    var resp FamilyResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/family").
             WithParameter("userId", userId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveFamilyMembersByFamilyId
// Retrieves all of the members of a family by the unique Family Id.
//   string familyId The unique Id of the Family.
func (c *FusionAuthClient) RetrieveFamilyMembersByFamilyId(familyId string) (*FamilyResponse, error) {
    var resp FamilyResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/family").
             WithUriSegment(familyId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveGroup
// Retrieves the group for the given Id.
//   string groupId The Id of the group.
func (c *FusionAuthClient) RetrieveGroup(groupId string) (*GroupResponse, *Errors, error) {
    var resp GroupResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group").
             WithUriSegment(groupId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveGroups
// Retrieves all of the groups.
func (c *FusionAuthClient) RetrieveGroups() (*GroupResponse, error) {
    var resp GroupResponse

    err := c.Start(&resp, nil).
             WithUri("/api/group").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveInactiveActions
// Retrieves all of the actions for the user with the given Id that are currently inactive.
// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
//   string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveInactiveActions(userId string) (*ActionResponse, *Errors, error) {
    var resp ActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/action").
             WithParameter("userId", userId).
             WithParameter("active", strconv.FormatBool(false)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveInactiveApplications
// Retrieves all of the applications that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveApplications() (*ApplicationResponse, error) {
    var resp ApplicationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/application").
             WithParameter("inactive", strconv.FormatBool(true)).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveInactiveUserActions
// Retrieves all of the user actions that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveUserActions() (*UserActionResponse, error) {
    var resp UserActionResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user-action").
             WithParameter("inactive", strconv.FormatBool(true)).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveIntegration
// Retrieves the available integrations.
func (c *FusionAuthClient) RetrieveIntegration() (*IntegrationResponse, error) {
    var resp IntegrationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/integration").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveJWTPublicKey
// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
//   string keyId The Id of the public key (kid).
func (c *FusionAuthClient) RetrieveJWTPublicKey(keyId string) (*PublicKeyResponse, error) {
    var resp PublicKeyResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/jwt/public-key").
             WithParameter("kid", keyId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveJWTPublicKeyByApplicationId
// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
//   string applicationId The Id of the Application for which this key is used.
func (c *FusionAuthClient) RetrieveJWTPublicKeyByApplicationId(applicationId string) (*PublicKeyResponse, error) {
    var resp PublicKeyResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/jwt/public-key").
             WithParameter("applicationId", applicationId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveJWTPublicKeys
// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
func (c *FusionAuthClient) RetrieveJWTPublicKeys() (*PublicKeyResponse, error) {
    var resp PublicKeyResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/jwt/public-key").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveJsonWebKeySet
// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
func (c *FusionAuthClient) RetrieveJsonWebKeySet() (*JWKSResponse, error) {
    var resp JWKSResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/.well-known/jwks.json").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveKey
// Retrieves the key for the given Id.
//   string keyId The Id of the key.
func (c *FusionAuthClient) RetrieveKey(keyId string) (*KeyResponse, *Errors, error) {
    var resp KeyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/key").
             WithUriSegment(keyId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveKeys
// Retrieves all of the keys.
func (c *FusionAuthClient) RetrieveKeys() (*KeyResponse, error) {
    var resp KeyResponse

    err := c.Start(&resp, nil).
             WithUri("/api/key").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveLambda
// Retrieves the lambda for the given Id.
//   string lambdaId The Id of the lambda.
func (c *FusionAuthClient) RetrieveLambda(lambdaId string) (*LambdaResponse, *Errors, error) {
    var resp LambdaResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/lambda").
             WithUriSegment(lambdaId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveLambdas
// Retrieves all of the lambdas.
func (c *FusionAuthClient) RetrieveLambdas() (*LambdaResponse, error) {
    var resp LambdaResponse

    err := c.Start(&resp, nil).
             WithUri("/api/lambda").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveLambdasByType
// Retrieves all of the lambdas for the provided type.
//   LambdaType _type The type of the lambda to return.
func (c *FusionAuthClient) RetrieveLambdasByType(_type LambdaType) (*LambdaResponse, error) {
    var resp LambdaResponse

    err := c.Start(&resp, nil).
             WithUri("/api/lambda").
             WithParameter("type", string(_type)).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveLoginReport
// Retrieves the login report between the two instants. If you specify an application id, it will only return the
// login counts for that application.
//   string applicationId (Optional) The application id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveLoginReport(applicationId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
    var resp LoginReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/login").
             WithParameter("applicationId", applicationId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveMonthlyActiveReport
// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
// return the monthly active counts for that application.
//   string applicationId (Optional) The application id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveMonthlyActiveReport(applicationId string, start int64, end int64) (*MonthlyActiveUserReportResponse, *Errors, error) {
    var resp MonthlyActiveUserReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/monthly-active-user").
             WithParameter("applicationId", applicationId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveOauthConfiguration
// Retrieves the Oauth2 configuration for the application for the given Application Id.
//   string applicationId The Id of the Application to retrieve OAuth configuration.
func (c *FusionAuthClient) RetrieveOauthConfiguration(applicationId string) (*OAuthConfigurationResponse, *Errors, error) {
    var resp OAuthConfigurationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithUriSegment("oauth-configuration").
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveOpenIdConfiguration
// Returns the well known OpenID Configuration JSON document
func (c *FusionAuthClient) RetrieveOpenIdConfiguration() (*OpenIdConfiguration, error) {
    var resp OpenIdConfiguration

    err := c.StartAnonymous(&resp, nil).
             WithUri("/.well-known/openid-configuration").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrievePasswordValidationRules
// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
// 
// This API does not require an API key.
func (c *FusionAuthClient) RetrievePasswordValidationRules() (*PasswordValidationRulesResponse, error) {
    var resp PasswordValidationRulesResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/tenant/password-validation-rules").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrievePasswordValidationRulesWithTenantId
// Retrieves the password validation rules for a specific tenant.
// 
// This API does not require an API key.
//   string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrievePasswordValidationRulesWithTenantId(tenantId string) (*PasswordValidationRulesResponse, error) {
    var resp PasswordValidationRulesResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/tenant/password-validation-rules").
             WithUriSegment(tenantId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrievePendingChildren
// Retrieves all of the children for the given parent email address.
//   string parentEmail The email of the parent.
func (c *FusionAuthClient) RetrievePendingChildren(parentEmail string) (*PendingResponse, *Errors, error) {
    var resp PendingResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/family/pending").
             WithParameter("parentEmail", parentEmail).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveRecentLogins
// Retrieves the last number of login records.
//   int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//   int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveRecentLogins(offset int, limit int) (*RecentLoginResponse, *Errors, error) {
    var resp RecentLoginResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/recent-login").
             WithParameter("offset", strconv.Itoa(offset)).
             WithParameter("limit", strconv.Itoa(limit)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveRefreshTokens
// Retrieves the refresh tokens that belong to the user with the given Id.
//   string userId The Id of the user.
func (c *FusionAuthClient) RetrieveRefreshTokens(userId string) (*RefreshResponse, *Errors, error) {
    var resp RefreshResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/jwt/refresh").
             WithParameter("userId", userId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveRegistration
// Retrieves the user registration for the user with the given id and the given application id.
//   string userId The Id of the user.
//   string applicationId The Id of the application.
func (c *FusionAuthClient) RetrieveRegistration(userId string, applicationId string) (*RegistrationResponse, *Errors, error) {
    var resp RegistrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/registration").
             WithUriSegment(userId).
             WithUriSegment(applicationId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveRegistrationReport
// Retrieves the registration report between the two instants. If you specify an application id, it will only return
// the registration counts for that application.
//   string applicationId (Optional) The application id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveRegistrationReport(applicationId string, start int64, end int64) (*RegistrationReportResponse, *Errors, error) {
    var resp RegistrationReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/registration").
             WithParameter("applicationId", applicationId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveSystemConfiguration
// Retrieves the system configuration.
func (c *FusionAuthClient) RetrieveSystemConfiguration() (*SystemConfigurationResponse, error) {
    var resp SystemConfigurationResponse

    err := c.Start(&resp, nil).
             WithUri("/api/system-configuration").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveTenant
// Retrieves the tenant for the given Id.
//   string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrieveTenant(tenantId string) (*TenantResponse, *Errors, error) {
    var resp TenantResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/tenant").
             WithUriSegment(tenantId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveTenants
// Retrieves all of the tenants.
func (c *FusionAuthClient) RetrieveTenants() (*TenantResponse, error) {
    var resp TenantResponse

    err := c.Start(&resp, nil).
             WithUri("/api/tenant").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveTheme
// Retrieves the theme for the given Id.
//   string themeId The Id of the theme.
func (c *FusionAuthClient) RetrieveTheme(themeId string) (*ThemeResponse, *Errors, error) {
    var resp ThemeResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/theme").
             WithUriSegment(themeId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveThemes
// Retrieves all of the themes.
func (c *FusionAuthClient) RetrieveThemes() (*ThemeResponse, error) {
    var resp ThemeResponse

    err := c.Start(&resp, nil).
             WithUri("/api/theme").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveTotalReport
// Retrieves the totals report. This contains all of the total counts for each application and the global registration
// count.
func (c *FusionAuthClient) RetrieveTotalReport() (*TotalsReportResponse, error) {
    var resp TotalsReportResponse

    err := c.Start(&resp, nil).
             WithUri("/api/report/totals").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUser
// Retrieves the user for the given Id.
//   string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUser(userId string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserAction
// Retrieves the user action for the given Id. If you pass in null for the id, this will return all of the user
// actions.
//   string userActionId (Optional) The Id of the user action.
func (c *FusionAuthClient) RetrieveUserAction(userActionId string) (*UserActionResponse, error) {
    var resp UserActionResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserActionReason
// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all of the user
// action reasons.
//   string userActionReasonId (Optional) The Id of the user action reason.
func (c *FusionAuthClient) RetrieveUserActionReason(userActionReasonId string) (*UserActionReasonResponse, error) {
    var resp UserActionReasonResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user-action-reason").
             WithUriSegment(userActionReasonId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserActionReasons
// Retrieves all the user action reasons.
func (c *FusionAuthClient) RetrieveUserActionReasons() (*UserActionReasonResponse, error) {
    var resp UserActionReasonResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user-action-reason").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserActions
// Retrieves all of the user actions.
func (c *FusionAuthClient) RetrieveUserActions() (*UserActionResponse, error) {
    var resp UserActionResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user-action").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserByChangePasswordId
// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//   string changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
func (c *FusionAuthClient) RetrieveUserByChangePasswordId(changePasswordId string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithParameter("changePasswordId", changePasswordId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserByEmail
// Retrieves the user for the given email.
//   string email The email of the user.
func (c *FusionAuthClient) RetrieveUserByEmail(email string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithParameter("email", email).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserByLoginId
// Retrieves the user for the loginId. The loginId can be either the username or the email.
//   string loginId The email or username of the user.
func (c *FusionAuthClient) RetrieveUserByLoginId(loginId string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithParameter("loginId", loginId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserByUsername
// Retrieves the user for the given username.
//   string username The username of the user.
func (c *FusionAuthClient) RetrieveUserByUsername(username string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithParameter("username", username).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserByVerificationId
// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//   string verificationId The unique verification Id that has been set on the user object.
func (c *FusionAuthClient) RetrieveUserByVerificationId(verificationId string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithParameter("verificationId", verificationId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserComments
// Retrieves all of the comments for the user with the given Id.
//   string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUserComments(userId string) (*UserCommentResponse, *Errors, error) {
    var resp UserCommentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/comment").
             WithUriSegment(userId).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserConsent
// Retrieve a single User consent by Id.
//   string userConsentId The User consent Id
func (c *FusionAuthClient) RetrieveUserConsent(userConsentId string) (*UserConsentResponse, error) {
    var resp UserConsentResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/consent").
             WithUriSegment(userConsentId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserConsents
// Retrieves all of the consents for a User.
//   string userId The User's Id
func (c *FusionAuthClient) RetrieveUserConsents(userId string) (*UserConsentResponse, error) {
    var resp UserConsentResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/consent").
             WithParameter("userId", userId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveUserLoginReport
// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
// login counts for that application.
//   string applicationId (Optional) The application id.
//   string userId The userId id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReport(applicationId string, userId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
    var resp LoginReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/login").
             WithParameter("applicationId", applicationId).
             WithParameter("userId", userId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserLoginReportByLoginId
// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
// login counts for that application.
//   string applicationId (Optional) The application id.
//   string loginId The userId id.
//   int64 start The start instant as UTC milliseconds since Epoch.
//   int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReportByLoginId(applicationId string, loginId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
    var resp LoginReportResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/report/login").
             WithParameter("applicationId", applicationId).
             WithParameter("loginId", loginId).
             WithParameter("start", strconv.FormatInt(start, 10)).
             WithParameter("end", strconv.FormatInt(end, 10)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserRecentLogins
// Retrieves the last number of login records for a user.
//   string userId The Id of the user.
//   int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//   int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveUserRecentLogins(userId string, offset int, limit int) (*RecentLoginResponse, *Errors, error) {
    var resp RecentLoginResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/recent-login").
             WithParameter("userId", userId).
             WithParameter("offset", strconv.Itoa(offset)).
             WithParameter("limit", strconv.Itoa(limit)).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveUserUsingJWT
// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
//   string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) RetrieveUserUsingJWT(encodedJWT string) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithAuthorization("JWT " + encodedJWT).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RetrieveWebhook
// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
//   string webhookId (Optional) The Id of the webhook.
func (c *FusionAuthClient) RetrieveWebhook(webhookId string) (*WebhookResponse, error) {
    var resp WebhookResponse

    err := c.Start(&resp, nil).
             WithUri("/api/webhook").
             WithUriSegment(webhookId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RetrieveWebhooks
// Retrieves all the webhooks.
func (c *FusionAuthClient) RetrieveWebhooks() (*WebhookResponse, error) {
    var resp WebhookResponse

    err := c.Start(&resp, nil).
             WithUri("/api/webhook").
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// RevokeRefreshToken
// Revokes a single refresh token, all tokens for a user or all tokens for an application. If you provide a user id
// and an application id, this will delete all the refresh tokens for that user for that application.
//   string token (Optional) The refresh token to delete.
//   string userId (Optional) The user id whose tokens to delete.
//   string applicationId (Optional) The application id of the tokens to delete.
func (c *FusionAuthClient) RevokeRefreshToken(token string, userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/jwt/refresh").
             WithParameter("token", token).
             WithParameter("userId", userId).
             WithParameter("applicationId", applicationId).
             WithMethod(http.MethodDelete).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// RevokeUserConsent
// Revokes a single User consent by Id.
//   string userConsentId The User Consent Id
func (c *FusionAuthClient) RevokeUserConsent(userConsentId string) (*BaseHTTPResponse, error) {
    var resp BaseHTTPResponse

    err := c.Start(&resp, nil).
             WithUri("/api/user/consent").
             WithUriSegment(userConsentId).
             WithMethod(http.MethodDelete).
             Do()
    return &resp, err
}

// SearchAuditLogs
// Searches the audit logs with the specified criteria and pagination.
//   AuditLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchAuditLogs(request AuditLogSearchRequest) (*AuditLogSearchResponse, error) {
    var resp AuditLogSearchResponse

    err := c.Start(&resp, nil).
             WithUri("/api/system/audit-log/search").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    return &resp, err
}

// SearchEventLogs
// Searches the event logs with the specified criteria and pagination.
//   EventLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEventLogs(request EventLogSearchRequest) (*EventLogSearchResponse, error) {
    var resp EventLogSearchResponse

    err := c.Start(&resp, nil).
             WithUri("/api/system/event-log/search").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    return &resp, err
}

// SearchLoginRecords
// Searches the login records with the specified criteria and pagination.
//   LoginRecordSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchLoginRecords(request LoginRecordSearchRequest) (*LoginRecordSearchResponse, error) {
    var resp LoginRecordSearchResponse

    err := c.Start(&resp, nil).
             WithUri("/api/system/login-record/search").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    return &resp, err
}

// SearchUsers
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//   []string ids The user ids to search for.
//
// Deprecated: This method has been renamed to SearchUsersByIds, use that method instead.
func (c *FusionAuthClient) SearchUsers(ids []string) (*SearchResponse, *Errors, error) {
    var resp SearchResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/search").
             WithParameter("ids", ids).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SearchUsersByIds
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//   []string ids The user ids to search for.
func (c *FusionAuthClient) SearchUsersByIds(ids []string) (*SearchResponse, *Errors, error) {
    var resp SearchResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/search").
             WithParameter("ids", ids).
             WithMethod(http.MethodGet).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SearchUsersByQuery
// Retrieves the users for the given search criteria and pagination.
//   SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//   and sortFields.
func (c *FusionAuthClient) SearchUsersByQuery(request SearchRequest) (*SearchResponse, *Errors, error) {
    var resp SearchResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/search").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SearchUsersByQueryString
// Retrieves the users for the given search criteria and pagination.
//   SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//   and sortFields.
//
// Deprecated: This method has been renamed to SearchUsersByQuery, use that method instead.
func (c *FusionAuthClient) SearchUsersByQueryString(request SearchRequest) (*SearchResponse, *Errors, error) {
    var resp SearchResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/search").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SendEmail
// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
// pairs in the email template.
//   string emailTemplateId The id for the template.
//   SendRequest request The send email request that contains all of the information used to send the email.
func (c *FusionAuthClient) SendEmail(emailTemplateId string, request SendRequest) (*SendResponse, *Errors, error) {
    var resp SendResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/send").
             WithUriSegment(emailTemplateId).
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SendFamilyRequestEmail
// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
//   FamilyEmailRequest request The request object that contains the parent email.
func (c *FusionAuthClient) SendFamilyRequestEmail(request FamilyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/family/request").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SendPasswordlessCode
// Send a passwordless authentication code in an email to complete login.
//   PasswordlessSendRequest request The passwordless send request that contains all of the information used to send an email containing a code.
func (c *FusionAuthClient) SendPasswordlessCode(request PasswordlessSendRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/passwordless/send").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SendTwoFactorCode
// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
//   TwoFactorSendRequest request The request object that contains all of the information used to send the code.
func (c *FusionAuthClient) SendTwoFactorCode(request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/two-factor/send").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// SendTwoFactorCodeForLogin
// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
//   string twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
func (c *FusionAuthClient) SendTwoFactorCodeForLogin(twoFactorId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/two-factor/send").
             WithUriSegment(twoFactorId).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// StartIdentityProviderLogin
// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
//   IdentityProviderStartLoginRequest request The third-party login request that contains information from the third-party login
//   providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) StartIdentityProviderLogin(request IdentityProviderStartLoginRequest) (*IdentityProviderStartLoginResponse, *Errors, error) {
    var resp IdentityProviderStartLoginResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/identity-provider/start").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// StartPasswordlessLogin
// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
//   PasswordlessStartRequest request The passwordless start request that contains all of the information used to begin the passwordless login request.
func (c *FusionAuthClient) StartPasswordlessLogin(request PasswordlessStartRequest) (*PasswordlessStartResponse, *Errors, error) {
    var resp PasswordlessStartResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/passwordless/start").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// TwoFactorLogin
// Complete login using a 2FA challenge
//   TwoFactorLoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) TwoFactorLogin(request TwoFactorLoginRequest) (*LoginResponse, *Errors, error) {
    var resp LoginResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/two-factor/login").
             WithJSONBody(request).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateApplication
// Updates the application with the given Id.
//   string applicationId The Id of the application to update.
//   ApplicationRequest request The request that contains all of the new application information.
func (c *FusionAuthClient) UpdateApplication(applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateApplicationRole
// Updates the application role with the given id for the application.
//   string applicationId The Id of the application that the role belongs to.
//   string roleId The Id of the role to update.
//   ApplicationRequest request The request that contains all of the new role information.
func (c *FusionAuthClient) UpdateApplicationRole(applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
    var resp ApplicationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/application").
             WithUriSegment(applicationId).
             WithUriSegment("role").
             WithUriSegment(roleId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateConsent
// Updates the consent with the given Id.
//   string consentId The Id of the consent to update.
//   ConsentRequest request The request that contains all of the new consent information.
func (c *FusionAuthClient) UpdateConsent(consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
    var resp ConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/consent").
             WithUriSegment(consentId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateEmailTemplate
// Updates the email template with the given Id.
//   string emailTemplateId The Id of the email template to update.
//   EmailTemplateRequest request The request that contains all of the new email template information.
func (c *FusionAuthClient) UpdateEmailTemplate(emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
    var resp EmailTemplateResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/email/template").
             WithUriSegment(emailTemplateId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateGroup
// Updates the group with the given Id.
//   string groupId The Id of the group to update.
//   GroupRequest request The request that contains all of the new group information.
func (c *FusionAuthClient) UpdateGroup(groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
    var resp GroupResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/group").
             WithUriSegment(groupId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateIntegrations
// Updates the available integrations.
//   IntegrationRequest request The request that contains all of the new integration information.
func (c *FusionAuthClient) UpdateIntegrations(request IntegrationRequest) (*IntegrationResponse, *Errors, error) {
    var resp IntegrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/integration").
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateKey
// Updates the key with the given Id.
//   string keyId The Id of the key to update.
//   KeyRequest request The request that contains all of the new key information.
func (c *FusionAuthClient) UpdateKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
    var resp KeyResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/key").
             WithUriSegment(keyId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateLambda
// Updates the lambda with the given Id.
//   string lambdaId The Id of the lambda to update.
//   LambdaRequest request The request that contains all of the new lambda information.
func (c *FusionAuthClient) UpdateLambda(lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
    var resp LambdaResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/lambda").
             WithUriSegment(lambdaId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateRegistration
// Updates the registration for the user with the given id and the application defined in the request.
//   string userId The Id of the user whose registration is going to be updated.
//   RegistrationRequest request The request that contains all of the new registration information.
func (c *FusionAuthClient) UpdateRegistration(userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
    var resp RegistrationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/registration").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateSystemConfiguration
// Updates the system configuration.
//   SystemConfigurationRequest request The request that contains all of the new system configuration information.
func (c *FusionAuthClient) UpdateSystemConfiguration(request SystemConfigurationRequest) (*SystemConfigurationResponse, *Errors, error) {
    var resp SystemConfigurationResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/system-configuration").
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateTenant
// Updates the tenant with the given Id.
//   string tenantId The Id of the tenant to update.
//   TenantRequest request The request that contains all of the new tenant information.
func (c *FusionAuthClient) UpdateTenant(tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
    var resp TenantResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/tenant").
             WithUriSegment(tenantId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateTheme
// Updates the theme with the given Id.
//   string themeId The Id of the theme to update.
//   ThemeRequest request The request that contains all of the new theme information.
func (c *FusionAuthClient) UpdateTheme(themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
    var resp ThemeResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/theme").
             WithUriSegment(themeId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateUser
// Updates the user with the given Id.
//   string userId The Id of the user to update.
//   UserRequest request The request that contains all of the new user information.
func (c *FusionAuthClient) UpdateUser(userId string, request UserRequest) (*UserResponse, *Errors, error) {
    var resp UserResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user").
             WithUriSegment(userId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateUserAction
// Updates the user action with the given Id.
//   string userActionId The Id of the user action to update.
//   UserActionRequest request The request that contains all of the new user action information.
func (c *FusionAuthClient) UpdateUserAction(userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
    var resp UserActionResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action").
             WithUriSegment(userActionId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateUserActionReason
// Updates the user action reason with the given Id.
//   string userActionReasonId The Id of the user action reason to update.
//   UserActionReasonRequest request The request that contains all of the new user action reason information.
func (c *FusionAuthClient) UpdateUserActionReason(userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
    var resp UserActionReasonResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user-action-reason").
             WithUriSegment(userActionReasonId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateUserConsent
// Updates a single User consent by Id.
//   string userConsentId The User Consent Id
//   UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) UpdateUserConsent(userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
    var resp UserConsentResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/user/consent").
             WithUriSegment(userConsentId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// UpdateWebhook
// Updates the webhook with the given Id.
//   string webhookId The Id of the webhook to update.
//   WebhookRequest request The request that contains all of the new webhook information.
func (c *FusionAuthClient) UpdateWebhook(webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
    var resp WebhookResponse
    var errors Errors

    restClient := c.Start(&resp, &errors)
    err := restClient.WithUri("/api/webhook").
             WithUriSegment(webhookId).
             WithJSONBody(request).
             WithMethod(http.MethodPut).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// ValidateDevice
// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
//   string userCode The end-user verification code.
//   string clientId The client id.
func (c *FusionAuthClient) ValidateDevice(userCode string, clientId string) (*BaseHTTPResponse, error) {
    var resp BaseHTTPResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/oauth2/device/validate").
             WithParameter("user_code", userCode).
             WithParameter("client_id", clientId).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// ValidateJWT
// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
// signed and not expired.
// <p>
// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
//   string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) ValidateJWT(encodedJWT string) (*ValidateResponse, error) {
    var resp ValidateResponse

    err := c.StartAnonymous(&resp, nil).
             WithUri("/api/jwt/validate").
             WithAuthorization("JWT " + encodedJWT).
             WithMethod(http.MethodGet).
             Do()
    return &resp, err
}

// VerifyEmail
// Confirms a email verification. The Id given is usually from an email sent to the user.
//   string verificationId The email verification id sent to the user.
func (c *FusionAuthClient) VerifyEmail(verificationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/user/verify-email").
             WithUriSegment(verificationId).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

// VerifyRegistration
// Confirms an application registration. The Id given is usually from an email sent to the user.
//   string verificationId The registration verification Id sent to the user.
func (c *FusionAuthClient) VerifyRegistration(verificationId string) (*BaseHTTPResponse, *Errors, error) {
    var resp BaseHTTPResponse
    var errors Errors

    restClient := c.StartAnonymous(&resp, &errors)
    err := restClient.WithUri("/api/user/verify-registration").
             WithUriSegment(verificationId).
             WithMethod(http.MethodPost).
             Do()
    if restClient.ErrorRef == nil {
      return &resp, nil, err
    }
    return &resp, &errors, err
}

