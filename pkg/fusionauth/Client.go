/*
* Copyright (c) 2019-2023, FusionAuth, All Rights Reserved
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// NewClient creates a new FusionAuthClient
// if httpClient is nil then a DefaultClient is used
func NewClient(httpClient *http.Client, baseURL *url.URL, apiKey string) *FusionAuthClient {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 5 * time.Minute,
		}
	}
	c := &FusionAuthClient{
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		APIKey:     apiKey,
	}

	return c
}

// SetTenantId sets the tenantId on the client
func (c *FusionAuthClient) SetTenantId(tenantId string) {
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

	rc.WithHeader("Accept", "application/json")
	return rc
}

func (rc *restClient) Do(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, rc.Method, rc.Uri.String(), rc.Body)
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
		if err = json.NewDecoder(resp.Body).Decode(rc.ErrorRef); err == io.EOF {
			err = nil
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
// "actioner". Both user ids are required in the request object.
//
//	ActionRequest request The action request that includes all the information about the action being taken including
//	the id of the action, any options and the duration (if applicable).
func (c *FusionAuthClient) ActionUser(request ActionRequest) (*ActionResponse, *Errors, error) {
	return c.ActionUserWithContext(context.TODO(), request)
}

// ActionUserWithContext
// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
// "actioner". Both user ids are required in the request object.
//
//	ActionRequest request The action request that includes all the information about the action being taken including
//	the id of the action, any options and the duration (if applicable).
func (c *FusionAuthClient) ActionUserWithContext(ctx context.Context, request ActionRequest) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ActivateReactor
// Activates the FusionAuth Reactor using a license id and optionally a license text (for air-gapped deployments)
//
//	ReactorRequest request An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).
func (c *FusionAuthClient) ActivateReactor(request ReactorRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ActivateReactorWithContext(context.TODO(), request)
}

// ActivateReactorWithContext
// Activates the FusionAuth Reactor using a license id and optionally a license text (for air-gapped deployments)
//
//	ReactorRequest request An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).
func (c *FusionAuthClient) ActivateReactorWithContext(ctx context.Context, request ReactorRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/reactor").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// AddUserToFamily
// Adds a user to an existing family. The family id must be specified.
//
//	string familyId The id of the family.
//	FamilyRequest request The request object that contains all the information used to determine which user to add to the family.
func (c *FusionAuthClient) AddUserToFamily(familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
	return c.AddUserToFamilyWithContext(context.TODO(), familyId, request)
}

// AddUserToFamilyWithContext
// Adds a user to an existing family. The family id must be specified.
//
//	string familyId The id of the family.
//	FamilyRequest request The request object that contains all the information used to determine which user to add to the family.
func (c *FusionAuthClient) AddUserToFamilyWithContext(ctx context.Context, familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
	var resp FamilyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/family").
		WithUriSegment(familyId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ApproveDevice
// Approve a device grant.
//
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
//	string clientSecret (Optional) The client secret. This value will be required if client authentication is enabled.
//	string token The access token used to identify the user.
//	string userCode The end-user verification code.
func (c *FusionAuthClient) ApproveDevice(clientId string, clientSecret string, token string, userCode string) (*DeviceApprovalResponse, *Errors, error) {
	return c.ApproveDeviceWithContext(context.TODO(), clientId, clientSecret, token, userCode)
}

// ApproveDeviceWithContext
// Approve a device grant.
//
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
//	string clientSecret (Optional) The client secret. This value will be required if client authentication is enabled.
//	string token The access token used to identify the user.
//	string userCode The end-user verification code.
func (c *FusionAuthClient) ApproveDeviceWithContext(ctx context.Context, clientId string, clientSecret string, token string, userCode string) (*DeviceApprovalResponse, *Errors, error) {
	var resp DeviceApprovalResponse
	var errors Errors
	formBody := url.Values{}
	formBody.Set("client_id", clientId)
	formBody.Set("client_secret", clientSecret)
	formBody.Set("token", token)
	formBody.Set("user_code", userCode)

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/oauth2/device/approve").
		WithFormData(formBody).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CancelAction
// Cancels the user action.
//
//	string actionId The action id of the action to cancel.
//	ActionRequest request The action request that contains the information about the cancellation.
func (c *FusionAuthClient) CancelAction(actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
	return c.CancelActionWithContext(context.TODO(), actionId, request)
}

// CancelActionWithContext
// Cancels the user action.
//
//	string actionId The action id of the action to cancel.
//	ActionRequest request The action request that contains the information about the cancellation.
func (c *FusionAuthClient) CancelActionWithContext(ctx context.Context, actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithUriSegment(actionId).
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ChangePassword
// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
// and they clicked on a link to reset their password.
//
// As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
// the value in the request body.
//
//	string changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
//	ChangePasswordRequest request The change password request that contains all the information used to change the password.
func (c *FusionAuthClient) ChangePassword(changePasswordId string, request ChangePasswordRequest) (*ChangePasswordResponse, *Errors, error) {
	return c.ChangePasswordWithContext(context.TODO(), changePasswordId, request)
}

// ChangePasswordWithContext
// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
// and they clicked on a link to reset their password.
//
// As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
// the value in the request body.
//
//	string changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
//	ChangePasswordRequest request The change password request that contains all the information used to change the password.
func (c *FusionAuthClient) ChangePasswordWithContext(ctx context.Context, changePasswordId string, request ChangePasswordRequest) (*ChangePasswordResponse, *Errors, error) {
	var resp ChangePasswordResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/change-password").
		WithUriSegment(changePasswordId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ChangePasswordByIdentity
// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
// method.
//
//	ChangePasswordRequest request The change password request that contains all the information used to change the password.
func (c *FusionAuthClient) ChangePasswordByIdentity(request ChangePasswordRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ChangePasswordByIdentityWithContext(context.TODO(), request)
}

// ChangePasswordByIdentityWithContext
// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
// method.
//
//	ChangePasswordRequest request The change password request that contains all the information used to change the password.
func (c *FusionAuthClient) ChangePasswordByIdentityWithContext(ctx context.Context, request ChangePasswordRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/change-password").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CheckChangePasswordUsingId
// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
func (c *FusionAuthClient) CheckChangePasswordUsingId(changePasswordId string) (*BaseHTTPResponse, *Errors, error) {
	return c.CheckChangePasswordUsingIdWithContext(context.TODO(), changePasswordId)
}

// CheckChangePasswordUsingIdWithContext
// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
func (c *FusionAuthClient) CheckChangePasswordUsingIdWithContext(ctx context.Context, changePasswordId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/change-password").
		WithUriSegment(changePasswordId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CheckChangePasswordUsingJWT
// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) CheckChangePasswordUsingJWT(encodedJWT string) (*BaseHTTPResponse, *Errors, error) {
	return c.CheckChangePasswordUsingJWTWithContext(context.TODO(), encodedJWT)
}

// CheckChangePasswordUsingJWTWithContext
// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) CheckChangePasswordUsingJWTWithContext(ctx context.Context, encodedJWT string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/change-password").
		WithAuthorization("Bearer " + encodedJWT).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CheckChangePasswordUsingLoginId
// Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string loginId The loginId of the User that you intend to change the password for.
func (c *FusionAuthClient) CheckChangePasswordUsingLoginId(loginId string) (*BaseHTTPResponse, *Errors, error) {
	return c.CheckChangePasswordUsingLoginIdWithContext(context.TODO(), loginId)
}

// CheckChangePasswordUsingLoginIdWithContext
// Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
// your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
//
// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
//
//	string loginId The loginId of the User that you intend to change the password for.
func (c *FusionAuthClient) CheckChangePasswordUsingLoginIdWithContext(ctx context.Context, loginId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/change-password").
		WithParameter("username", loginId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ClientCredentialsGrant
// Make a Client Credentials grant request to obtain an access token.
//
//	string clientId (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret used to authenticate this request.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string scope (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.
func (c *FusionAuthClient) ClientCredentialsGrant(clientId string, clientSecret string, scope string) (*AccessToken, *OAuthError, error) {
	return c.ClientCredentialsGrantWithContext(context.TODO(), clientId, clientSecret, scope)
}

// ClientCredentialsGrantWithContext
// Make a Client Credentials grant request to obtain an access token.
//
//	string clientId (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret used to authenticate this request.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string scope (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.
func (c *FusionAuthClient) ClientCredentialsGrantWithContext(ctx context.Context, clientId string, clientSecret string, scope string) (*AccessToken, *OAuthError, error) {
	var resp AccessToken
	var errors OAuthError
	formBody := url.Values{}
	formBody.Set("client_id", clientId)
	formBody.Set("client_secret", clientSecret)
	formBody.Set("grant_type", "client_credentials")
	formBody.Set("scope", scope)

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/oauth2/token").
		WithFormData(formBody).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CommentOnUser
// Adds a comment to the user's account.
//
//	UserCommentRequest request The request object that contains all the information used to create the user comment.
func (c *FusionAuthClient) CommentOnUser(request UserCommentRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.CommentOnUserWithContext(context.TODO(), request)
}

// CommentOnUserWithContext
// Adds a comment to the user's account.
//
//	UserCommentRequest request The request object that contains all the information used to create the user comment.
func (c *FusionAuthClient) CommentOnUserWithContext(ctx context.Context, request UserCommentRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/comment").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CompleteWebAuthnAssertion
// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
//
//	WebAuthnLoginRequest request An object containing data necessary for completing the authentication ceremony
func (c *FusionAuthClient) CompleteWebAuthnAssertion(request WebAuthnLoginRequest) (*WebAuthnAssertResponse, *Errors, error) {
	return c.CompleteWebAuthnAssertionWithContext(context.TODO(), request)
}

// CompleteWebAuthnAssertionWithContext
// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
//
//	WebAuthnLoginRequest request An object containing data necessary for completing the authentication ceremony
func (c *FusionAuthClient) CompleteWebAuthnAssertionWithContext(ctx context.Context, request WebAuthnLoginRequest) (*WebAuthnAssertResponse, *Errors, error) {
	var resp WebAuthnAssertResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/assert").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CompleteWebAuthnLogin
// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
//
//	WebAuthnLoginRequest request An object containing data necessary for completing the authentication ceremony
func (c *FusionAuthClient) CompleteWebAuthnLogin(request WebAuthnLoginRequest) (*LoginResponse, *Errors, error) {
	return c.CompleteWebAuthnLoginWithContext(context.TODO(), request)
}

// CompleteWebAuthnLoginWithContext
// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
//
//	WebAuthnLoginRequest request An object containing data necessary for completing the authentication ceremony
func (c *FusionAuthClient) CompleteWebAuthnLoginWithContext(ctx context.Context, request WebAuthnLoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/login").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CompleteWebAuthnRegistration
// Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
//
//	WebAuthnRegisterCompleteRequest request An object containing data necessary for completing the registration ceremony
func (c *FusionAuthClient) CompleteWebAuthnRegistration(request WebAuthnRegisterCompleteRequest) (*WebAuthnRegisterCompleteResponse, *Errors, error) {
	return c.CompleteWebAuthnRegistrationWithContext(context.TODO(), request)
}

// CompleteWebAuthnRegistrationWithContext
// Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
//
//	WebAuthnRegisterCompleteRequest request An object containing data necessary for completing the registration ceremony
func (c *FusionAuthClient) CompleteWebAuthnRegistrationWithContext(ctx context.Context, request WebAuthnRegisterCompleteRequest) (*WebAuthnRegisterCompleteResponse, *Errors, error) {
	var resp WebAuthnRegisterCompleteResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/register/complete").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateAPIKey
// Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
// an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted
// to that API key.
//
// If an API key is locked to a tenant, it can only create API Keys for that same tenant.
//
//	string keyId (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.
//	APIKeyRequest request The request object that contains all the information needed to create the APIKey.
func (c *FusionAuthClient) CreateAPIKey(keyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	return c.CreateAPIKeyWithContext(context.TODO(), keyId, request)
}

// CreateAPIKeyWithContext
// Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
// an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted
// to that API key.
//
// If an API key is locked to a tenant, it can only create API Keys for that same tenant.
//
//	string keyId (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.
//	APIKeyRequest request The request object that contains all the information needed to create the APIKey.
func (c *FusionAuthClient) CreateAPIKeyWithContext(ctx context.Context, keyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	var resp APIKeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/api-key").
		WithUriSegment(keyId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateApplication
// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
//
//	string applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
//	ApplicationRequest request The request object that contains all the information used to create the application.
func (c *FusionAuthClient) CreateApplication(applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	return c.CreateApplicationWithContext(context.TODO(), applicationId, request)
}

// CreateApplicationWithContext
// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
//
//	string applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
//	ApplicationRequest request The request object that contains all the information used to create the application.
func (c *FusionAuthClient) CreateApplicationWithContext(ctx context.Context, applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateApplicationRole
// Creates a new role for an application. You must specify the id of the application you are creating the role for.
// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
//
//	string applicationId The Id of the application to create the role on.
//	string roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
//	ApplicationRequest request The request object that contains all the information used to create the application role.
func (c *FusionAuthClient) CreateApplicationRole(applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	return c.CreateApplicationRoleWithContext(context.TODO(), applicationId, roleId, request)
}

// CreateApplicationRoleWithContext
// Creates a new role for an application. You must specify the id of the application you are creating the role for.
// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
//
//	string applicationId The Id of the application to create the role on.
//	string roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
//	ApplicationRequest request The request object that contains all the information used to create the application role.
func (c *FusionAuthClient) CreateApplicationRoleWithContext(ctx context.Context, applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithUriSegment("role").
		WithUriSegment(roleId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateAuditLog
// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
//
//	AuditLogRequest request The request object that contains all the information used to create the audit log entry.
func (c *FusionAuthClient) CreateAuditLog(request AuditLogRequest) (*AuditLogResponse, *Errors, error) {
	return c.CreateAuditLogWithContext(context.TODO(), request)
}

// CreateAuditLogWithContext
// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
//
//	AuditLogRequest request The request object that contains all the information used to create the audit log entry.
func (c *FusionAuthClient) CreateAuditLogWithContext(ctx context.Context, request AuditLogRequest) (*AuditLogResponse, *Errors, error) {
	var resp AuditLogResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/audit-log").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateConnector
// Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
//
//	string connectorId (Optional) The Id for the connector. If not provided a secure random UUID will be generated.
//	ConnectorRequest request The request object that contains all the information used to create the connector.
func (c *FusionAuthClient) CreateConnector(connectorId string, request ConnectorRequest) (*ConnectorResponse, *Errors, error) {
	return c.CreateConnectorWithContext(context.TODO(), connectorId, request)
}

// CreateConnectorWithContext
// Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
//
//	string connectorId (Optional) The Id for the connector. If not provided a secure random UUID will be generated.
//	ConnectorRequest request The request object that contains all the information used to create the connector.
func (c *FusionAuthClient) CreateConnectorWithContext(ctx context.Context, connectorId string, request ConnectorRequest) (*ConnectorResponse, *Errors, error) {
	var resp ConnectorResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/connector").
		WithUriSegment(connectorId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateConsent
// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
//
//	string consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
//	ConsentRequest request The request object that contains all the information used to create the consent.
func (c *FusionAuthClient) CreateConsent(consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
	return c.CreateConsentWithContext(context.TODO(), consentId, request)
}

// CreateConsentWithContext
// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
//
//	string consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
//	ConsentRequest request The request object that contains all the information used to create the consent.
func (c *FusionAuthClient) CreateConsentWithContext(ctx context.Context, consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
	var resp ConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/consent").
		WithUriSegment(consentId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateEmailTemplate
// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
//
//	string emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
//	EmailTemplateRequest request The request object that contains all the information used to create the email template.
func (c *FusionAuthClient) CreateEmailTemplate(emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
	return c.CreateEmailTemplateWithContext(context.TODO(), emailTemplateId, request)
}

// CreateEmailTemplateWithContext
// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
//
//	string emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
//	EmailTemplateRequest request The request object that contains all the information used to create the email template.
func (c *FusionAuthClient) CreateEmailTemplateWithContext(ctx context.Context, emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
	var resp EmailTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template").
		WithUriSegment(emailTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateEntity
// Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
//
//	string entityId (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.
//	EntityRequest request The request object that contains all the information used to create the Entity.
func (c *FusionAuthClient) CreateEntity(entityId string, request EntityRequest) (*EntityResponse, *Errors, error) {
	return c.CreateEntityWithContext(context.TODO(), entityId, request)
}

// CreateEntityWithContext
// Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
//
//	string entityId (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.
//	EntityRequest request The request object that contains all the information used to create the Entity.
func (c *FusionAuthClient) CreateEntityWithContext(ctx context.Context, entityId string, request EntityRequest) (*EntityResponse, *Errors, error) {
	var resp EntityResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateEntityType
// Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
//
//	string entityTypeId (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.
//	EntityTypeRequest request The request object that contains all the information used to create the Entity Type.
func (c *FusionAuthClient) CreateEntityType(entityTypeId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	return c.CreateEntityTypeWithContext(context.TODO(), entityTypeId, request)
}

// CreateEntityTypeWithContext
// Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
//
//	string entityTypeId (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.
//	EntityTypeRequest request The request object that contains all the information used to create the Entity Type.
func (c *FusionAuthClient) CreateEntityTypeWithContext(ctx context.Context, entityTypeId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateEntityTypePermission
// Creates a new permission for an entity type. You must specify the id of the entity type you are creating the permission for.
// You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
//
//	string entityTypeId The Id of the entity type to create the permission on.
//	string permissionId (Optional) The Id of the permission. If not provided a secure random UUID will be generated.
//	EntityTypeRequest request The request object that contains all the information used to create the permission.
func (c *FusionAuthClient) CreateEntityTypePermission(entityTypeId string, permissionId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	return c.CreateEntityTypePermissionWithContext(context.TODO(), entityTypeId, permissionId, request)
}

// CreateEntityTypePermissionWithContext
// Creates a new permission for an entity type. You must specify the id of the entity type you are creating the permission for.
// You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
//
//	string entityTypeId The Id of the entity type to create the permission on.
//	string permissionId (Optional) The Id of the permission. If not provided a secure random UUID will be generated.
//	EntityTypeRequest request The request object that contains all the information used to create the permission.
func (c *FusionAuthClient) CreateEntityTypePermissionWithContext(ctx context.Context, entityTypeId string, permissionId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithUriSegment("permission").
		WithUriSegment(permissionId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateFamily
// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
// family, if not provided one will be generated.
//
//	string familyId (Optional) The id for the family. If not provided a secure random UUID will be generated.
//	FamilyRequest request The request object that contains all the information used to create the family.
func (c *FusionAuthClient) CreateFamily(familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
	return c.CreateFamilyWithContext(context.TODO(), familyId, request)
}

// CreateFamilyWithContext
// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
// family, if not provided one will be generated.
//
//	string familyId (Optional) The id for the family. If not provided a secure random UUID will be generated.
//	FamilyRequest request The request object that contains all the information used to create the family.
func (c *FusionAuthClient) CreateFamilyWithContext(ctx context.Context, familyId string, request FamilyRequest) (*FamilyResponse, *Errors, error) {
	var resp FamilyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/family").
		WithUriSegment(familyId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateForm
// Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
//
//	string formId (Optional) The Id for the form. If not provided a secure random UUID will be generated.
//	FormRequest request The request object that contains all the information used to create the form.
func (c *FusionAuthClient) CreateForm(formId string, request FormRequest) (*FormResponse, *Errors, error) {
	return c.CreateFormWithContext(context.TODO(), formId, request)
}

// CreateFormWithContext
// Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
//
//	string formId (Optional) The Id for the form. If not provided a secure random UUID will be generated.
//	FormRequest request The request object that contains all the information used to create the form.
func (c *FusionAuthClient) CreateFormWithContext(ctx context.Context, formId string, request FormRequest) (*FormResponse, *Errors, error) {
	var resp FormResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form").
		WithUriSegment(formId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateFormField
// Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
//
//	string fieldId (Optional) The Id for the form field. If not provided a secure random UUID will be generated.
//	FormFieldRequest request The request object that contains all the information used to create the form field.
func (c *FusionAuthClient) CreateFormField(fieldId string, request FormFieldRequest) (*FormFieldResponse, *Errors, error) {
	return c.CreateFormFieldWithContext(context.TODO(), fieldId, request)
}

// CreateFormFieldWithContext
// Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
//
//	string fieldId (Optional) The Id for the form field. If not provided a secure random UUID will be generated.
//	FormFieldRequest request The request object that contains all the information used to create the form field.
func (c *FusionAuthClient) CreateFormFieldWithContext(ctx context.Context, fieldId string, request FormFieldRequest) (*FormFieldResponse, *Errors, error) {
	var resp FormFieldResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form/field").
		WithUriSegment(fieldId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateGroup
// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
//
//	string groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
//	GroupRequest request The request object that contains all the information used to create the group.
func (c *FusionAuthClient) CreateGroup(groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
	return c.CreateGroupWithContext(context.TODO(), groupId, request)
}

// CreateGroupWithContext
// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
//
//	string groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
//	GroupRequest request The request object that contains all the information used to create the group.
func (c *FusionAuthClient) CreateGroupWithContext(ctx context.Context, groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
	var resp GroupResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group").
		WithUriSegment(groupId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateGroupMembers
// Creates a member in a group.
//
//	MemberRequest request The request object that contains all the information used to create the group member(s).
func (c *FusionAuthClient) CreateGroupMembers(request MemberRequest) (*MemberResponse, *Errors, error) {
	return c.CreateGroupMembersWithContext(context.TODO(), request)
}

// CreateGroupMembersWithContext
// Creates a member in a group.
//
//	MemberRequest request The request object that contains all the information used to create the group member(s).
func (c *FusionAuthClient) CreateGroupMembersWithContext(ctx context.Context, request MemberRequest) (*MemberResponse, *Errors, error) {
	var resp MemberResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group/member").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateIPAccessControlList
// Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
//
//	string accessControlListId (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.
//	IPAccessControlListRequest request The request object that contains all the information used to create the IP Access Control List.
func (c *FusionAuthClient) CreateIPAccessControlList(accessControlListId string, request IPAccessControlListRequest) (*IPAccessControlListResponse, *Errors, error) {
	return c.CreateIPAccessControlListWithContext(context.TODO(), accessControlListId, request)
}

// CreateIPAccessControlListWithContext
// Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
//
//	string accessControlListId (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.
//	IPAccessControlListRequest request The request object that contains all the information used to create the IP Access Control List.
func (c *FusionAuthClient) CreateIPAccessControlListWithContext(ctx context.Context, accessControlListId string, request IPAccessControlListRequest) (*IPAccessControlListResponse, *Errors, error) {
	var resp IPAccessControlListResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/ip-acl").
		WithUriSegment(accessControlListId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateLambda
// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
//
//	string lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
//	LambdaRequest request The request object that contains all the information used to create the lambda.
func (c *FusionAuthClient) CreateLambda(lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
	return c.CreateLambdaWithContext(context.TODO(), lambdaId, request)
}

// CreateLambdaWithContext
// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
//
//	string lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
//	LambdaRequest request The request object that contains all the information used to create the lambda.
func (c *FusionAuthClient) CreateLambdaWithContext(ctx context.Context, lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
	var resp LambdaResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda").
		WithUriSegment(lambdaId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateMessageTemplate
// Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
//
//	string messageTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
//	MessageTemplateRequest request The request object that contains all the information used to create the message template.
func (c *FusionAuthClient) CreateMessageTemplate(messageTemplateId string, request MessageTemplateRequest) (*MessageTemplateResponse, *Errors, error) {
	return c.CreateMessageTemplateWithContext(context.TODO(), messageTemplateId, request)
}

// CreateMessageTemplateWithContext
// Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
//
//	string messageTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
//	MessageTemplateRequest request The request object that contains all the information used to create the message template.
func (c *FusionAuthClient) CreateMessageTemplateWithContext(ctx context.Context, messageTemplateId string, request MessageTemplateRequest) (*MessageTemplateResponse, *Errors, error) {
	var resp MessageTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/message/template").
		WithUriSegment(messageTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateMessenger
// Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
//
//	string messengerId (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.
//	MessengerRequest request The request object that contains all the information used to create the messenger.
func (c *FusionAuthClient) CreateMessenger(messengerId string, request MessengerRequest) (*MessengerResponse, *Errors, error) {
	return c.CreateMessengerWithContext(context.TODO(), messengerId, request)
}

// CreateMessengerWithContext
// Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
//
//	string messengerId (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.
//	MessengerRequest request The request object that contains all the information used to create the messenger.
func (c *FusionAuthClient) CreateMessengerWithContext(ctx context.Context, messengerId string, request MessengerRequest) (*MessengerResponse, *Errors, error) {
	var resp MessengerResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/messenger").
		WithUriSegment(messengerId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateTenant
// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
//
//	string tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
//	TenantRequest request The request object that contains all the information used to create the tenant.
func (c *FusionAuthClient) CreateTenant(tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
	return c.CreateTenantWithContext(context.TODO(), tenantId, request)
}

// CreateTenantWithContext
// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
//
//	string tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
//	TenantRequest request The request object that contains all the information used to create the tenant.
func (c *FusionAuthClient) CreateTenantWithContext(ctx context.Context, tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
	var resp TenantResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateTheme
// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
//
//	string themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
//	ThemeRequest request The request object that contains all the information used to create the theme.
func (c *FusionAuthClient) CreateTheme(themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
	return c.CreateThemeWithContext(context.TODO(), themeId, request)
}

// CreateThemeWithContext
// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
//
//	string themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
//	ThemeRequest request The request object that contains all the information used to create the theme.
func (c *FusionAuthClient) CreateThemeWithContext(ctx context.Context, themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
	var resp ThemeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme").
		WithUriSegment(themeId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateUser
// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
//
//	string userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
//	UserRequest request The request object that contains all the information used to create the user.
func (c *FusionAuthClient) CreateUser(userId string, request UserRequest) (*UserResponse, *Errors, error) {
	return c.CreateUserWithContext(context.TODO(), userId, request)
}

// CreateUserWithContext
// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
//
//	string userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
//	UserRequest request The request object that contains all the information used to create the user.
func (c *FusionAuthClient) CreateUserWithContext(ctx context.Context, userId string, request UserRequest) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateUserAction
// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
// that the user action can be applied to any user.
//
//	string userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
//	UserActionRequest request The request object that contains all the information used to create the user action.
func (c *FusionAuthClient) CreateUserAction(userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
	return c.CreateUserActionWithContext(context.TODO(), userActionId, request)
}

// CreateUserActionWithContext
// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
// that the user action can be applied to any user.
//
//	string userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
//	UserActionRequest request The request object that contains all the information used to create the user action.
func (c *FusionAuthClient) CreateUserActionWithContext(ctx context.Context, userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
	var resp UserActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateUserActionReason
// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
// successfully. Anytime after that the user action reason can be used.
//
//	string userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
//	UserActionReasonRequest request The request object that contains all the information used to create the user action reason.
func (c *FusionAuthClient) CreateUserActionReason(userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
	return c.CreateUserActionReasonWithContext(context.TODO(), userActionReasonId, request)
}

// CreateUserActionReasonWithContext
// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
// successfully. Anytime after that the user action reason can be used.
//
//	string userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
//	UserActionReasonRequest request The request object that contains all the information used to create the user action reason.
func (c *FusionAuthClient) CreateUserActionReasonWithContext(ctx context.Context, userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
	var resp UserActionReasonResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action-reason").
		WithUriSegment(userActionReasonId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateUserConsent
// Creates a single User consent.
//
//	string userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
//	UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) CreateUserConsent(userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
	return c.CreateUserConsentWithContext(context.TODO(), userConsentId, request)
}

// CreateUserConsentWithContext
// Creates a single User consent.
//
//	string userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
//	UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) CreateUserConsentWithContext(ctx context.Context, userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
	var resp UserConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/consent").
		WithUriSegment(userConsentId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateUserLink
// Link an external user from a 3rd party identity provider to a FusionAuth user.
//
//	IdentityProviderLinkRequest request The request object that contains all the information used to link the FusionAuth user.
func (c *FusionAuthClient) CreateUserLink(request IdentityProviderLinkRequest) (*IdentityProviderLinkResponse, *Errors, error) {
	return c.CreateUserLinkWithContext(context.TODO(), request)
}

// CreateUserLinkWithContext
// Link an external user from a 3rd party identity provider to a FusionAuth user.
//
//	IdentityProviderLinkRequest request The request object that contains all the information used to link the FusionAuth user.
func (c *FusionAuthClient) CreateUserLinkWithContext(ctx context.Context, request IdentityProviderLinkRequest) (*IdentityProviderLinkResponse, *Errors, error) {
	var resp IdentityProviderLinkResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/link").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// CreateWebhook
// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
//
//	string webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
//	WebhookRequest request The request object that contains all the information used to create the webhook.
func (c *FusionAuthClient) CreateWebhook(webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
	return c.CreateWebhookWithContext(context.TODO(), webhookId, request)
}

// CreateWebhookWithContext
// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
//
//	string webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
//	WebhookRequest request The request object that contains all the information used to create the webhook.
func (c *FusionAuthClient) CreateWebhookWithContext(ctx context.Context, webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
	var resp WebhookResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webhook").
		WithUriSegment(webhookId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeactivateApplication
// Deactivates the application with the given Id.
//
//	string applicationId The Id of the application to deactivate.
func (c *FusionAuthClient) DeactivateApplication(applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeactivateApplicationWithContext(context.TODO(), applicationId)
}

// DeactivateApplicationWithContext
// Deactivates the application with the given Id.
//
//	string applicationId The Id of the application to deactivate.
func (c *FusionAuthClient) DeactivateApplicationWithContext(ctx context.Context, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeactivateReactor
// Deactivates the FusionAuth Reactor.
func (c *FusionAuthClient) DeactivateReactor() (*BaseHTTPResponse, error) {
	return c.DeactivateReactorWithContext(context.TODO())
}

// DeactivateReactorWithContext
// Deactivates the FusionAuth Reactor.
func (c *FusionAuthClient) DeactivateReactorWithContext(ctx context.Context) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.Start(&resp, nil).
		WithUri("/api/reactor").
		WithMethod(http.MethodDelete).
		Do(ctx)
	return &resp, err
}

// DeactivateUser
// Deactivates the user with the given Id.
//
//	string userId The Id of the user to deactivate.
func (c *FusionAuthClient) DeactivateUser(userId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeactivateUserWithContext(context.TODO(), userId)
}

// DeactivateUserWithContext
// Deactivates the user with the given Id.
//
//	string userId The Id of the user to deactivate.
func (c *FusionAuthClient) DeactivateUserWithContext(ctx context.Context, userId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeactivateUserAction
// Deactivates the user action with the given Id.
//
//	string userActionId The Id of the user action to deactivate.
func (c *FusionAuthClient) DeactivateUserAction(userActionId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeactivateUserActionWithContext(context.TODO(), userActionId)
}

// DeactivateUserActionWithContext
// Deactivates the user action with the given Id.
//
//	string userActionId The Id of the user action to deactivate.
func (c *FusionAuthClient) DeactivateUserActionWithContext(ctx context.Context, userActionId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeactivateUsers
// Deactivates the users with the given ids.
//
//	[]string userIds The ids of the users to deactivate.
//
// Deprecated: This method has been renamed to DeactivateUsersByIds, use that method instead.
func (c *FusionAuthClient) DeactivateUsers(userIds []string) (*UserDeleteResponse, *Errors, error) {
	return c.DeactivateUsersWithContext(context.TODO(), userIds)
}

// DeactivateUsersWithContext
// Deactivates the users with the given ids.
//
//	[]string userIds The ids of the users to deactivate.
//
// Deprecated: This method has been renamed to DeactivateUsersByIdsWithContext, use that method instead.
func (c *FusionAuthClient) DeactivateUsersWithContext(ctx context.Context, userIds []string) (*UserDeleteResponse, *Errors, error) {
	var resp UserDeleteResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/bulk").
		WithParameter("userId", userIds).
		WithParameter("dryRun", strconv.FormatBool(false)).
		WithParameter("hardDelete", strconv.FormatBool(false)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeactivateUsersByIds
// Deactivates the users with the given ids.
//
//	[]string userIds The ids of the users to deactivate.
func (c *FusionAuthClient) DeactivateUsersByIds(userIds []string) (*UserDeleteResponse, *Errors, error) {
	return c.DeactivateUsersByIdsWithContext(context.TODO(), userIds)
}

// DeactivateUsersByIdsWithContext
// Deactivates the users with the given ids.
//
//	[]string userIds The ids of the users to deactivate.
func (c *FusionAuthClient) DeactivateUsersByIdsWithContext(ctx context.Context, userIds []string) (*UserDeleteResponse, *Errors, error) {
	var resp UserDeleteResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/bulk").
		WithParameter("userId", userIds).
		WithParameter("dryRun", strconv.FormatBool(false)).
		WithParameter("hardDelete", strconv.FormatBool(false)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteAPIKey
// Deletes the API key for the given Id.
//
//	string keyId The Id of the authentication API key to delete.
func (c *FusionAuthClient) DeleteAPIKey(keyId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteAPIKeyWithContext(context.TODO(), keyId)
}

// DeleteAPIKeyWithContext
// Deletes the API key for the given Id.
//
//	string keyId The Id of the authentication API key to delete.
func (c *FusionAuthClient) DeleteAPIKeyWithContext(ctx context.Context, keyId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/api-key").
		WithUriSegment(keyId).
		WithMethod(http.MethodDelete).
		Do(ctx)
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
//
//	string applicationId The Id of the application to delete.
func (c *FusionAuthClient) DeleteApplication(applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteApplicationWithContext(context.TODO(), applicationId)
}

// DeleteApplicationWithContext
// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
// delete the application, any registrations for that application, metrics and reports for the application, all the
// roles for the application, and any other data associated with the application. This operation could take a very
// long time, depending on the amount of data in your database.
//
//	string applicationId The Id of the application to delete.
func (c *FusionAuthClient) DeleteApplicationWithContext(ctx context.Context, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithParameter("hardDelete", strconv.FormatBool(true)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteApplicationRole
// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
// permanently removes the given role from all users that had it.
//
//	string applicationId The Id of the application to deactivate.
//	string roleId The Id of the role to delete.
func (c *FusionAuthClient) DeleteApplicationRole(applicationId string, roleId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteApplicationRoleWithContext(context.TODO(), applicationId, roleId)
}

// DeleteApplicationRoleWithContext
// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
// permanently removes the given role from all users that had it.
//
//	string applicationId The Id of the application to deactivate.
//	string roleId The Id of the role to delete.
func (c *FusionAuthClient) DeleteApplicationRoleWithContext(ctx context.Context, applicationId string, roleId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithUriSegment("role").
		WithUriSegment(roleId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteConnector
// Deletes the connector for the given Id.
//
//	string connectorId The Id of the connector to delete.
func (c *FusionAuthClient) DeleteConnector(connectorId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteConnectorWithContext(context.TODO(), connectorId)
}

// DeleteConnectorWithContext
// Deletes the connector for the given Id.
//
//	string connectorId The Id of the connector to delete.
func (c *FusionAuthClient) DeleteConnectorWithContext(ctx context.Context, connectorId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/connector").
		WithUriSegment(connectorId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteConsent
// Deletes the consent for the given Id.
//
//	string consentId The Id of the consent to delete.
func (c *FusionAuthClient) DeleteConsent(consentId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteConsentWithContext(context.TODO(), consentId)
}

// DeleteConsentWithContext
// Deletes the consent for the given Id.
//
//	string consentId The Id of the consent to delete.
func (c *FusionAuthClient) DeleteConsentWithContext(ctx context.Context, consentId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/consent").
		WithUriSegment(consentId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteEmailTemplate
// Deletes the email template for the given Id.
//
//	string emailTemplateId The Id of the email template to delete.
func (c *FusionAuthClient) DeleteEmailTemplate(emailTemplateId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteEmailTemplateWithContext(context.TODO(), emailTemplateId)
}

// DeleteEmailTemplateWithContext
// Deletes the email template for the given Id.
//
//	string emailTemplateId The Id of the email template to delete.
func (c *FusionAuthClient) DeleteEmailTemplateWithContext(ctx context.Context, emailTemplateId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template").
		WithUriSegment(emailTemplateId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteEntity
// Deletes the Entity for the given Id.
//
//	string entityId The Id of the Entity to delete.
func (c *FusionAuthClient) DeleteEntity(entityId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteEntityWithContext(context.TODO(), entityId)
}

// DeleteEntityWithContext
// Deletes the Entity for the given Id.
//
//	string entityId The Id of the Entity to delete.
func (c *FusionAuthClient) DeleteEntityWithContext(ctx context.Context, entityId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteEntityGrant
// Deletes an Entity Grant for the given User or Entity.
//
//	string entityId The Id of the Entity that the Entity Grant is being deleted for.
//	string recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
//	string userId (Optional) The Id of the User that the Entity Grant is for.
func (c *FusionAuthClient) DeleteEntityGrant(entityId string, recipientEntityId string, userId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteEntityGrantWithContext(context.TODO(), entityId, recipientEntityId, userId)
}

// DeleteEntityGrantWithContext
// Deletes an Entity Grant for the given User or Entity.
//
//	string entityId The Id of the Entity that the Entity Grant is being deleted for.
//	string recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
//	string userId (Optional) The Id of the User that the Entity Grant is for.
func (c *FusionAuthClient) DeleteEntityGrantWithContext(ctx context.Context, entityId string, recipientEntityId string, userId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithUriSegment("grant").
		WithParameter("recipientEntityId", recipientEntityId).
		WithParameter("userId", userId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteEntityType
// Deletes the Entity Type for the given Id.
//
//	string entityTypeId The Id of the Entity Type to delete.
func (c *FusionAuthClient) DeleteEntityType(entityTypeId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteEntityTypeWithContext(context.TODO(), entityTypeId)
}

// DeleteEntityTypeWithContext
// Deletes the Entity Type for the given Id.
//
//	string entityTypeId The Id of the Entity Type to delete.
func (c *FusionAuthClient) DeleteEntityTypeWithContext(ctx context.Context, entityTypeId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteEntityTypePermission
// Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
// permanently removes the given permission from all grants that had it.
//
//	string entityTypeId The Id of the entityType the the permission belongs to.
//	string permissionId The Id of the permission to delete.
func (c *FusionAuthClient) DeleteEntityTypePermission(entityTypeId string, permissionId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteEntityTypePermissionWithContext(context.TODO(), entityTypeId, permissionId)
}

// DeleteEntityTypePermissionWithContext
// Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
// permanently removes the given permission from all grants that had it.
//
//	string entityTypeId The Id of the entityType the the permission belongs to.
//	string permissionId The Id of the permission to delete.
func (c *FusionAuthClient) DeleteEntityTypePermissionWithContext(ctx context.Context, entityTypeId string, permissionId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithUriSegment("permission").
		WithUriSegment(permissionId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteForm
// Deletes the form for the given Id.
//
//	string formId The Id of the form to delete.
func (c *FusionAuthClient) DeleteForm(formId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteFormWithContext(context.TODO(), formId)
}

// DeleteFormWithContext
// Deletes the form for the given Id.
//
//	string formId The Id of the form to delete.
func (c *FusionAuthClient) DeleteFormWithContext(ctx context.Context, formId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form").
		WithUriSegment(formId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteFormField
// Deletes the form field for the given Id.
//
//	string fieldId The Id of the form field to delete.
func (c *FusionAuthClient) DeleteFormField(fieldId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteFormFieldWithContext(context.TODO(), fieldId)
}

// DeleteFormFieldWithContext
// Deletes the form field for the given Id.
//
//	string fieldId The Id of the form field to delete.
func (c *FusionAuthClient) DeleteFormFieldWithContext(ctx context.Context, fieldId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form/field").
		WithUriSegment(fieldId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteGroup
// Deletes the group for the given Id.
//
//	string groupId The Id of the group to delete.
func (c *FusionAuthClient) DeleteGroup(groupId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteGroupWithContext(context.TODO(), groupId)
}

// DeleteGroupWithContext
// Deletes the group for the given Id.
//
//	string groupId The Id of the group to delete.
func (c *FusionAuthClient) DeleteGroupWithContext(ctx context.Context, groupId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group").
		WithUriSegment(groupId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteGroupMembers
// Removes users as members of a group.
//
//	MemberDeleteRequest request The member request that contains all the information used to remove members to the group.
func (c *FusionAuthClient) DeleteGroupMembers(request MemberDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteGroupMembersWithContext(context.TODO(), request)
}

// DeleteGroupMembersWithContext
// Removes users as members of a group.
//
//	MemberDeleteRequest request The member request that contains all the information used to remove members to the group.
func (c *FusionAuthClient) DeleteGroupMembersWithContext(ctx context.Context, request MemberDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group/member").
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteIPAccessControlList
// Deletes the IP Access Control List for the given Id.
//
//	string ipAccessControlListId The Id of the IP Access Control List to delete.
func (c *FusionAuthClient) DeleteIPAccessControlList(ipAccessControlListId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteIPAccessControlListWithContext(context.TODO(), ipAccessControlListId)
}

// DeleteIPAccessControlListWithContext
// Deletes the IP Access Control List for the given Id.
//
//	string ipAccessControlListId The Id of the IP Access Control List to delete.
func (c *FusionAuthClient) DeleteIPAccessControlListWithContext(ctx context.Context, ipAccessControlListId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/ip-acl").
		WithUriSegment(ipAccessControlListId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteIdentityProvider
// Deletes the identity provider for the given Id.
//
//	string identityProviderId The Id of the identity provider to delete.
func (c *FusionAuthClient) DeleteIdentityProvider(identityProviderId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteIdentityProviderWithContext(context.TODO(), identityProviderId)
}

// DeleteIdentityProviderWithContext
// Deletes the identity provider for the given Id.
//
//	string identityProviderId The Id of the identity provider to delete.
func (c *FusionAuthClient) DeleteIdentityProviderWithContext(ctx context.Context, identityProviderId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider").
		WithUriSegment(identityProviderId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteKey
// Deletes the key for the given Id.
//
//	string keyId The Id of the key to delete.
func (c *FusionAuthClient) DeleteKey(keyId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteKeyWithContext(context.TODO(), keyId)
}

// DeleteKeyWithContext
// Deletes the key for the given Id.
//
//	string keyId The Id of the key to delete.
func (c *FusionAuthClient) DeleteKeyWithContext(ctx context.Context, keyId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key").
		WithUriSegment(keyId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteLambda
// Deletes the lambda for the given Id.
//
//	string lambdaId The Id of the lambda to delete.
func (c *FusionAuthClient) DeleteLambda(lambdaId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteLambdaWithContext(context.TODO(), lambdaId)
}

// DeleteLambdaWithContext
// Deletes the lambda for the given Id.
//
//	string lambdaId The Id of the lambda to delete.
func (c *FusionAuthClient) DeleteLambdaWithContext(ctx context.Context, lambdaId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda").
		WithUriSegment(lambdaId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteMessageTemplate
// Deletes the message template for the given Id.
//
//	string messageTemplateId The Id of the message template to delete.
func (c *FusionAuthClient) DeleteMessageTemplate(messageTemplateId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteMessageTemplateWithContext(context.TODO(), messageTemplateId)
}

// DeleteMessageTemplateWithContext
// Deletes the message template for the given Id.
//
//	string messageTemplateId The Id of the message template to delete.
func (c *FusionAuthClient) DeleteMessageTemplateWithContext(ctx context.Context, messageTemplateId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/message/template").
		WithUriSegment(messageTemplateId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteMessenger
// Deletes the messenger for the given Id.
//
//	string messengerId The Id of the messenger to delete.
func (c *FusionAuthClient) DeleteMessenger(messengerId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteMessengerWithContext(context.TODO(), messengerId)
}

// DeleteMessengerWithContext
// Deletes the messenger for the given Id.
//
//	string messengerId The Id of the messenger to delete.
func (c *FusionAuthClient) DeleteMessengerWithContext(ctx context.Context, messengerId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/messenger").
		WithUriSegment(messengerId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteRegistration
// Deletes the user registration for the given user and application.
//
//	string userId The Id of the user whose registration is being deleted.
//	string applicationId The Id of the application to remove the registration for.
func (c *FusionAuthClient) DeleteRegistration(userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteRegistrationWithContext(context.TODO(), userId, applicationId)
}

// DeleteRegistrationWithContext
// Deletes the user registration for the given user and application.
//
//	string userId The Id of the user whose registration is being deleted.
//	string applicationId The Id of the application to remove the registration for.
func (c *FusionAuthClient) DeleteRegistrationWithContext(ctx context.Context, userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithUriSegment(applicationId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteRegistrationWithRequest
// Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
//
//	string userId The Id of the user whose registration is being deleted.
//	string applicationId The Id of the application to remove the registration for.
//	RegistrationDeleteRequest request The request body that contains the event information.
func (c *FusionAuthClient) DeleteRegistrationWithRequest(userId string, applicationId string, request RegistrationDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteRegistrationWithRequestWithContext(context.TODO(), userId, applicationId, request)
}

// DeleteRegistrationWithRequestWithContext
// Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
//
//	string userId The Id of the user whose registration is being deleted.
//	string applicationId The Id of the application to remove the registration for.
//	RegistrationDeleteRequest request The request body that contains the event information.
func (c *FusionAuthClient) DeleteRegistrationWithRequestWithContext(ctx context.Context, userId string, applicationId string, request RegistrationDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithUriSegment(applicationId).
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteTenant
// Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
// with the tenant and everything under the tenant (applications, users, etc).
//
//	string tenantId The Id of the tenant to delete.
func (c *FusionAuthClient) DeleteTenant(tenantId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteTenantWithContext(context.TODO(), tenantId)
}

// DeleteTenantWithContext
// Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
// with the tenant and everything under the tenant (applications, users, etc).
//
//	string tenantId The Id of the tenant to delete.
func (c *FusionAuthClient) DeleteTenantWithContext(ctx context.Context, tenantId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteTenantAsync
// Deletes the tenant for the given Id asynchronously.
// This method is helpful if you do not want to wait for the delete operation to complete.
//
//	string tenantId The Id of the tenant to delete.
func (c *FusionAuthClient) DeleteTenantAsync(tenantId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteTenantAsyncWithContext(context.TODO(), tenantId)
}

// DeleteTenantAsyncWithContext
// Deletes the tenant for the given Id asynchronously.
// This method is helpful if you do not want to wait for the delete operation to complete.
//
//	string tenantId The Id of the tenant to delete.
func (c *FusionAuthClient) DeleteTenantAsyncWithContext(ctx context.Context, tenantId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithParameter("async", strconv.FormatBool(true)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteTenantWithRequest
// Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
// with the tenant and everything under the tenant (applications, users, etc).
//
//	string tenantId The Id of the tenant to delete.
//	TenantDeleteRequest request The request object that contains all the information used to delete the user.
func (c *FusionAuthClient) DeleteTenantWithRequest(tenantId string, request TenantDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteTenantWithRequestWithContext(context.TODO(), tenantId, request)
}

// DeleteTenantWithRequestWithContext
// Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
// with the tenant and everything under the tenant (applications, users, etc).
//
//	string tenantId The Id of the tenant to delete.
//	TenantDeleteRequest request The request object that contains all the information used to delete the user.
func (c *FusionAuthClient) DeleteTenantWithRequestWithContext(ctx context.Context, tenantId string, request TenantDeleteRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteTheme
// Deletes the theme for the given Id.
//
//	string themeId The Id of the theme to delete.
func (c *FusionAuthClient) DeleteTheme(themeId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteThemeWithContext(context.TODO(), themeId)
}

// DeleteThemeWithContext
// Deletes the theme for the given Id.
//
//	string themeId The Id of the theme to delete.
func (c *FusionAuthClient) DeleteThemeWithContext(ctx context.Context, themeId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme").
		WithUriSegment(themeId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteUser
// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
// with the user.
//
//	string userId The Id of the user to delete.
func (c *FusionAuthClient) DeleteUser(userId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteUserWithContext(context.TODO(), userId)
}

// DeleteUserWithContext
// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
// with the user.
//
//	string userId The Id of the user to delete.
func (c *FusionAuthClient) DeleteUserWithContext(ctx context.Context, userId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithParameter("hardDelete", strconv.FormatBool(true)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteUserAction
// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
// the action being applied to any users.
//
//	string userActionId The Id of the user action to delete.
func (c *FusionAuthClient) DeleteUserAction(userActionId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteUserActionWithContext(context.TODO(), userActionId)
}

// DeleteUserActionWithContext
// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
// the action being applied to any users.
//
//	string userActionId The Id of the user action to delete.
func (c *FusionAuthClient) DeleteUserActionWithContext(ctx context.Context, userActionId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithParameter("hardDelete", strconv.FormatBool(true)).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteUserActionReason
// Deletes the user action reason for the given Id.
//
//	string userActionReasonId The Id of the user action reason to delete.
func (c *FusionAuthClient) DeleteUserActionReason(userActionReasonId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteUserActionReasonWithContext(context.TODO(), userActionReasonId)
}

// DeleteUserActionReasonWithContext
// Deletes the user action reason for the given Id.
//
//	string userActionReasonId The Id of the user action reason to delete.
func (c *FusionAuthClient) DeleteUserActionReasonWithContext(ctx context.Context, userActionReasonId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action-reason").
		WithUriSegment(userActionReasonId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteUserLink
// Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
//
//	string identityProviderId The unique Id of the identity provider.
//	string identityProviderUserId The unique Id of the user in the 3rd party identity provider to unlink.
//	string userId The unique Id of the FusionAuth user to unlink.
func (c *FusionAuthClient) DeleteUserLink(identityProviderId string, identityProviderUserId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	return c.DeleteUserLinkWithContext(context.TODO(), identityProviderId, identityProviderUserId, userId)
}

// DeleteUserLinkWithContext
// Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
//
//	string identityProviderId The unique Id of the identity provider.
//	string identityProviderUserId The unique Id of the user in the 3rd party identity provider to unlink.
//	string userId The unique Id of the FusionAuth user to unlink.
func (c *FusionAuthClient) DeleteUserLinkWithContext(ctx context.Context, identityProviderId string, identityProviderUserId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	var resp IdentityProviderLinkResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/link").
		WithParameter("identityProviderId", identityProviderId).
		WithParameter("identityProviderUserId", identityProviderUserId).
		WithParameter("userId", userId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteUserWithRequest
// Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
// with the user.
//
//	string userId The Id of the user to delete (required).
//	UserDeleteSingleRequest request The request object that contains all the information used to delete the user.
func (c *FusionAuthClient) DeleteUserWithRequest(userId string, request UserDeleteSingleRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteUserWithRequestWithContext(context.TODO(), userId, request)
}

// DeleteUserWithRequestWithContext
// Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
// with the user.
//
//	string userId The Id of the user to delete (required).
//	UserDeleteSingleRequest request The request object that contains all the information used to delete the user.
func (c *FusionAuthClient) DeleteUserWithRequestWithContext(ctx context.Context, userId string, request UserDeleteSingleRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
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
//
//	UserDeleteRequest request The UserDeleteRequest.
//
// Deprecated: This method has been renamed to DeleteUsersByQuery, use that method instead.
func (c *FusionAuthClient) DeleteUsers(request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
	return c.DeleteUsersWithContext(context.TODO(), request)
}

// DeleteUsersWithContext
// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
//
// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
//
//	UserDeleteRequest request The UserDeleteRequest.
//
// Deprecated: This method has been renamed to DeleteUsersByQueryWithContext, use that method instead.
func (c *FusionAuthClient) DeleteUsersWithContext(ctx context.Context, request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
	var resp UserDeleteResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/bulk").
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
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
//
//	UserDeleteRequest request The UserDeleteRequest.
func (c *FusionAuthClient) DeleteUsersByQuery(request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
	return c.DeleteUsersByQueryWithContext(context.TODO(), request)
}

// DeleteUsersByQueryWithContext
// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
//
// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
//
//	UserDeleteRequest request The UserDeleteRequest.
func (c *FusionAuthClient) DeleteUsersByQueryWithContext(ctx context.Context, request UserDeleteRequest) (*UserDeleteResponse, *Errors, error) {
	var resp UserDeleteResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/bulk").
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteWebAuthnCredential
// Deletes the WebAuthn credential for the given Id.
//
//	string id The Id of the WebAuthn credential to delete.
func (c *FusionAuthClient) DeleteWebAuthnCredential(id string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteWebAuthnCredentialWithContext(context.TODO(), id)
}

// DeleteWebAuthnCredentialWithContext
// Deletes the WebAuthn credential for the given Id.
//
//	string id The Id of the WebAuthn credential to delete.
func (c *FusionAuthClient) DeleteWebAuthnCredentialWithContext(ctx context.Context, id string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn").
		WithUriSegment(id).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DeleteWebhook
// Deletes the webhook for the given Id.
//
//	string webhookId The Id of the webhook to delete.
func (c *FusionAuthClient) DeleteWebhook(webhookId string) (*BaseHTTPResponse, *Errors, error) {
	return c.DeleteWebhookWithContext(context.TODO(), webhookId)
}

// DeleteWebhookWithContext
// Deletes the webhook for the given Id.
//
//	string webhookId The Id of the webhook to delete.
func (c *FusionAuthClient) DeleteWebhookWithContext(ctx context.Context, webhookId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webhook").
		WithUriSegment(webhookId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DisableTwoFactor
// Disable two-factor authentication for a user.
//
//	string userId The Id of the User for which you're disabling two-factor authentication.
//	string methodId The two-factor method identifier you wish to disable
//	string code The two-factor code used verify the the caller knows the two-factor secret.
func (c *FusionAuthClient) DisableTwoFactor(userId string, methodId string, code string) (*BaseHTTPResponse, *Errors, error) {
	return c.DisableTwoFactorWithContext(context.TODO(), userId, methodId, code)
}

// DisableTwoFactorWithContext
// Disable two-factor authentication for a user.
//
//	string userId The Id of the User for which you're disabling two-factor authentication.
//	string methodId The two-factor method identifier you wish to disable
//	string code The two-factor code used verify the the caller knows the two-factor secret.
func (c *FusionAuthClient) DisableTwoFactorWithContext(ctx context.Context, userId string, methodId string, code string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/two-factor").
		WithUriSegment(userId).
		WithParameter("methodId", methodId).
		WithParameter("code", code).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// DisableTwoFactorWithRequest
// Disable two-factor authentication for a user using a JSON body rather than URL parameters.
//
//	string userId The Id of the User for which you're disabling two-factor authentication.
//	TwoFactorDisableRequest request The request information that contains the code and methodId along with any event information.
func (c *FusionAuthClient) DisableTwoFactorWithRequest(userId string, request TwoFactorDisableRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.DisableTwoFactorWithRequestWithContext(context.TODO(), userId, request)
}

// DisableTwoFactorWithRequestWithContext
// Disable two-factor authentication for a user using a JSON body rather than URL parameters.
//
//	string userId The Id of the User for which you're disabling two-factor authentication.
//	TwoFactorDisableRequest request The request information that contains the code and methodId along with any event information.
func (c *FusionAuthClient) DisableTwoFactorWithRequestWithContext(ctx context.Context, userId string, request TwoFactorDisableRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/two-factor").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// EnableTwoFactor
// Enable two-factor authentication for a user.
//
//	string userId The Id of the user to enable two-factor authentication.
//	TwoFactorRequest request The two-factor enable request information.
func (c *FusionAuthClient) EnableTwoFactor(userId string, request TwoFactorRequest) (*TwoFactorResponse, *Errors, error) {
	return c.EnableTwoFactorWithContext(context.TODO(), userId, request)
}

// EnableTwoFactorWithContext
// Enable two-factor authentication for a user.
//
//	string userId The Id of the user to enable two-factor authentication.
//	TwoFactorRequest request The two-factor enable request information.
func (c *FusionAuthClient) EnableTwoFactorWithContext(ctx context.Context, userId string, request TwoFactorRequest) (*TwoFactorResponse, *Errors, error) {
	var resp TwoFactorResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/two-factor").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ExchangeOAuthCodeForAccessToken
// Exchanges an OAuth authorization code for an access token.
// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
//
//	string code The authorization code returned on the /oauth2/authorize response.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value will be required if client authentication is enabled.
//	string redirectUri The URI to redirect to upon a successful request.
func (c *FusionAuthClient) ExchangeOAuthCodeForAccessToken(code string, clientId string, clientSecret string, redirectUri string) (*AccessToken, *OAuthError, error) {
	return c.ExchangeOAuthCodeForAccessTokenWithContext(context.TODO(), code, clientId, clientSecret, redirectUri)
}

// ExchangeOAuthCodeForAccessTokenWithContext
// Exchanges an OAuth authorization code for an access token.
// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
//
//	string code The authorization code returned on the /oauth2/authorize response.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value will be required if client authentication is enabled.
//	string redirectUri The URI to redirect to upon a successful request.
func (c *FusionAuthClient) ExchangeOAuthCodeForAccessTokenWithContext(ctx context.Context, code string, clientId string, clientSecret string, redirectUri string) (*AccessToken, *OAuthError, error) {
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
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ExchangeOAuthCodeForAccessTokenUsingPKCE
// Exchanges an OAuth authorization code and code_verifier for an access token.
// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
//
//	string code The authorization code returned on the /oauth2/authorize response.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string redirectUri The URI to redirect to upon a successful request.
//	string codeVerifier The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.
func (c *FusionAuthClient) ExchangeOAuthCodeForAccessTokenUsingPKCE(code string, clientId string, clientSecret string, redirectUri string, codeVerifier string) (*AccessToken, *OAuthError, error) {
	return c.ExchangeOAuthCodeForAccessTokenUsingPKCEWithContext(context.TODO(), code, clientId, clientSecret, redirectUri, codeVerifier)
}

// ExchangeOAuthCodeForAccessTokenUsingPKCEWithContext
// Exchanges an OAuth authorization code and code_verifier for an access token.
// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
//
//	string code The authorization code returned on the /oauth2/authorize response.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string redirectUri The URI to redirect to upon a successful request.
//	string codeVerifier The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.
func (c *FusionAuthClient) ExchangeOAuthCodeForAccessTokenUsingPKCEWithContext(ctx context.Context, code string, clientId string, clientSecret string, redirectUri string, codeVerifier string) (*AccessToken, *OAuthError, error) {
	var resp AccessToken
	var errors OAuthError
	formBody := url.Values{}
	formBody.Set("code", code)
	formBody.Set("client_id", clientId)
	formBody.Set("client_secret", clientSecret)
	formBody.Set("grant_type", "authorization_code")
	formBody.Set("redirect_uri", redirectUri)
	formBody.Set("code_verifier", codeVerifier)

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/oauth2/token").
		WithFormData(formBody).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ExchangeRefreshTokenForAccessToken
// Exchange a Refresh Token for an Access Token.
// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
//
//	string refreshToken The refresh token that you would like to use to exchange for an access token.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//	string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeRefreshTokenForAccessToken(refreshToken string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
	return c.ExchangeRefreshTokenForAccessTokenWithContext(context.TODO(), refreshToken, clientId, clientSecret, scope, userCode)
}

// ExchangeRefreshTokenForAccessTokenWithContext
// Exchange a Refresh Token for an Access Token.
// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
//
//	string refreshToken The refresh token that you would like to use to exchange for an access token.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//	string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeRefreshTokenForAccessTokenWithContext(ctx context.Context, refreshToken string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
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
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ExchangeRefreshTokenForJWT
// Exchange a refresh token for a new JWT.
//
//	RefreshRequest request The refresh request.
func (c *FusionAuthClient) ExchangeRefreshTokenForJWT(request RefreshRequest) (*JWTRefreshResponse, *Errors, error) {
	return c.ExchangeRefreshTokenForJWTWithContext(context.TODO(), request)
}

// ExchangeRefreshTokenForJWTWithContext
// Exchange a refresh token for a new JWT.
//
//	RefreshRequest request The refresh request.
func (c *FusionAuthClient) ExchangeRefreshTokenForJWTWithContext(ctx context.Context, request RefreshRequest) (*JWTRefreshResponse, *Errors, error) {
	var resp JWTRefreshResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ExchangeUserCredentialsForAccessToken
// Exchange User Credentials for a Token.
// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
//
//	string username The login identifier of the user. The login identifier can be either the email or the username.
//	string password The user’s password.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//	string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeUserCredentialsForAccessToken(username string, password string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
	return c.ExchangeUserCredentialsForAccessTokenWithContext(context.TODO(), username, password, clientId, clientSecret, scope, userCode)
}

// ExchangeUserCredentialsForAccessTokenWithContext
// Exchange User Credentials for a Token.
// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
//
//	string username The login identifier of the user. The login identifier can be either the email or the username.
//	string password The user’s password.
//	string clientId (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
//	This parameter is optional when Basic Authorization is used to authenticate this request.
//	string clientSecret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
//	string scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
//	string userCode (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
func (c *FusionAuthClient) ExchangeUserCredentialsForAccessTokenWithContext(ctx context.Context, username string, password string, clientId string, clientSecret string, scope string, userCode string) (*AccessToken, *OAuthError, error) {
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
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ForgotPassword
// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
//
//	ForgotPasswordRequest request The request that contains the information about the user so that they can be emailed.
func (c *FusionAuthClient) ForgotPassword(request ForgotPasswordRequest) (*ForgotPasswordResponse, *Errors, error) {
	return c.ForgotPasswordWithContext(context.TODO(), request)
}

// ForgotPasswordWithContext
// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
//
//	ForgotPasswordRequest request The request that contains the information about the user so that they can be emailed.
func (c *FusionAuthClient) ForgotPasswordWithContext(ctx context.Context, request ForgotPasswordRequest) (*ForgotPasswordResponse, *Errors, error) {
	var resp ForgotPasswordResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/forgot-password").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// GenerateEmailVerificationId
// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) GenerateEmailVerificationId(email string) (*VerifyEmailResponse, error) {
	return c.GenerateEmailVerificationIdWithContext(context.TODO(), email)
}

// GenerateEmailVerificationIdWithContext
// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) GenerateEmailVerificationIdWithContext(ctx context.Context, email string) (*VerifyEmailResponse, error) {
	var resp VerifyEmailResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/verify-email").
		WithParameter("email", email).
		WithParameter("sendVerifyEmail", strconv.FormatBool(false)).
		WithMethod(http.MethodPut).
		Do(ctx)
	return &resp, err
}

// GenerateKey
// Generate a new RSA or EC key pair or an HMAC secret.
//
//	string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//	KeyRequest request The request object that contains all the information used to create the key.
func (c *FusionAuthClient) GenerateKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	return c.GenerateKeyWithContext(context.TODO(), keyId, request)
}

// GenerateKeyWithContext
// Generate a new RSA or EC key pair or an HMAC secret.
//
//	string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//	KeyRequest request The request object that contains all the information used to create the key.
func (c *FusionAuthClient) GenerateKeyWithContext(ctx context.Context, keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	var resp KeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key/generate").
		WithUriSegment(keyId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// GenerateRegistrationVerificationId
// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//
//	string email The email address of the user that needs a new verification email.
//	string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) GenerateRegistrationVerificationId(email string, applicationId string) (*VerifyRegistrationResponse, error) {
	return c.GenerateRegistrationVerificationIdWithContext(context.TODO(), email, applicationId)
}

// GenerateRegistrationVerificationIdWithContext
// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
// email to the User. This API may be used to collect the verificationId for use with a third party system.
//
//	string email The email address of the user that needs a new verification email.
//	string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) GenerateRegistrationVerificationIdWithContext(ctx context.Context, email string, applicationId string) (*VerifyRegistrationResponse, error) {
	var resp VerifyRegistrationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/verify-registration").
		WithParameter("email", email).
		WithParameter("sendVerifyPasswordEmail", strconv.FormatBool(false)).
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodPut).
		Do(ctx)
	return &resp, err
}

// GenerateTwoFactorRecoveryCodes
// Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes.
//
//	string userId The Id of the user to generate new Two Factor recovery codes.
func (c *FusionAuthClient) GenerateTwoFactorRecoveryCodes(userId string) (*TwoFactorRecoveryCodeResponse, *Errors, error) {
	return c.GenerateTwoFactorRecoveryCodesWithContext(context.TODO(), userId)
}

// GenerateTwoFactorRecoveryCodesWithContext
// Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes.
//
//	string userId The Id of the user to generate new Two Factor recovery codes.
func (c *FusionAuthClient) GenerateTwoFactorRecoveryCodesWithContext(ctx context.Context, userId string) (*TwoFactorRecoveryCodeResponse, *Errors, error) {
	var resp TwoFactorRecoveryCodeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/two-factor/recovery-code").
		WithUriSegment(userId).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// GenerateTwoFactorSecret
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
func (c *FusionAuthClient) GenerateTwoFactorSecret() (*SecretResponse, error) {
	return c.GenerateTwoFactorSecretWithContext(context.TODO())
}

// GenerateTwoFactorSecretWithContext
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
func (c *FusionAuthClient) GenerateTwoFactorSecretWithContext(ctx context.Context) (*SecretResponse, error) {
	var resp SecretResponse

	err := c.Start(&resp, nil).
		WithUri("/api/two-factor/secret").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// GenerateTwoFactorSecretUsingJWT
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) GenerateTwoFactorSecretUsingJWT(encodedJWT string) (*SecretResponse, error) {
	return c.GenerateTwoFactorSecretUsingJWTWithContext(context.TODO(), encodedJWT)
}

// GenerateTwoFactorSecretUsingJWTWithContext
// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
// application such as Google Authenticator.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) GenerateTwoFactorSecretUsingJWTWithContext(ctx context.Context, encodedJWT string) (*SecretResponse, error) {
	var resp SecretResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/two-factor/secret").
		WithAuthorization("Bearer " + encodedJWT).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// IdentityProviderLogin
// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
// login systems.
//
//	IdentityProviderLoginRequest request The third-party login request that contains information from the third-party login
//	providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) IdentityProviderLogin(request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
	return c.IdentityProviderLoginWithContext(context.TODO(), request)
}

// IdentityProviderLoginWithContext
// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
// login systems.
//
//	IdentityProviderLoginRequest request The third-party login request that contains information from the third-party login
//	providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) IdentityProviderLoginWithContext(ctx context.Context, request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/login").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ImportKey
// Import an existing RSA or EC key pair or an HMAC secret.
//
//	string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//	KeyRequest request The request object that contains all the information used to create the key.
func (c *FusionAuthClient) ImportKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	return c.ImportKeyWithContext(context.TODO(), keyId, request)
}

// ImportKeyWithContext
// Import an existing RSA or EC key pair or an HMAC secret.
//
//	string keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
//	KeyRequest request The request object that contains all the information used to create the key.
func (c *FusionAuthClient) ImportKeyWithContext(ctx context.Context, keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	var resp KeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key/import").
		WithUriSegment(keyId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ImportRefreshTokens
// Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
// expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
// Application. This is done to increases the insert performance.
//
// Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
// explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
// body with specific validation errors. This will slow the request down but will allow you to identify the cause of
// the failure. See the validateDbConstraints request parameter.
//
//	RefreshTokenImportRequest request The request that contains all the information about all the refresh tokens to import.
func (c *FusionAuthClient) ImportRefreshTokens(request RefreshTokenImportRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ImportRefreshTokensWithContext(context.TODO(), request)
}

// ImportRefreshTokensWithContext
// Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
// expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
// Application. This is done to increases the insert performance.
//
// Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
// explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
// body with specific validation errors. This will slow the request down but will allow you to identify the cause of
// the failure. See the validateDbConstraints request parameter.
//
//	RefreshTokenImportRequest request The request that contains all the information about all the refresh tokens to import.
func (c *FusionAuthClient) ImportRefreshTokensWithContext(ctx context.Context, request RefreshTokenImportRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/refresh-token/import").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ImportUsers
// Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
// that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
// increases the insert performance.
//
// Therefore, if you encounter an error due to a database key violation, the response will likely offer
// a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
// body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
// the validateDbConstraints request parameter.
//
//	ImportRequest request The request that contains all the information about all the users to import.
func (c *FusionAuthClient) ImportUsers(request ImportRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ImportUsersWithContext(context.TODO(), request)
}

// ImportUsersWithContext
// Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
// that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
// increases the insert performance.
//
// Therefore, if you encounter an error due to a database key violation, the response will likely offer
// a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
// body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
// the validateDbConstraints request parameter.
//
//	ImportRequest request The request that contains all the information about all the users to import.
func (c *FusionAuthClient) ImportUsersWithContext(ctx context.Context, request ImportRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/import").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ImportWebAuthnCredential
// Import a WebAuthn credential
//
//	WebAuthnCredentialImportRequest request An object containing data necessary for importing the credential
func (c *FusionAuthClient) ImportWebAuthnCredential(request WebAuthnCredentialImportRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ImportWebAuthnCredentialWithContext(context.TODO(), request)
}

// ImportWebAuthnCredentialWithContext
// Import a WebAuthn credential
//
//	WebAuthnCredentialImportRequest request An object containing data necessary for importing the credential
func (c *FusionAuthClient) ImportWebAuthnCredentialWithContext(ctx context.Context, request WebAuthnCredentialImportRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/import").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
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
//
//	string applicationId The Application Id for which you are requesting a new access token be issued.
//	string encodedJWT The encoded JWT (access token).
//	string refreshToken (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
//	<p>The target application represented by the applicationId request parameter must have refresh
//	tokens enabled in order to receive a refresh token in the response.</p>
func (c *FusionAuthClient) IssueJWT(applicationId string, encodedJWT string, refreshToken string) (*IssueResponse, *Errors, error) {
	return c.IssueJWTWithContext(context.TODO(), applicationId, encodedJWT, refreshToken)
}

// IssueJWTWithContext
// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
// access token is properly signed and not expired.
// <p>
// This API may be used in an SSO configuration to issue new tokens for another application after the user has
// obtained a valid token from authentication.
//
//	string applicationId The Application Id for which you are requesting a new access token be issued.
//	string encodedJWT The encoded JWT (access token).
//	string refreshToken (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
//	<p>The target application represented by the applicationId request parameter must have refresh
//	tokens enabled in order to receive a refresh token in the response.</p>
func (c *FusionAuthClient) IssueJWTWithContext(ctx context.Context, applicationId string, encodedJWT string, refreshToken string) (*IssueResponse, *Errors, error) {
	var resp IssueResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/jwt/issue").
		WithAuthorization("Bearer "+encodedJWT).
		WithParameter("applicationId", applicationId).
		WithParameter("refreshToken", refreshToken).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// Login
// Authenticates a user to FusionAuth.
//
// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
//
//	LoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) Login(request LoginRequest) (*LoginResponse, *Errors, error) {
	return c.LoginWithContext(context.TODO(), request)
}

// LoginWithContext
// Authenticates a user to FusionAuth.
//
// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
//
//	LoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) LoginWithContext(ctx context.Context, request LoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/login").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
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
//
//	string userId The Id of the user that was logged in.
//	string applicationId The Id of the application that they logged into.
//	string callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
//	the IP address will be that of the client or last proxy that sent the request.
func (c *FusionAuthClient) LoginPing(userId string, applicationId string, callerIPAddress string) (*LoginResponse, *Errors, error) {
	return c.LoginPingWithContext(context.TODO(), userId, applicationId, callerIPAddress)
}

// LoginPingWithContext
// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
// application where they no longer have a session. This helps correctly track login counts, times and helps with
// reporting.
//
//	string userId The Id of the user that was logged in.
//	string applicationId The Id of the application that they logged into.
//	string callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
//	the IP address will be that of the client or last proxy that sent the request.
func (c *FusionAuthClient) LoginPingWithContext(ctx context.Context, userId string, applicationId string, callerIPAddress string) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/login").
		WithUriSegment(userId).
		WithUriSegment(applicationId).
		WithParameter("ipAddress", callerIPAddress).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// LoginPingWithRequest
// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
// application where they no longer have a session. This helps correctly track login counts, times and helps with
// reporting.
//
//	LoginPingRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) LoginPingWithRequest(request LoginPingRequest) (*LoginResponse, *Errors, error) {
	return c.LoginPingWithRequestWithContext(context.TODO(), request)
}

// LoginPingWithRequestWithContext
// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
// application where they no longer have a session. This helps correctly track login counts, times and helps with
// reporting.
//
//	LoginPingRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) LoginPingWithRequestWithContext(ctx context.Context, request LoginPingRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/login").
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// Logout
// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
// token or refresh token cookies.
//
//	bool global When this value is set to true all the refresh tokens issued to the owner of the
//	provided token will be revoked.
//	string refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
//	If provided this takes precedence over the cookie.
func (c *FusionAuthClient) Logout(global bool, refreshToken string) (*BaseHTTPResponse, error) {
	return c.LogoutWithContext(context.TODO(), global, refreshToken)
}

// LogoutWithContext
// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
// token or refresh token cookies.
//
//	bool global When this value is set to true all the refresh tokens issued to the owner of the
//	provided token will be revoked.
//	string refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
//	If provided this takes precedence over the cookie.
func (c *FusionAuthClient) LogoutWithContext(ctx context.Context, global bool, refreshToken string) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/logout").
		WithParameter("global", strconv.FormatBool(global)).
		WithParameter("refreshToken", refreshToken).
		WithMethod(http.MethodPost).
		Do(ctx)
	return &resp, err
}

// LogoutWithRequest
// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
// client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
//
//	LogoutRequest request The request object that contains all the information used to logout the user.
func (c *FusionAuthClient) LogoutWithRequest(request LogoutRequest) (*BaseHTTPResponse, error) {
	return c.LogoutWithRequestWithContext(context.TODO(), request)
}

// LogoutWithRequestWithContext
// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
// client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
//
//	LogoutRequest request The request object that contains all the information used to logout the user.
func (c *FusionAuthClient) LogoutWithRequestWithContext(ctx context.Context, request LogoutRequest) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/logout").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	return &resp, err
}

// LookupIdentityProvider
// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
// by a registered identity provider. A 404 indicates the domain is not managed.
//
//	string domain The domain or email address to lookup.
func (c *FusionAuthClient) LookupIdentityProvider(domain string) (*LookupResponse, error) {
	return c.LookupIdentityProviderWithContext(context.TODO(), domain)
}

// LookupIdentityProviderWithContext
// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
// by a registered identity provider. A 404 indicates the domain is not managed.
//
//	string domain The domain or email address to lookup.
func (c *FusionAuthClient) LookupIdentityProviderWithContext(ctx context.Context, domain string) (*LookupResponse, error) {
	var resp LookupResponse

	err := c.Start(&resp, nil).
		WithUri("/api/identity-provider/lookup").
		WithParameter("domain", domain).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// ModifyAction
// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
// action.
//
//	string actionId The Id of the action to modify. This is technically the user action log id.
//	ActionRequest request The request that contains all the information about the modification.
func (c *FusionAuthClient) ModifyAction(actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
	return c.ModifyActionWithContext(context.TODO(), actionId, request)
}

// ModifyActionWithContext
// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
// action.
//
//	string actionId The Id of the action to modify. This is technically the user action log id.
//	ActionRequest request The request that contains all the information about the modification.
func (c *FusionAuthClient) ModifyActionWithContext(ctx context.Context, actionId string, request ActionRequest) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithUriSegment(actionId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PasswordlessLogin
// Complete a login request using a passwordless code
//
//	PasswordlessLoginRequest request The passwordless login request that contains all the information used to complete login.
func (c *FusionAuthClient) PasswordlessLogin(request PasswordlessLoginRequest) (*LoginResponse, *Errors, error) {
	return c.PasswordlessLoginWithContext(context.TODO(), request)
}

// PasswordlessLoginWithContext
// Complete a login request using a passwordless code
//
//	PasswordlessLoginRequest request The passwordless login request that contains all the information used to complete login.
func (c *FusionAuthClient) PasswordlessLoginWithContext(ctx context.Context, request PasswordlessLoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/passwordless/login").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchAPIKey
// Updates an authentication API key by given id
//
//	string keyId The Id of the authentication key. If not provided a secure random api key will be generated.
//	APIKeyRequest request The request object that contains all the information needed to create the APIKey.
func (c *FusionAuthClient) PatchAPIKey(keyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	return c.PatchAPIKeyWithContext(context.TODO(), keyId, request)
}

// PatchAPIKeyWithContext
// Updates an authentication API key by given id
//
//	string keyId The Id of the authentication key. If not provided a secure random api key will be generated.
//	APIKeyRequest request The request object that contains all the information needed to create the APIKey.
func (c *FusionAuthClient) PatchAPIKeyWithContext(ctx context.Context, keyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	var resp APIKeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/api-key").
		WithUriSegment(keyId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchApplication
// Updates, via PATCH, the application with the given Id.
//
//	string applicationId The Id of the application to update.
//	ApplicationRequest request The request that contains just the new application information.
func (c *FusionAuthClient) PatchApplication(applicationId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
	return c.PatchApplicationWithContext(context.TODO(), applicationId, request)
}

// PatchApplicationWithContext
// Updates, via PATCH, the application with the given Id.
//
//	string applicationId The Id of the application to update.
//	ApplicationRequest request The request that contains just the new application information.
func (c *FusionAuthClient) PatchApplicationWithContext(ctx context.Context, applicationId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchApplicationRole
// Updates, via PATCH, the application role with the given id for the application.
//
//	string applicationId The Id of the application that the role belongs to.
//	string roleId The Id of the role to update.
//	ApplicationRequest request The request that contains just the new role information.
func (c *FusionAuthClient) PatchApplicationRole(applicationId string, roleId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
	return c.PatchApplicationRoleWithContext(context.TODO(), applicationId, roleId, request)
}

// PatchApplicationRoleWithContext
// Updates, via PATCH, the application role with the given id for the application.
//
//	string applicationId The Id of the application that the role belongs to.
//	string roleId The Id of the role to update.
//	ApplicationRequest request The request that contains just the new role information.
func (c *FusionAuthClient) PatchApplicationRoleWithContext(ctx context.Context, applicationId string, roleId string, request map[string]interface{}) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithUriSegment("role").
		WithUriSegment(roleId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchConnector
// Updates, via PATCH, the connector with the given Id.
//
//	string connectorId The Id of the connector to update.
//	ConnectorRequest request The request that contains just the new connector information.
func (c *FusionAuthClient) PatchConnector(connectorId string, request map[string]interface{}) (*ConnectorResponse, *Errors, error) {
	return c.PatchConnectorWithContext(context.TODO(), connectorId, request)
}

// PatchConnectorWithContext
// Updates, via PATCH, the connector with the given Id.
//
//	string connectorId The Id of the connector to update.
//	ConnectorRequest request The request that contains just the new connector information.
func (c *FusionAuthClient) PatchConnectorWithContext(ctx context.Context, connectorId string, request map[string]interface{}) (*ConnectorResponse, *Errors, error) {
	var resp ConnectorResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/connector").
		WithUriSegment(connectorId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchConsent
// Updates, via PATCH, the consent with the given Id.
//
//	string consentId The Id of the consent to update.
//	ConsentRequest request The request that contains just the new consent information.
func (c *FusionAuthClient) PatchConsent(consentId string, request map[string]interface{}) (*ConsentResponse, *Errors, error) {
	return c.PatchConsentWithContext(context.TODO(), consentId, request)
}

// PatchConsentWithContext
// Updates, via PATCH, the consent with the given Id.
//
//	string consentId The Id of the consent to update.
//	ConsentRequest request The request that contains just the new consent information.
func (c *FusionAuthClient) PatchConsentWithContext(ctx context.Context, consentId string, request map[string]interface{}) (*ConsentResponse, *Errors, error) {
	var resp ConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/consent").
		WithUriSegment(consentId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchEmailTemplate
// Updates, via PATCH, the email template with the given Id.
//
//	string emailTemplateId The Id of the email template to update.
//	EmailTemplateRequest request The request that contains just the new email template information.
func (c *FusionAuthClient) PatchEmailTemplate(emailTemplateId string, request map[string]interface{}) (*EmailTemplateResponse, *Errors, error) {
	return c.PatchEmailTemplateWithContext(context.TODO(), emailTemplateId, request)
}

// PatchEmailTemplateWithContext
// Updates, via PATCH, the email template with the given Id.
//
//	string emailTemplateId The Id of the email template to update.
//	EmailTemplateRequest request The request that contains just the new email template information.
func (c *FusionAuthClient) PatchEmailTemplateWithContext(ctx context.Context, emailTemplateId string, request map[string]interface{}) (*EmailTemplateResponse, *Errors, error) {
	var resp EmailTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template").
		WithUriSegment(emailTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchEntityType
// Updates, via PATCH, the Entity Type with the given Id.
//
//	string entityTypeId The Id of the Entity Type to update.
//	EntityTypeRequest request The request that contains just the new Entity Type information.
func (c *FusionAuthClient) PatchEntityType(entityTypeId string, request map[string]interface{}) (*EntityTypeResponse, *Errors, error) {
	return c.PatchEntityTypeWithContext(context.TODO(), entityTypeId, request)
}

// PatchEntityTypeWithContext
// Updates, via PATCH, the Entity Type with the given Id.
//
//	string entityTypeId The Id of the Entity Type to update.
//	EntityTypeRequest request The request that contains just the new Entity Type information.
func (c *FusionAuthClient) PatchEntityTypeWithContext(ctx context.Context, entityTypeId string, request map[string]interface{}) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchGroup
// Updates, via PATCH, the group with the given Id.
//
//	string groupId The Id of the group to update.
//	GroupRequest request The request that contains just the new group information.
func (c *FusionAuthClient) PatchGroup(groupId string, request map[string]interface{}) (*GroupResponse, *Errors, error) {
	return c.PatchGroupWithContext(context.TODO(), groupId, request)
}

// PatchGroupWithContext
// Updates, via PATCH, the group with the given Id.
//
//	string groupId The Id of the group to update.
//	GroupRequest request The request that contains just the new group information.
func (c *FusionAuthClient) PatchGroupWithContext(ctx context.Context, groupId string, request map[string]interface{}) (*GroupResponse, *Errors, error) {
	var resp GroupResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group").
		WithUriSegment(groupId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchIdentityProvider
// Updates, via PATCH, the identity provider with the given Id.
//
//	string identityProviderId The Id of the identity provider to update.
//	IdentityProviderRequest request The request object that contains just the updated identity provider information.
func (c *FusionAuthClient) PatchIdentityProvider(identityProviderId string, request map[string]interface{}) (*IdentityProviderResponse, *Errors, error) {
	return c.PatchIdentityProviderWithContext(context.TODO(), identityProviderId, request)
}

// PatchIdentityProviderWithContext
// Updates, via PATCH, the identity provider with the given Id.
//
//	string identityProviderId The Id of the identity provider to update.
//	IdentityProviderRequest request The request object that contains just the updated identity provider information.
func (c *FusionAuthClient) PatchIdentityProviderWithContext(ctx context.Context, identityProviderId string, request map[string]interface{}) (*IdentityProviderResponse, *Errors, error) {
	var resp IdentityProviderResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider").
		WithUriSegment(identityProviderId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchIntegrations
// Updates, via PATCH, the available integrations.
//
//	IntegrationRequest request The request that contains just the new integration information.
func (c *FusionAuthClient) PatchIntegrations(request map[string]interface{}) (*IntegrationResponse, *Errors, error) {
	return c.PatchIntegrationsWithContext(context.TODO(), request)
}

// PatchIntegrationsWithContext
// Updates, via PATCH, the available integrations.
//
//	IntegrationRequest request The request that contains just the new integration information.
func (c *FusionAuthClient) PatchIntegrationsWithContext(ctx context.Context, request map[string]interface{}) (*IntegrationResponse, *Errors, error) {
	var resp IntegrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/integration").
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchLambda
// Updates, via PATCH, the lambda with the given Id.
//
//	string lambdaId The Id of the lambda to update.
//	LambdaRequest request The request that contains just the new lambda information.
func (c *FusionAuthClient) PatchLambda(lambdaId string, request map[string]interface{}) (*LambdaResponse, *Errors, error) {
	return c.PatchLambdaWithContext(context.TODO(), lambdaId, request)
}

// PatchLambdaWithContext
// Updates, via PATCH, the lambda with the given Id.
//
//	string lambdaId The Id of the lambda to update.
//	LambdaRequest request The request that contains just the new lambda information.
func (c *FusionAuthClient) PatchLambdaWithContext(ctx context.Context, lambdaId string, request map[string]interface{}) (*LambdaResponse, *Errors, error) {
	var resp LambdaResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda").
		WithUriSegment(lambdaId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchMessageTemplate
// Updates, via PATCH, the message template with the given Id.
//
//	string messageTemplateId The Id of the message template to update.
//	MessageTemplateRequest request The request that contains just the new message template information.
func (c *FusionAuthClient) PatchMessageTemplate(messageTemplateId string, request map[string]interface{}) (*MessageTemplateResponse, *Errors, error) {
	return c.PatchMessageTemplateWithContext(context.TODO(), messageTemplateId, request)
}

// PatchMessageTemplateWithContext
// Updates, via PATCH, the message template with the given Id.
//
//	string messageTemplateId The Id of the message template to update.
//	MessageTemplateRequest request The request that contains just the new message template information.
func (c *FusionAuthClient) PatchMessageTemplateWithContext(ctx context.Context, messageTemplateId string, request map[string]interface{}) (*MessageTemplateResponse, *Errors, error) {
	var resp MessageTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/message/template").
		WithUriSegment(messageTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchMessenger
// Updates, via PATCH, the messenger with the given Id.
//
//	string messengerId The Id of the messenger to update.
//	MessengerRequest request The request that contains just the new messenger information.
func (c *FusionAuthClient) PatchMessenger(messengerId string, request map[string]interface{}) (*MessengerResponse, *Errors, error) {
	return c.PatchMessengerWithContext(context.TODO(), messengerId, request)
}

// PatchMessengerWithContext
// Updates, via PATCH, the messenger with the given Id.
//
//	string messengerId The Id of the messenger to update.
//	MessengerRequest request The request that contains just the new messenger information.
func (c *FusionAuthClient) PatchMessengerWithContext(ctx context.Context, messengerId string, request map[string]interface{}) (*MessengerResponse, *Errors, error) {
	var resp MessengerResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/messenger").
		WithUriSegment(messengerId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchRegistration
// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
//
//	string userId The Id of the user whose registration is going to be updated.
//	RegistrationRequest request The request that contains just the new registration information.
func (c *FusionAuthClient) PatchRegistration(userId string, request map[string]interface{}) (*RegistrationResponse, *Errors, error) {
	return c.PatchRegistrationWithContext(context.TODO(), userId, request)
}

// PatchRegistrationWithContext
// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
//
//	string userId The Id of the user whose registration is going to be updated.
//	RegistrationRequest request The request that contains just the new registration information.
func (c *FusionAuthClient) PatchRegistrationWithContext(ctx context.Context, userId string, request map[string]interface{}) (*RegistrationResponse, *Errors, error) {
	var resp RegistrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchSystemConfiguration
// Updates, via PATCH, the system configuration.
//
//	SystemConfigurationRequest request The request that contains just the new system configuration information.
func (c *FusionAuthClient) PatchSystemConfiguration(request map[string]interface{}) (*SystemConfigurationResponse, *Errors, error) {
	return c.PatchSystemConfigurationWithContext(context.TODO(), request)
}

// PatchSystemConfigurationWithContext
// Updates, via PATCH, the system configuration.
//
//	SystemConfigurationRequest request The request that contains just the new system configuration information.
func (c *FusionAuthClient) PatchSystemConfigurationWithContext(ctx context.Context, request map[string]interface{}) (*SystemConfigurationResponse, *Errors, error) {
	var resp SystemConfigurationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system-configuration").
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchTenant
// Updates, via PATCH, the tenant with the given Id.
//
//	string tenantId The Id of the tenant to update.
//	TenantRequest request The request that contains just the new tenant information.
func (c *FusionAuthClient) PatchTenant(tenantId string, request map[string]interface{}) (*TenantResponse, *Errors, error) {
	return c.PatchTenantWithContext(context.TODO(), tenantId, request)
}

// PatchTenantWithContext
// Updates, via PATCH, the tenant with the given Id.
//
//	string tenantId The Id of the tenant to update.
//	TenantRequest request The request that contains just the new tenant information.
func (c *FusionAuthClient) PatchTenantWithContext(ctx context.Context, tenantId string, request map[string]interface{}) (*TenantResponse, *Errors, error) {
	var resp TenantResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchTheme
// Updates, via PATCH, the theme with the given Id.
//
//	string themeId The Id of the theme to update.
//	ThemeRequest request The request that contains just the new theme information.
func (c *FusionAuthClient) PatchTheme(themeId string, request map[string]interface{}) (*ThemeResponse, *Errors, error) {
	return c.PatchThemeWithContext(context.TODO(), themeId, request)
}

// PatchThemeWithContext
// Updates, via PATCH, the theme with the given Id.
//
//	string themeId The Id of the theme to update.
//	ThemeRequest request The request that contains just the new theme information.
func (c *FusionAuthClient) PatchThemeWithContext(ctx context.Context, themeId string, request map[string]interface{}) (*ThemeResponse, *Errors, error) {
	var resp ThemeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme").
		WithUriSegment(themeId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchUser
// Updates, via PATCH, the user with the given Id.
//
//	string userId The Id of the user to update.
//	UserRequest request The request that contains just the new user information.
func (c *FusionAuthClient) PatchUser(userId string, request map[string]interface{}) (*UserResponse, *Errors, error) {
	return c.PatchUserWithContext(context.TODO(), userId, request)
}

// PatchUserWithContext
// Updates, via PATCH, the user with the given Id.
//
//	string userId The Id of the user to update.
//	UserRequest request The request that contains just the new user information.
func (c *FusionAuthClient) PatchUserWithContext(ctx context.Context, userId string, request map[string]interface{}) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchUserAction
// Updates, via PATCH, the user action with the given Id.
//
//	string userActionId The Id of the user action to update.
//	UserActionRequest request The request that contains just the new user action information.
func (c *FusionAuthClient) PatchUserAction(userActionId string, request map[string]interface{}) (*UserActionResponse, *Errors, error) {
	return c.PatchUserActionWithContext(context.TODO(), userActionId, request)
}

// PatchUserActionWithContext
// Updates, via PATCH, the user action with the given Id.
//
//	string userActionId The Id of the user action to update.
//	UserActionRequest request The request that contains just the new user action information.
func (c *FusionAuthClient) PatchUserActionWithContext(ctx context.Context, userActionId string, request map[string]interface{}) (*UserActionResponse, *Errors, error) {
	var resp UserActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchUserActionReason
// Updates, via PATCH, the user action reason with the given Id.
//
//	string userActionReasonId The Id of the user action reason to update.
//	UserActionReasonRequest request The request that contains just the new user action reason information.
func (c *FusionAuthClient) PatchUserActionReason(userActionReasonId string, request map[string]interface{}) (*UserActionReasonResponse, *Errors, error) {
	return c.PatchUserActionReasonWithContext(context.TODO(), userActionReasonId, request)
}

// PatchUserActionReasonWithContext
// Updates, via PATCH, the user action reason with the given Id.
//
//	string userActionReasonId The Id of the user action reason to update.
//	UserActionReasonRequest request The request that contains just the new user action reason information.
func (c *FusionAuthClient) PatchUserActionReasonWithContext(ctx context.Context, userActionReasonId string, request map[string]interface{}) (*UserActionReasonResponse, *Errors, error) {
	var resp UserActionReasonResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action-reason").
		WithUriSegment(userActionReasonId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// PatchUserConsent
// Updates, via PATCH, a single User consent by Id.
//
//	string userConsentId The User Consent Id
//	UserConsentRequest request The request that contains just the new user consent information.
func (c *FusionAuthClient) PatchUserConsent(userConsentId string, request map[string]interface{}) (*UserConsentResponse, *Errors, error) {
	return c.PatchUserConsentWithContext(context.TODO(), userConsentId, request)
}

// PatchUserConsentWithContext
// Updates, via PATCH, a single User consent by Id.
//
//	string userConsentId The User Consent Id
//	UserConsentRequest request The request that contains just the new user consent information.
func (c *FusionAuthClient) PatchUserConsentWithContext(ctx context.Context, userConsentId string, request map[string]interface{}) (*UserConsentResponse, *Errors, error) {
	var resp UserConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/consent").
		WithUriSegment(userConsentId).
		WithJSONBody(request).
		WithMethod(http.MethodPatch).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ReactivateApplication
// Reactivates the application with the given Id.
//
//	string applicationId The Id of the application to reactivate.
func (c *FusionAuthClient) ReactivateApplication(applicationId string) (*ApplicationResponse, *Errors, error) {
	return c.ReactivateApplicationWithContext(context.TODO(), applicationId)
}

// ReactivateApplicationWithContext
// Reactivates the application with the given Id.
//
//	string applicationId The Id of the application to reactivate.
func (c *FusionAuthClient) ReactivateApplicationWithContext(ctx context.Context, applicationId string) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithParameter("reactivate", strconv.FormatBool(true)).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ReactivateUser
// Reactivates the user with the given Id.
//
//	string userId The Id of the user to reactivate.
func (c *FusionAuthClient) ReactivateUser(userId string) (*UserResponse, *Errors, error) {
	return c.ReactivateUserWithContext(context.TODO(), userId)
}

// ReactivateUserWithContext
// Reactivates the user with the given Id.
//
//	string userId The Id of the user to reactivate.
func (c *FusionAuthClient) ReactivateUserWithContext(ctx context.Context, userId string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithParameter("reactivate", strconv.FormatBool(true)).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ReactivateUserAction
// Reactivates the user action with the given Id.
//
//	string userActionId The Id of the user action to reactivate.
func (c *FusionAuthClient) ReactivateUserAction(userActionId string) (*UserActionResponse, *Errors, error) {
	return c.ReactivateUserActionWithContext(context.TODO(), userActionId)
}

// ReactivateUserActionWithContext
// Reactivates the user action with the given Id.
//
//	string userActionId The Id of the user action to reactivate.
func (c *FusionAuthClient) ReactivateUserActionWithContext(ctx context.Context, userActionId string) (*UserActionResponse, *Errors, error) {
	var resp UserActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithParameter("reactivate", strconv.FormatBool(true)).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ReconcileJWT
// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
//
//	IdentityProviderLoginRequest request The reconcile request that contains the data to reconcile the User.
func (c *FusionAuthClient) ReconcileJWT(request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
	return c.ReconcileJWTWithContext(context.TODO(), request)
}

// ReconcileJWTWithContext
// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
//
//	IdentityProviderLoginRequest request The reconcile request that contains the data to reconcile the User.
func (c *FusionAuthClient) ReconcileJWTWithContext(ctx context.Context, request IdentityProviderLoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/jwt/reconcile").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RefreshEntitySearchIndex
// Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
// if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
//
//	ensure the index immediately current before making a query request to the search index.
func (c *FusionAuthClient) RefreshEntitySearchIndex() (*BaseHTTPResponse, error) {
	return c.RefreshEntitySearchIndexWithContext(context.TODO())
}

// RefreshEntitySearchIndexWithContext
// Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
// if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
//
//	ensure the index immediately current before making a query request to the search index.
func (c *FusionAuthClient) RefreshEntitySearchIndexWithContext(ctx context.Context) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.Start(&resp, nil).
		WithUri("/api/entity/search").
		WithMethod(http.MethodPut).
		Do(ctx)
	return &resp, err
}

// RefreshUserSearchIndex
// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
//
//	ensure the index immediately current before making a query request to the search index.
func (c *FusionAuthClient) RefreshUserSearchIndex() (*BaseHTTPResponse, error) {
	return c.RefreshUserSearchIndexWithContext(context.TODO())
}

// RefreshUserSearchIndexWithContext
// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
//
//	ensure the index immediately current before making a query request to the search index.
func (c *FusionAuthClient) RefreshUserSearchIndexWithContext(ctx context.Context) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/search").
		WithMethod(http.MethodPut).
		Do(ctx)
	return &resp, err
}

// RegenerateReactorKeys
// Regenerates any keys that are used by the FusionAuth Reactor.
func (c *FusionAuthClient) RegenerateReactorKeys() (*BaseHTTPResponse, error) {
	return c.RegenerateReactorKeysWithContext(context.TODO())
}

// RegenerateReactorKeysWithContext
// Regenerates any keys that are used by the FusionAuth Reactor.
func (c *FusionAuthClient) RegenerateReactorKeysWithContext(ctx context.Context) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.Start(&resp, nil).
		WithUri("/api/reactor").
		WithMethod(http.MethodPut).
		Do(ctx)
	return &resp, err
}

// Register
// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
// will create the user as well as register them for the application. This is called a Full Registration. However, if
// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
// application. The user id can also be provided and it will either be used to look up an existing user or it will be
// used for the newly created User.
//
//	string userId (Optional) The Id of the user being registered for the application and optionally created.
//	RegistrationRequest request The request that optionally contains the User and must contain the UserRegistration.
func (c *FusionAuthClient) Register(userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
	return c.RegisterWithContext(context.TODO(), userId, request)
}

// RegisterWithContext
// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
// will create the user as well as register them for the application. This is called a Full Registration. However, if
// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
// application. The user id can also be provided and it will either be used to look up an existing user or it will be
// used for the newly created User.
//
//	string userId (Optional) The Id of the user being registered for the application and optionally created.
//	RegistrationRequest request The request that optionally contains the User and must contain the UserRegistration.
func (c *FusionAuthClient) RegisterWithContext(ctx context.Context, userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
	var resp RegistrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// Reindex
// Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will
// increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless
// instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index.
//
// You have been warned.
//
//	ReindexRequest request The request that contains the index name.
func (c *FusionAuthClient) Reindex(request ReindexRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.ReindexWithContext(context.TODO(), request)
}

// ReindexWithContext
// Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will
// increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless
// instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index.
//
// You have been warned.
//
//	ReindexRequest request The request that contains the index name.
func (c *FusionAuthClient) ReindexWithContext(ctx context.Context, request ReindexRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/reindex").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RemoveUserFromFamily
// Removes a user from the family with the given id.
//
//	string familyId The id of the family to remove the user from.
//	string userId The id of the user to remove from the family.
func (c *FusionAuthClient) RemoveUserFromFamily(familyId string, userId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RemoveUserFromFamilyWithContext(context.TODO(), familyId, userId)
}

// RemoveUserFromFamilyWithContext
// Removes a user from the family with the given id.
//
//	string familyId The id of the family to remove the user from.
//	string userId The id of the user to remove from the family.
func (c *FusionAuthClient) RemoveUserFromFamilyWithContext(ctx context.Context, familyId string, userId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/family").
		WithUriSegment(familyId).
		WithUriSegment(userId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ResendEmailVerification
// Re-sends the verification email to the user.
//
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) ResendEmailVerification(email string) (*VerifyEmailResponse, *Errors, error) {
	return c.ResendEmailVerificationWithContext(context.TODO(), email)
}

// ResendEmailVerificationWithContext
// Re-sends the verification email to the user.
//
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) ResendEmailVerificationWithContext(ctx context.Context, email string) (*VerifyEmailResponse, *Errors, error) {
	var resp VerifyEmailResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-email").
		WithParameter("email", email).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ResendEmailVerificationWithApplicationTemplate
// Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
// instead of the tenant configuration.
//
//	string applicationId The unique Application Id to used to resolve an application specific email template.
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) ResendEmailVerificationWithApplicationTemplate(applicationId string, email string) (*VerifyEmailResponse, *Errors, error) {
	return c.ResendEmailVerificationWithApplicationTemplateWithContext(context.TODO(), applicationId, email)
}

// ResendEmailVerificationWithApplicationTemplateWithContext
// Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
// instead of the tenant configuration.
//
//	string applicationId The unique Application Id to used to resolve an application specific email template.
//	string email The email address of the user that needs a new verification email.
func (c *FusionAuthClient) ResendEmailVerificationWithApplicationTemplateWithContext(ctx context.Context, applicationId string, email string) (*VerifyEmailResponse, *Errors, error) {
	var resp VerifyEmailResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-email").
		WithParameter("applicationId", applicationId).
		WithParameter("email", email).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ResendRegistrationVerification
// Re-sends the application registration verification email to the user.
//
//	string email The email address of the user that needs a new verification email.
//	string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) ResendRegistrationVerification(email string, applicationId string) (*VerifyRegistrationResponse, *Errors, error) {
	return c.ResendRegistrationVerificationWithContext(context.TODO(), email, applicationId)
}

// ResendRegistrationVerificationWithContext
// Re-sends the application registration verification email to the user.
//
//	string email The email address of the user that needs a new verification email.
//	string applicationId The Id of the application to be verified.
func (c *FusionAuthClient) ResendRegistrationVerificationWithContext(ctx context.Context, email string, applicationId string) (*VerifyRegistrationResponse, *Errors, error) {
	var resp VerifyRegistrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-registration").
		WithParameter("email", email).
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveAPIKey
// Retrieves an authentication API key for the given id
//
//	string keyId The Id of the API key to retrieve.
func (c *FusionAuthClient) RetrieveAPIKey(keyId string) (*APIKeyResponse, *Errors, error) {
	return c.RetrieveAPIKeyWithContext(context.TODO(), keyId)
}

// RetrieveAPIKeyWithContext
// Retrieves an authentication API key for the given id
//
//	string keyId The Id of the API key to retrieve.
func (c *FusionAuthClient) RetrieveAPIKeyWithContext(ctx context.Context, keyId string) (*APIKeyResponse, *Errors, error) {
	var resp APIKeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/api-key").
		WithUriSegment(keyId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveAction
// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
//
//	string actionId The Id of the action to retrieve.
func (c *FusionAuthClient) RetrieveAction(actionId string) (*ActionResponse, *Errors, error) {
	return c.RetrieveActionWithContext(context.TODO(), actionId)
}

// RetrieveActionWithContext
// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
//
//	string actionId The Id of the action to retrieve.
func (c *FusionAuthClient) RetrieveActionWithContext(ctx context.Context, actionId string) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithUriSegment(actionId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveActions
// Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
// and inactive as well as non-time based actions.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActions(userId string) (*ActionResponse, *Errors, error) {
	return c.RetrieveActionsWithContext(context.TODO(), userId)
}

// RetrieveActionsWithContext
// Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
// and inactive as well as non-time based actions.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActionsWithContext(ctx context.Context, userId string) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveActionsPreventingLogin
// Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActionsPreventingLogin(userId string) (*ActionResponse, *Errors, error) {
	return c.RetrieveActionsPreventingLoginWithContext(context.TODO(), userId)
}

// RetrieveActionsPreventingLoginWithContext
// Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActionsPreventingLoginWithContext(ctx context.Context, userId string) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithParameter("userId", userId).
		WithParameter("preventingLogin", strconv.FormatBool(true)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveActiveActions
// Retrieves all the actions for the user with the given Id that are currently active.
// An active action means one that is time based and has not been canceled, and has not ended.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActiveActions(userId string) (*ActionResponse, *Errors, error) {
	return c.RetrieveActiveActionsWithContext(context.TODO(), userId)
}

// RetrieveActiveActionsWithContext
// Retrieves all the actions for the user with the given Id that are currently active.
// An active action means one that is time based and has not been canceled, and has not ended.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveActiveActionsWithContext(ctx context.Context, userId string) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithParameter("userId", userId).
		WithParameter("active", strconv.FormatBool(true)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveApplication
// Retrieves the application for the given id or all the applications if the id is null.
//
//	string applicationId (Optional) The application id.
func (c *FusionAuthClient) RetrieveApplication(applicationId string) (*ApplicationResponse, error) {
	return c.RetrieveApplicationWithContext(context.TODO(), applicationId)
}

// RetrieveApplicationWithContext
// Retrieves the application for the given id or all the applications if the id is null.
//
//	string applicationId (Optional) The application id.
func (c *FusionAuthClient) RetrieveApplicationWithContext(ctx context.Context, applicationId string) (*ApplicationResponse, error) {
	var resp ApplicationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/application").
		WithUriSegment(applicationId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveApplications
// Retrieves all the applications.
func (c *FusionAuthClient) RetrieveApplications() (*ApplicationResponse, error) {
	return c.RetrieveApplicationsWithContext(context.TODO())
}

// RetrieveApplicationsWithContext
// Retrieves all the applications.
func (c *FusionAuthClient) RetrieveApplicationsWithContext(ctx context.Context) (*ApplicationResponse, error) {
	var resp ApplicationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/application").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveAuditLog
// Retrieves a single audit log for the given Id.
//
//	int auditLogId The Id of the audit log to retrieve.
func (c *FusionAuthClient) RetrieveAuditLog(auditLogId int) (*AuditLogResponse, *Errors, error) {
	return c.RetrieveAuditLogWithContext(context.TODO(), auditLogId)
}

// RetrieveAuditLogWithContext
// Retrieves a single audit log for the given Id.
//
//	int auditLogId The Id of the audit log to retrieve.
func (c *FusionAuthClient) RetrieveAuditLogWithContext(ctx context.Context, auditLogId int) (*AuditLogResponse, *Errors, error) {
	var resp AuditLogResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/audit-log").
		WithUriSegment(strconv.Itoa(auditLogId)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveConnector
// Retrieves the connector with the given Id.
//
//	string connectorId The Id of the connector.
func (c *FusionAuthClient) RetrieveConnector(connectorId string) (*ConnectorResponse, error) {
	return c.RetrieveConnectorWithContext(context.TODO(), connectorId)
}

// RetrieveConnectorWithContext
// Retrieves the connector with the given Id.
//
//	string connectorId The Id of the connector.
func (c *FusionAuthClient) RetrieveConnectorWithContext(ctx context.Context, connectorId string) (*ConnectorResponse, error) {
	var resp ConnectorResponse

	err := c.Start(&resp, nil).
		WithUri("/api/connector").
		WithUriSegment(connectorId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveConnectors
// Retrieves all the connectors.
func (c *FusionAuthClient) RetrieveConnectors() (*ConnectorResponse, error) {
	return c.RetrieveConnectorsWithContext(context.TODO())
}

// RetrieveConnectorsWithContext
// Retrieves all the connectors.
func (c *FusionAuthClient) RetrieveConnectorsWithContext(ctx context.Context) (*ConnectorResponse, error) {
	var resp ConnectorResponse

	err := c.Start(&resp, nil).
		WithUri("/api/connector").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveConsent
// Retrieves the Consent for the given Id.
//
//	string consentId The Id of the consent.
func (c *FusionAuthClient) RetrieveConsent(consentId string) (*ConsentResponse, error) {
	return c.RetrieveConsentWithContext(context.TODO(), consentId)
}

// RetrieveConsentWithContext
// Retrieves the Consent for the given Id.
//
//	string consentId The Id of the consent.
func (c *FusionAuthClient) RetrieveConsentWithContext(ctx context.Context, consentId string) (*ConsentResponse, error) {
	var resp ConsentResponse

	err := c.Start(&resp, nil).
		WithUri("/api/consent").
		WithUriSegment(consentId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveConsents
// Retrieves all the consent.
func (c *FusionAuthClient) RetrieveConsents() (*ConsentResponse, error) {
	return c.RetrieveConsentsWithContext(context.TODO())
}

// RetrieveConsentsWithContext
// Retrieves all the consent.
func (c *FusionAuthClient) RetrieveConsentsWithContext(ctx context.Context) (*ConsentResponse, error) {
	var resp ConsentResponse

	err := c.Start(&resp, nil).
		WithUri("/api/consent").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveDailyActiveReport
// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
// return the daily active counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveDailyActiveReport(applicationId string, start int64, end int64) (*DailyActiveUserReportResponse, *Errors, error) {
	return c.RetrieveDailyActiveReportWithContext(context.TODO(), applicationId, start, end)
}

// RetrieveDailyActiveReportWithContext
// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
// return the daily active counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveDailyActiveReportWithContext(ctx context.Context, applicationId string, start int64, end int64) (*DailyActiveUserReportResponse, *Errors, error) {
	var resp DailyActiveUserReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/daily-active-user").
		WithParameter("applicationId", applicationId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEmailTemplate
// Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
//
//	string emailTemplateId (Optional) The Id of the email template.
func (c *FusionAuthClient) RetrieveEmailTemplate(emailTemplateId string) (*EmailTemplateResponse, error) {
	return c.RetrieveEmailTemplateWithContext(context.TODO(), emailTemplateId)
}

// RetrieveEmailTemplateWithContext
// Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
//
//	string emailTemplateId (Optional) The Id of the email template.
func (c *FusionAuthClient) RetrieveEmailTemplateWithContext(ctx context.Context, emailTemplateId string) (*EmailTemplateResponse, error) {
	var resp EmailTemplateResponse

	err := c.Start(&resp, nil).
		WithUri("/api/email/template").
		WithUriSegment(emailTemplateId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveEmailTemplatePreview
// Creates a preview of the email template provided in the request. This allows you to preview an email template that
// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
// will create the preview based on whatever is given.
//
//	PreviewRequest request The request that contains the email template and optionally a locale to render it in.
func (c *FusionAuthClient) RetrieveEmailTemplatePreview(request PreviewRequest) (*PreviewResponse, *Errors, error) {
	return c.RetrieveEmailTemplatePreviewWithContext(context.TODO(), request)
}

// RetrieveEmailTemplatePreviewWithContext
// Creates a preview of the email template provided in the request. This allows you to preview an email template that
// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
// will create the preview based on whatever is given.
//
//	PreviewRequest request The request that contains the email template and optionally a locale to render it in.
func (c *FusionAuthClient) RetrieveEmailTemplatePreviewWithContext(ctx context.Context, request PreviewRequest) (*PreviewResponse, *Errors, error) {
	var resp PreviewResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template/preview").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEmailTemplates
// Retrieves all the email templates.
func (c *FusionAuthClient) RetrieveEmailTemplates() (*EmailTemplateResponse, error) {
	return c.RetrieveEmailTemplatesWithContext(context.TODO())
}

// RetrieveEmailTemplatesWithContext
// Retrieves all the email templates.
func (c *FusionAuthClient) RetrieveEmailTemplatesWithContext(ctx context.Context) (*EmailTemplateResponse, error) {
	var resp EmailTemplateResponse

	err := c.Start(&resp, nil).
		WithUri("/api/email/template").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveEntity
// Retrieves the Entity for the given Id.
//
//	string entityId The Id of the Entity.
func (c *FusionAuthClient) RetrieveEntity(entityId string) (*EntityResponse, *Errors, error) {
	return c.RetrieveEntityWithContext(context.TODO(), entityId)
}

// RetrieveEntityWithContext
// Retrieves the Entity for the given Id.
//
//	string entityId The Id of the Entity.
func (c *FusionAuthClient) RetrieveEntityWithContext(ctx context.Context, entityId string) (*EntityResponse, *Errors, error) {
	var resp EntityResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEntityGrant
// Retrieves an Entity Grant for the given Entity and User/Entity.
//
//	string entityId The Id of the Entity.
//	string recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
//	string userId (Optional) The Id of the User that the Entity Grant is for.
func (c *FusionAuthClient) RetrieveEntityGrant(entityId string, recipientEntityId string, userId string) (*EntityGrantResponse, *Errors, error) {
	return c.RetrieveEntityGrantWithContext(context.TODO(), entityId, recipientEntityId, userId)
}

// RetrieveEntityGrantWithContext
// Retrieves an Entity Grant for the given Entity and User/Entity.
//
//	string entityId The Id of the Entity.
//	string recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
//	string userId (Optional) The Id of the User that the Entity Grant is for.
func (c *FusionAuthClient) RetrieveEntityGrantWithContext(ctx context.Context, entityId string, recipientEntityId string, userId string) (*EntityGrantResponse, *Errors, error) {
	var resp EntityGrantResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithUriSegment("grant").
		WithParameter("recipientEntityId", recipientEntityId).
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEntityType
// Retrieves the Entity Type for the given Id.
//
//	string entityTypeId The Id of the Entity Type.
func (c *FusionAuthClient) RetrieveEntityType(entityTypeId string) (*EntityTypeResponse, *Errors, error) {
	return c.RetrieveEntityTypeWithContext(context.TODO(), entityTypeId)
}

// RetrieveEntityTypeWithContext
// Retrieves the Entity Type for the given Id.
//
//	string entityTypeId The Id of the Entity Type.
func (c *FusionAuthClient) RetrieveEntityTypeWithContext(ctx context.Context, entityTypeId string) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEntityTypes
// Retrieves all the Entity Types.
func (c *FusionAuthClient) RetrieveEntityTypes() (*EntityTypeResponse, *Errors, error) {
	return c.RetrieveEntityTypesWithContext(context.TODO())
}

// RetrieveEntityTypesWithContext
// Retrieves all the Entity Types.
func (c *FusionAuthClient) RetrieveEntityTypesWithContext(ctx context.Context) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveEventLog
// Retrieves a single event log for the given Id.
//
//	int eventLogId The Id of the event log to retrieve.
func (c *FusionAuthClient) RetrieveEventLog(eventLogId int) (*EventLogResponse, *Errors, error) {
	return c.RetrieveEventLogWithContext(context.TODO(), eventLogId)
}

// RetrieveEventLogWithContext
// Retrieves a single event log for the given Id.
//
//	int eventLogId The Id of the event log to retrieve.
func (c *FusionAuthClient) RetrieveEventLogWithContext(ctx context.Context, eventLogId int) (*EventLogResponse, *Errors, error) {
	var resp EventLogResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/event-log").
		WithUriSegment(strconv.Itoa(eventLogId)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveFamilies
// Retrieves all the families that a user belongs to.
//
//	string userId The User's id
func (c *FusionAuthClient) RetrieveFamilies(userId string) (*FamilyResponse, error) {
	return c.RetrieveFamiliesWithContext(context.TODO(), userId)
}

// RetrieveFamiliesWithContext
// Retrieves all the families that a user belongs to.
//
//	string userId The User's id
func (c *FusionAuthClient) RetrieveFamiliesWithContext(ctx context.Context, userId string) (*FamilyResponse, error) {
	var resp FamilyResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/family").
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveFamilyMembersByFamilyId
// Retrieves all the members of a family by the unique Family Id.
//
//	string familyId The unique Id of the Family.
func (c *FusionAuthClient) RetrieveFamilyMembersByFamilyId(familyId string) (*FamilyResponse, error) {
	return c.RetrieveFamilyMembersByFamilyIdWithContext(context.TODO(), familyId)
}

// RetrieveFamilyMembersByFamilyIdWithContext
// Retrieves all the members of a family by the unique Family Id.
//
//	string familyId The unique Id of the Family.
func (c *FusionAuthClient) RetrieveFamilyMembersByFamilyIdWithContext(ctx context.Context, familyId string) (*FamilyResponse, error) {
	var resp FamilyResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/family").
		WithUriSegment(familyId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveForm
// Retrieves the form with the given Id.
//
//	string formId The Id of the form.
func (c *FusionAuthClient) RetrieveForm(formId string) (*FormResponse, error) {
	return c.RetrieveFormWithContext(context.TODO(), formId)
}

// RetrieveFormWithContext
// Retrieves the form with the given Id.
//
//	string formId The Id of the form.
func (c *FusionAuthClient) RetrieveFormWithContext(ctx context.Context, formId string) (*FormResponse, error) {
	var resp FormResponse

	err := c.Start(&resp, nil).
		WithUri("/api/form").
		WithUriSegment(formId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveFormField
// Retrieves the form field with the given Id.
//
//	string fieldId The Id of the form field.
func (c *FusionAuthClient) RetrieveFormField(fieldId string) (*FormFieldResponse, error) {
	return c.RetrieveFormFieldWithContext(context.TODO(), fieldId)
}

// RetrieveFormFieldWithContext
// Retrieves the form field with the given Id.
//
//	string fieldId The Id of the form field.
func (c *FusionAuthClient) RetrieveFormFieldWithContext(ctx context.Context, fieldId string) (*FormFieldResponse, error) {
	var resp FormFieldResponse

	err := c.Start(&resp, nil).
		WithUri("/api/form/field").
		WithUriSegment(fieldId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveFormFields
// Retrieves all the forms fields
func (c *FusionAuthClient) RetrieveFormFields() (*FormFieldResponse, error) {
	return c.RetrieveFormFieldsWithContext(context.TODO())
}

// RetrieveFormFieldsWithContext
// Retrieves all the forms fields
func (c *FusionAuthClient) RetrieveFormFieldsWithContext(ctx context.Context) (*FormFieldResponse, error) {
	var resp FormFieldResponse

	err := c.Start(&resp, nil).
		WithUri("/api/form/field").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveForms
// Retrieves all the forms.
func (c *FusionAuthClient) RetrieveForms() (*FormResponse, error) {
	return c.RetrieveFormsWithContext(context.TODO())
}

// RetrieveFormsWithContext
// Retrieves all the forms.
func (c *FusionAuthClient) RetrieveFormsWithContext(ctx context.Context) (*FormResponse, error) {
	var resp FormResponse

	err := c.Start(&resp, nil).
		WithUri("/api/form").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveGroup
// Retrieves the group for the given Id.
//
//	string groupId The Id of the group.
func (c *FusionAuthClient) RetrieveGroup(groupId string) (*GroupResponse, *Errors, error) {
	return c.RetrieveGroupWithContext(context.TODO(), groupId)
}

// RetrieveGroupWithContext
// Retrieves the group for the given Id.
//
//	string groupId The Id of the group.
func (c *FusionAuthClient) RetrieveGroupWithContext(ctx context.Context, groupId string) (*GroupResponse, *Errors, error) {
	var resp GroupResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group").
		WithUriSegment(groupId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveGroups
// Retrieves all the groups.
func (c *FusionAuthClient) RetrieveGroups() (*GroupResponse, error) {
	return c.RetrieveGroupsWithContext(context.TODO())
}

// RetrieveGroupsWithContext
// Retrieves all the groups.
func (c *FusionAuthClient) RetrieveGroupsWithContext(ctx context.Context) (*GroupResponse, error) {
	var resp GroupResponse

	err := c.Start(&resp, nil).
		WithUri("/api/group").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveIPAccessControlList
// Retrieves the IP Access Control List with the given Id.
//
//	string ipAccessControlListId The Id of the IP Access Control List.
func (c *FusionAuthClient) RetrieveIPAccessControlList(ipAccessControlListId string) (*IPAccessControlListResponse, error) {
	return c.RetrieveIPAccessControlListWithContext(context.TODO(), ipAccessControlListId)
}

// RetrieveIPAccessControlListWithContext
// Retrieves the IP Access Control List with the given Id.
//
//	string ipAccessControlListId The Id of the IP Access Control List.
func (c *FusionAuthClient) RetrieveIPAccessControlListWithContext(ctx context.Context, ipAccessControlListId string) (*IPAccessControlListResponse, error) {
	var resp IPAccessControlListResponse

	err := c.Start(&resp, nil).
		WithUri("/api/ip-acl").
		WithUriSegment(ipAccessControlListId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveIdentityProviderByType
// Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single
// identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request
// may return multiple identity providers.
//
//	IdentityProviderType _type The type of the identity provider.
func (c *FusionAuthClient) RetrieveIdentityProviderByType(_type IdentityProviderType) (*IdentityProviderResponse, *Errors, error) {
	return c.RetrieveIdentityProviderByTypeWithContext(context.TODO(), _type)
}

// RetrieveIdentityProviderByTypeWithContext
// Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single
// identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request
// may return multiple identity providers.
//
//	IdentityProviderType _type The type of the identity provider.
func (c *FusionAuthClient) RetrieveIdentityProviderByTypeWithContext(ctx context.Context, _type IdentityProviderType) (*IdentityProviderResponse, *Errors, error) {
	var resp IdentityProviderResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider").
		WithParameter("type", string(_type)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveInactiveActions
// Retrieves all the actions for the user with the given Id that are currently inactive.
// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveInactiveActions(userId string) (*ActionResponse, *Errors, error) {
	return c.RetrieveInactiveActionsWithContext(context.TODO(), userId)
}

// RetrieveInactiveActionsWithContext
// Retrieves all the actions for the user with the given Id that are currently inactive.
// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
//
//	string userId The Id of the user to fetch the actions for.
func (c *FusionAuthClient) RetrieveInactiveActionsWithContext(ctx context.Context, userId string) (*ActionResponse, *Errors, error) {
	var resp ActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/action").
		WithParameter("userId", userId).
		WithParameter("active", strconv.FormatBool(false)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveInactiveApplications
// Retrieves all the applications that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveApplications() (*ApplicationResponse, error) {
	return c.RetrieveInactiveApplicationsWithContext(context.TODO())
}

// RetrieveInactiveApplicationsWithContext
// Retrieves all the applications that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveApplicationsWithContext(ctx context.Context) (*ApplicationResponse, error) {
	var resp ApplicationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/application").
		WithParameter("inactive", strconv.FormatBool(true)).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveInactiveUserActions
// Retrieves all the user actions that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveUserActions() (*UserActionResponse, error) {
	return c.RetrieveInactiveUserActionsWithContext(context.TODO())
}

// RetrieveInactiveUserActionsWithContext
// Retrieves all the user actions that are currently inactive.
func (c *FusionAuthClient) RetrieveInactiveUserActionsWithContext(ctx context.Context) (*UserActionResponse, error) {
	var resp UserActionResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user-action").
		WithParameter("inactive", strconv.FormatBool(true)).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveIntegration
// Retrieves the available integrations.
func (c *FusionAuthClient) RetrieveIntegration() (*IntegrationResponse, error) {
	return c.RetrieveIntegrationWithContext(context.TODO())
}

// RetrieveIntegrationWithContext
// Retrieves the available integrations.
func (c *FusionAuthClient) RetrieveIntegrationWithContext(ctx context.Context) (*IntegrationResponse, error) {
	var resp IntegrationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/integration").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveJWTPublicKey
// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
//
//	string keyId The Id of the public key (kid).
func (c *FusionAuthClient) RetrieveJWTPublicKey(keyId string) (*PublicKeyResponse, error) {
	return c.RetrieveJWTPublicKeyWithContext(context.TODO(), keyId)
}

// RetrieveJWTPublicKeyWithContext
// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
//
//	string keyId The Id of the public key (kid).
func (c *FusionAuthClient) RetrieveJWTPublicKeyWithContext(ctx context.Context, keyId string) (*PublicKeyResponse, error) {
	var resp PublicKeyResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/jwt/public-key").
		WithParameter("kid", keyId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveJWTPublicKeyByApplicationId
// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
//
//	string applicationId The Id of the Application for which this key is used.
func (c *FusionAuthClient) RetrieveJWTPublicKeyByApplicationId(applicationId string) (*PublicKeyResponse, error) {
	return c.RetrieveJWTPublicKeyByApplicationIdWithContext(context.TODO(), applicationId)
}

// RetrieveJWTPublicKeyByApplicationIdWithContext
// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
//
//	string applicationId The Id of the Application for which this key is used.
func (c *FusionAuthClient) RetrieveJWTPublicKeyByApplicationIdWithContext(ctx context.Context, applicationId string) (*PublicKeyResponse, error) {
	var resp PublicKeyResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/jwt/public-key").
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveJWTPublicKeys
// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
func (c *FusionAuthClient) RetrieveJWTPublicKeys() (*PublicKeyResponse, error) {
	return c.RetrieveJWTPublicKeysWithContext(context.TODO())
}

// RetrieveJWTPublicKeysWithContext
// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
func (c *FusionAuthClient) RetrieveJWTPublicKeysWithContext(ctx context.Context) (*PublicKeyResponse, error) {
	var resp PublicKeyResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/jwt/public-key").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveJsonWebKeySet
// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
func (c *FusionAuthClient) RetrieveJsonWebKeySet() (*JWKSResponse, error) {
	return c.RetrieveJsonWebKeySetWithContext(context.TODO())
}

// RetrieveJsonWebKeySetWithContext
// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
func (c *FusionAuthClient) RetrieveJsonWebKeySetWithContext(ctx context.Context) (*JWKSResponse, error) {
	var resp JWKSResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/.well-known/jwks.json").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveKey
// Retrieves the key for the given Id.
//
//	string keyId The Id of the key.
func (c *FusionAuthClient) RetrieveKey(keyId string) (*KeyResponse, *Errors, error) {
	return c.RetrieveKeyWithContext(context.TODO(), keyId)
}

// RetrieveKeyWithContext
// Retrieves the key for the given Id.
//
//	string keyId The Id of the key.
func (c *FusionAuthClient) RetrieveKeyWithContext(ctx context.Context, keyId string) (*KeyResponse, *Errors, error) {
	var resp KeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key").
		WithUriSegment(keyId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveKeys
// Retrieves all the keys.
func (c *FusionAuthClient) RetrieveKeys() (*KeyResponse, error) {
	return c.RetrieveKeysWithContext(context.TODO())
}

// RetrieveKeysWithContext
// Retrieves all the keys.
func (c *FusionAuthClient) RetrieveKeysWithContext(ctx context.Context) (*KeyResponse, error) {
	var resp KeyResponse

	err := c.Start(&resp, nil).
		WithUri("/api/key").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveLambda
// Retrieves the lambda for the given Id.
//
//	string lambdaId The Id of the lambda.
func (c *FusionAuthClient) RetrieveLambda(lambdaId string) (*LambdaResponse, *Errors, error) {
	return c.RetrieveLambdaWithContext(context.TODO(), lambdaId)
}

// RetrieveLambdaWithContext
// Retrieves the lambda for the given Id.
//
//	string lambdaId The Id of the lambda.
func (c *FusionAuthClient) RetrieveLambdaWithContext(ctx context.Context, lambdaId string) (*LambdaResponse, *Errors, error) {
	var resp LambdaResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda").
		WithUriSegment(lambdaId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveLambdas
// Retrieves all the lambdas.
func (c *FusionAuthClient) RetrieveLambdas() (*LambdaResponse, error) {
	return c.RetrieveLambdasWithContext(context.TODO())
}

// RetrieveLambdasWithContext
// Retrieves all the lambdas.
func (c *FusionAuthClient) RetrieveLambdasWithContext(ctx context.Context) (*LambdaResponse, error) {
	var resp LambdaResponse

	err := c.Start(&resp, nil).
		WithUri("/api/lambda").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveLambdasByType
// Retrieves all the lambdas for the provided type.
//
//	LambdaType _type The type of the lambda to return.
func (c *FusionAuthClient) RetrieveLambdasByType(_type LambdaType) (*LambdaResponse, error) {
	return c.RetrieveLambdasByTypeWithContext(context.TODO(), _type)
}

// RetrieveLambdasByTypeWithContext
// Retrieves all the lambdas for the provided type.
//
//	LambdaType _type The type of the lambda to return.
func (c *FusionAuthClient) RetrieveLambdasByTypeWithContext(ctx context.Context, _type LambdaType) (*LambdaResponse, error) {
	var resp LambdaResponse

	err := c.Start(&resp, nil).
		WithUri("/api/lambda").
		WithParameter("type", string(_type)).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveLoginReport
// Retrieves the login report between the two instants. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveLoginReport(applicationId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	return c.RetrieveLoginReportWithContext(context.TODO(), applicationId, start, end)
}

// RetrieveLoginReportWithContext
// Retrieves the login report between the two instants. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveLoginReportWithContext(ctx context.Context, applicationId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	var resp LoginReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/login").
		WithParameter("applicationId", applicationId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveMessageTemplate
// Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
//
//	string messageTemplateId (Optional) The Id of the message template.
func (c *FusionAuthClient) RetrieveMessageTemplate(messageTemplateId string) (*MessageTemplateResponse, error) {
	return c.RetrieveMessageTemplateWithContext(context.TODO(), messageTemplateId)
}

// RetrieveMessageTemplateWithContext
// Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
//
//	string messageTemplateId (Optional) The Id of the message template.
func (c *FusionAuthClient) RetrieveMessageTemplateWithContext(ctx context.Context, messageTemplateId string) (*MessageTemplateResponse, error) {
	var resp MessageTemplateResponse

	err := c.Start(&resp, nil).
		WithUri("/api/message/template").
		WithUriSegment(messageTemplateId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveMessageTemplatePreview
// Creates a preview of the message template provided in the request, normalized to a given locale.
//
//	PreviewMessageTemplateRequest request The request that contains the email template and optionally a locale to render it in.
func (c *FusionAuthClient) RetrieveMessageTemplatePreview(request PreviewMessageTemplateRequest) (*PreviewMessageTemplateResponse, *Errors, error) {
	return c.RetrieveMessageTemplatePreviewWithContext(context.TODO(), request)
}

// RetrieveMessageTemplatePreviewWithContext
// Creates a preview of the message template provided in the request, normalized to a given locale.
//
//	PreviewMessageTemplateRequest request The request that contains the email template and optionally a locale to render it in.
func (c *FusionAuthClient) RetrieveMessageTemplatePreviewWithContext(ctx context.Context, request PreviewMessageTemplateRequest) (*PreviewMessageTemplateResponse, *Errors, error) {
	var resp PreviewMessageTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/message/template/preview").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveMessageTemplates
// Retrieves all the message templates.
func (c *FusionAuthClient) RetrieveMessageTemplates() (*MessageTemplateResponse, error) {
	return c.RetrieveMessageTemplatesWithContext(context.TODO())
}

// RetrieveMessageTemplatesWithContext
// Retrieves all the message templates.
func (c *FusionAuthClient) RetrieveMessageTemplatesWithContext(ctx context.Context) (*MessageTemplateResponse, error) {
	var resp MessageTemplateResponse

	err := c.Start(&resp, nil).
		WithUri("/api/message/template").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveMessenger
// Retrieves the messenger with the given Id.
//
//	string messengerId The Id of the messenger.
func (c *FusionAuthClient) RetrieveMessenger(messengerId string) (*MessengerResponse, error) {
	return c.RetrieveMessengerWithContext(context.TODO(), messengerId)
}

// RetrieveMessengerWithContext
// Retrieves the messenger with the given Id.
//
//	string messengerId The Id of the messenger.
func (c *FusionAuthClient) RetrieveMessengerWithContext(ctx context.Context, messengerId string) (*MessengerResponse, error) {
	var resp MessengerResponse

	err := c.Start(&resp, nil).
		WithUri("/api/messenger").
		WithUriSegment(messengerId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveMessengers
// Retrieves all the messengers.
func (c *FusionAuthClient) RetrieveMessengers() (*MessengerResponse, error) {
	return c.RetrieveMessengersWithContext(context.TODO())
}

// RetrieveMessengersWithContext
// Retrieves all the messengers.
func (c *FusionAuthClient) RetrieveMessengersWithContext(ctx context.Context) (*MessengerResponse, error) {
	var resp MessengerResponse

	err := c.Start(&resp, nil).
		WithUri("/api/messenger").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveMonthlyActiveReport
// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
// return the monthly active counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveMonthlyActiveReport(applicationId string, start int64, end int64) (*MonthlyActiveUserReportResponse, *Errors, error) {
	return c.RetrieveMonthlyActiveReportWithContext(context.TODO(), applicationId, start, end)
}

// RetrieveMonthlyActiveReportWithContext
// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
// return the monthly active counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveMonthlyActiveReportWithContext(ctx context.Context, applicationId string, start int64, end int64) (*MonthlyActiveUserReportResponse, *Errors, error) {
	var resp MonthlyActiveUserReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/monthly-active-user").
		WithParameter("applicationId", applicationId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveOauthConfiguration
// Retrieves the Oauth2 configuration for the application for the given Application Id.
//
//	string applicationId The Id of the Application to retrieve OAuth configuration.
func (c *FusionAuthClient) RetrieveOauthConfiguration(applicationId string) (*OAuthConfigurationResponse, *Errors, error) {
	return c.RetrieveOauthConfigurationWithContext(context.TODO(), applicationId)
}

// RetrieveOauthConfigurationWithContext
// Retrieves the Oauth2 configuration for the application for the given Application Id.
//
//	string applicationId The Id of the Application to retrieve OAuth configuration.
func (c *FusionAuthClient) RetrieveOauthConfigurationWithContext(ctx context.Context, applicationId string) (*OAuthConfigurationResponse, *Errors, error) {
	var resp OAuthConfigurationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithUriSegment("oauth-configuration").
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveOpenIdConfiguration
// Returns the well known OpenID Configuration JSON document
func (c *FusionAuthClient) RetrieveOpenIdConfiguration() (*OpenIdConfiguration, error) {
	return c.RetrieveOpenIdConfigurationWithContext(context.TODO())
}

// RetrieveOpenIdConfigurationWithContext
// Returns the well known OpenID Configuration JSON document
func (c *FusionAuthClient) RetrieveOpenIdConfigurationWithContext(ctx context.Context) (*OpenIdConfiguration, error) {
	var resp OpenIdConfiguration

	err := c.StartAnonymous(&resp, nil).
		WithUri("/.well-known/openid-configuration").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrievePasswordValidationRules
// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided
// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
//
// This API does not require an API key.
func (c *FusionAuthClient) RetrievePasswordValidationRules() (*PasswordValidationRulesResponse, error) {
	return c.RetrievePasswordValidationRulesWithContext(context.TODO())
}

// RetrievePasswordValidationRulesWithContext
// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided
// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
//
// This API does not require an API key.
func (c *FusionAuthClient) RetrievePasswordValidationRulesWithContext(ctx context.Context) (*PasswordValidationRulesResponse, error) {
	var resp PasswordValidationRulesResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/tenant/password-validation-rules").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrievePasswordValidationRulesWithTenantId
// Retrieves the password validation rules for a specific tenant.
//
// This API does not require an API key.
//
//	string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrievePasswordValidationRulesWithTenantId(tenantId string) (*PasswordValidationRulesResponse, error) {
	return c.RetrievePasswordValidationRulesWithTenantIdWithContext(context.TODO(), tenantId)
}

// RetrievePasswordValidationRulesWithTenantIdWithContext
// Retrieves the password validation rules for a specific tenant.
//
// This API does not require an API key.
//
//	string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrievePasswordValidationRulesWithTenantIdWithContext(ctx context.Context, tenantId string) (*PasswordValidationRulesResponse, error) {
	var resp PasswordValidationRulesResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/tenant/password-validation-rules").
		WithUriSegment(tenantId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrievePendingChildren
// Retrieves all the children for the given parent email address.
//
//	string parentEmail The email of the parent.
func (c *FusionAuthClient) RetrievePendingChildren(parentEmail string) (*PendingResponse, *Errors, error) {
	return c.RetrievePendingChildrenWithContext(context.TODO(), parentEmail)
}

// RetrievePendingChildrenWithContext
// Retrieves all the children for the given parent email address.
//
//	string parentEmail The email of the parent.
func (c *FusionAuthClient) RetrievePendingChildrenWithContext(ctx context.Context, parentEmail string) (*PendingResponse, *Errors, error) {
	var resp PendingResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/family/pending").
		WithParameter("parentEmail", parentEmail).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrievePendingLink
// Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
//
//	string pendingLinkId The pending link Id.
//	string userId The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.
func (c *FusionAuthClient) RetrievePendingLink(pendingLinkId string, userId string) (*IdentityProviderPendingLinkResponse, *Errors, error) {
	return c.RetrievePendingLinkWithContext(context.TODO(), pendingLinkId, userId)
}

// RetrievePendingLinkWithContext
// Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
//
//	string pendingLinkId The pending link Id.
//	string userId The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.
func (c *FusionAuthClient) RetrievePendingLinkWithContext(ctx context.Context, pendingLinkId string, userId string) (*IdentityProviderPendingLinkResponse, *Errors, error) {
	var resp IdentityProviderPendingLinkResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/link/pending").
		WithUriSegment(pendingLinkId).
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveReactorMetrics
// Retrieves the FusionAuth Reactor metrics.
func (c *FusionAuthClient) RetrieveReactorMetrics() (*ReactorMetricsResponse, error) {
	return c.RetrieveReactorMetricsWithContext(context.TODO())
}

// RetrieveReactorMetricsWithContext
// Retrieves the FusionAuth Reactor metrics.
func (c *FusionAuthClient) RetrieveReactorMetricsWithContext(ctx context.Context) (*ReactorMetricsResponse, error) {
	var resp ReactorMetricsResponse

	err := c.Start(&resp, nil).
		WithUri("/api/reactor/metrics").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveReactorStatus
// Retrieves the FusionAuth Reactor status.
func (c *FusionAuthClient) RetrieveReactorStatus() (*ReactorResponse, error) {
	return c.RetrieveReactorStatusWithContext(context.TODO())
}

// RetrieveReactorStatusWithContext
// Retrieves the FusionAuth Reactor status.
func (c *FusionAuthClient) RetrieveReactorStatusWithContext(ctx context.Context) (*ReactorResponse, error) {
	var resp ReactorResponse

	err := c.Start(&resp, nil).
		WithUri("/api/reactor").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveRecentLogins
// Retrieves the last number of login records.
//
//	int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//	int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveRecentLogins(offset int, limit int) (*RecentLoginResponse, *Errors, error) {
	return c.RetrieveRecentLoginsWithContext(context.TODO(), offset, limit)
}

// RetrieveRecentLoginsWithContext
// Retrieves the last number of login records.
//
//	int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//	int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveRecentLoginsWithContext(ctx context.Context, offset int, limit int) (*RecentLoginResponse, *Errors, error) {
	var resp RecentLoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/recent-login").
		WithParameter("offset", strconv.Itoa(offset)).
		WithParameter("limit", strconv.Itoa(limit)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveRefreshTokenById
// Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
//
//	string tokenId The Id of the token.
func (c *FusionAuthClient) RetrieveRefreshTokenById(tokenId string) (*RefreshTokenResponse, *Errors, error) {
	return c.RetrieveRefreshTokenByIdWithContext(context.TODO(), tokenId)
}

// RetrieveRefreshTokenByIdWithContext
// Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
//
//	string tokenId The Id of the token.
func (c *FusionAuthClient) RetrieveRefreshTokenByIdWithContext(ctx context.Context, tokenId string) (*RefreshTokenResponse, *Errors, error) {
	var resp RefreshTokenResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithUriSegment(tokenId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveRefreshTokens
// Retrieves the refresh tokens that belong to the user with the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveRefreshTokens(userId string) (*RefreshTokenResponse, *Errors, error) {
	return c.RetrieveRefreshTokensWithContext(context.TODO(), userId)
}

// RetrieveRefreshTokensWithContext
// Retrieves the refresh tokens that belong to the user with the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveRefreshTokensWithContext(ctx context.Context, userId string) (*RefreshTokenResponse, *Errors, error) {
	var resp RefreshTokenResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveRegistration
// Retrieves the user registration for the user with the given id and the given application id.
//
//	string userId The Id of the user.
//	string applicationId The Id of the application.
func (c *FusionAuthClient) RetrieveRegistration(userId string, applicationId string) (*RegistrationResponse, *Errors, error) {
	return c.RetrieveRegistrationWithContext(context.TODO(), userId, applicationId)
}

// RetrieveRegistrationWithContext
// Retrieves the user registration for the user with the given id and the given application id.
//
//	string userId The Id of the user.
//	string applicationId The Id of the application.
func (c *FusionAuthClient) RetrieveRegistrationWithContext(ctx context.Context, userId string, applicationId string) (*RegistrationResponse, *Errors, error) {
	var resp RegistrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithUriSegment(applicationId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveRegistrationReport
// Retrieves the registration report between the two instants. If you specify an application id, it will only return
// the registration counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveRegistrationReport(applicationId string, start int64, end int64) (*RegistrationReportResponse, *Errors, error) {
	return c.RetrieveRegistrationReportWithContext(context.TODO(), applicationId, start, end)
}

// RetrieveRegistrationReportWithContext
// Retrieves the registration report between the two instants. If you specify an application id, it will only return
// the registration counts for that application.
//
//	string applicationId (Optional) The application id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveRegistrationReportWithContext(ctx context.Context, applicationId string, start int64, end int64) (*RegistrationReportResponse, *Errors, error) {
	var resp RegistrationReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/registration").
		WithParameter("applicationId", applicationId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveReindexStatus
// Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of
// 404 indicates no re-index is in progress.
func (c *FusionAuthClient) RetrieveReindexStatus() (*BaseHTTPResponse, *Errors, error) {
	return c.RetrieveReindexStatusWithContext(context.TODO())
}

// RetrieveReindexStatusWithContext
// Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of
// 404 indicates no re-index is in progress.
func (c *FusionAuthClient) RetrieveReindexStatusWithContext(ctx context.Context) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/reindex").
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveSystemConfiguration
// Retrieves the system configuration.
func (c *FusionAuthClient) RetrieveSystemConfiguration() (*SystemConfigurationResponse, error) {
	return c.RetrieveSystemConfigurationWithContext(context.TODO())
}

// RetrieveSystemConfigurationWithContext
// Retrieves the system configuration.
func (c *FusionAuthClient) RetrieveSystemConfigurationWithContext(ctx context.Context) (*SystemConfigurationResponse, error) {
	var resp SystemConfigurationResponse

	err := c.Start(&resp, nil).
		WithUri("/api/system-configuration").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveTenant
// Retrieves the tenant for the given Id.
//
//	string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrieveTenant(tenantId string) (*TenantResponse, *Errors, error) {
	return c.RetrieveTenantWithContext(context.TODO(), tenantId)
}

// RetrieveTenantWithContext
// Retrieves the tenant for the given Id.
//
//	string tenantId The Id of the tenant.
func (c *FusionAuthClient) RetrieveTenantWithContext(ctx context.Context, tenantId string) (*TenantResponse, *Errors, error) {
	var resp TenantResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveTenants
// Retrieves all the tenants.
func (c *FusionAuthClient) RetrieveTenants() (*TenantResponse, error) {
	return c.RetrieveTenantsWithContext(context.TODO())
}

// RetrieveTenantsWithContext
// Retrieves all the tenants.
func (c *FusionAuthClient) RetrieveTenantsWithContext(ctx context.Context) (*TenantResponse, error) {
	var resp TenantResponse

	err := c.Start(&resp, nil).
		WithUri("/api/tenant").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveTheme
// Retrieves the theme for the given Id.
//
//	string themeId The Id of the theme.
func (c *FusionAuthClient) RetrieveTheme(themeId string) (*ThemeResponse, *Errors, error) {
	return c.RetrieveThemeWithContext(context.TODO(), themeId)
}

// RetrieveThemeWithContext
// Retrieves the theme for the given Id.
//
//	string themeId The Id of the theme.
func (c *FusionAuthClient) RetrieveThemeWithContext(ctx context.Context, themeId string) (*ThemeResponse, *Errors, error) {
	var resp ThemeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme").
		WithUriSegment(themeId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveThemes
// Retrieves all the themes.
func (c *FusionAuthClient) RetrieveThemes() (*ThemeResponse, error) {
	return c.RetrieveThemesWithContext(context.TODO())
}

// RetrieveThemesWithContext
// Retrieves all the themes.
func (c *FusionAuthClient) RetrieveThemesWithContext(ctx context.Context) (*ThemeResponse, error) {
	var resp ThemeResponse

	err := c.Start(&resp, nil).
		WithUri("/api/theme").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveTotalReport
// Retrieves the totals report. This contains all the total counts for each application and the global registration
// count.
func (c *FusionAuthClient) RetrieveTotalReport() (*TotalsReportResponse, error) {
	return c.RetrieveTotalReportWithContext(context.TODO())
}

// RetrieveTotalReportWithContext
// Retrieves the totals report. This contains all the total counts for each application and the global registration
// count.
func (c *FusionAuthClient) RetrieveTotalReportWithContext(ctx context.Context) (*TotalsReportResponse, error) {
	var resp TotalsReportResponse

	err := c.Start(&resp, nil).
		WithUri("/api/report/totals").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveTwoFactorRecoveryCodes
// Retrieve two-factor recovery codes for a user.
//
//	string userId The Id of the user to retrieve Two Factor recovery codes.
func (c *FusionAuthClient) RetrieveTwoFactorRecoveryCodes(userId string) (*TwoFactorRecoveryCodeResponse, *Errors, error) {
	return c.RetrieveTwoFactorRecoveryCodesWithContext(context.TODO(), userId)
}

// RetrieveTwoFactorRecoveryCodesWithContext
// Retrieve two-factor recovery codes for a user.
//
//	string userId The Id of the user to retrieve Two Factor recovery codes.
func (c *FusionAuthClient) RetrieveTwoFactorRecoveryCodesWithContext(ctx context.Context, userId string) (*TwoFactorRecoveryCodeResponse, *Errors, error) {
	var resp TwoFactorRecoveryCodeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/two-factor/recovery-code").
		WithUriSegment(userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveTwoFactorStatus
// Retrieve a user's two-factor status.
//
// This can be used to see if a user will need to complete a two-factor challenge to complete a login,
// and optionally identify the state of the two-factor trust across various applications.
//
//	string userId The user Id to retrieve the Two-Factor status.
//	string applicationId The optional applicationId to verify.
//	string twoFactorTrustId The optional two-factor trust Id to verify.
func (c *FusionAuthClient) RetrieveTwoFactorStatus(userId string, applicationId string, twoFactorTrustId string) (*TwoFactorStatusResponse, *Errors, error) {
	return c.RetrieveTwoFactorStatusWithContext(context.TODO(), userId, applicationId, twoFactorTrustId)
}

// RetrieveTwoFactorStatusWithContext
// Retrieve a user's two-factor status.
//
// This can be used to see if a user will need to complete a two-factor challenge to complete a login,
// and optionally identify the state of the two-factor trust across various applications.
//
//	string userId The user Id to retrieve the Two-Factor status.
//	string applicationId The optional applicationId to verify.
//	string twoFactorTrustId The optional two-factor trust Id to verify.
func (c *FusionAuthClient) RetrieveTwoFactorStatusWithContext(ctx context.Context, userId string, applicationId string, twoFactorTrustId string) (*TwoFactorStatusResponse, *Errors, error) {
	var resp TwoFactorStatusResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/status").
		WithParameter("userId", userId).
		WithParameter("applicationId", applicationId).
		WithUriSegment(twoFactorTrustId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUser
// Retrieves the user for the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUser(userId string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserWithContext(context.TODO(), userId)
}

// RetrieveUserWithContext
// Retrieves the user for the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUserWithContext(ctx context.Context, userId string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserAction
// Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
// actions.
//
//	string userActionId (Optional) The Id of the user action.
func (c *FusionAuthClient) RetrieveUserAction(userActionId string) (*UserActionResponse, error) {
	return c.RetrieveUserActionWithContext(context.TODO(), userActionId)
}

// RetrieveUserActionWithContext
// Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
// actions.
//
//	string userActionId (Optional) The Id of the user action.
func (c *FusionAuthClient) RetrieveUserActionWithContext(ctx context.Context, userActionId string) (*UserActionResponse, error) {
	var resp UserActionResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserActionReason
// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
// action reasons.
//
//	string userActionReasonId (Optional) The Id of the user action reason.
func (c *FusionAuthClient) RetrieveUserActionReason(userActionReasonId string) (*UserActionReasonResponse, error) {
	return c.RetrieveUserActionReasonWithContext(context.TODO(), userActionReasonId)
}

// RetrieveUserActionReasonWithContext
// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
// action reasons.
//
//	string userActionReasonId (Optional) The Id of the user action reason.
func (c *FusionAuthClient) RetrieveUserActionReasonWithContext(ctx context.Context, userActionReasonId string) (*UserActionReasonResponse, error) {
	var resp UserActionReasonResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user-action-reason").
		WithUriSegment(userActionReasonId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserActionReasons
// Retrieves all the user action reasons.
func (c *FusionAuthClient) RetrieveUserActionReasons() (*UserActionReasonResponse, error) {
	return c.RetrieveUserActionReasonsWithContext(context.TODO())
}

// RetrieveUserActionReasonsWithContext
// Retrieves all the user action reasons.
func (c *FusionAuthClient) RetrieveUserActionReasonsWithContext(ctx context.Context) (*UserActionReasonResponse, error) {
	var resp UserActionReasonResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user-action-reason").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserActions
// Retrieves all the user actions.
func (c *FusionAuthClient) RetrieveUserActions() (*UserActionResponse, error) {
	return c.RetrieveUserActionsWithContext(context.TODO())
}

// RetrieveUserActionsWithContext
// Retrieves all the user actions.
func (c *FusionAuthClient) RetrieveUserActionsWithContext(ctx context.Context) (*UserActionResponse, error) {
	var resp UserActionResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user-action").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserByChangePasswordId
// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//
//	string changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
func (c *FusionAuthClient) RetrieveUserByChangePasswordId(changePasswordId string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserByChangePasswordIdWithContext(context.TODO(), changePasswordId)
}

// RetrieveUserByChangePasswordIdWithContext
// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//
//	string changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
func (c *FusionAuthClient) RetrieveUserByChangePasswordIdWithContext(ctx context.Context, changePasswordId string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithParameter("changePasswordId", changePasswordId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserByEmail
// Retrieves the user for the given email.
//
//	string email The email of the user.
func (c *FusionAuthClient) RetrieveUserByEmail(email string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserByEmailWithContext(context.TODO(), email)
}

// RetrieveUserByEmailWithContext
// Retrieves the user for the given email.
//
//	string email The email of the user.
func (c *FusionAuthClient) RetrieveUserByEmailWithContext(ctx context.Context, email string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithParameter("email", email).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserByLoginId
// Retrieves the user for the loginId. The loginId can be either the username or the email.
//
//	string loginId The email or username of the user.
func (c *FusionAuthClient) RetrieveUserByLoginId(loginId string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserByLoginIdWithContext(context.TODO(), loginId)
}

// RetrieveUserByLoginIdWithContext
// Retrieves the user for the loginId. The loginId can be either the username or the email.
//
//	string loginId The email or username of the user.
func (c *FusionAuthClient) RetrieveUserByLoginIdWithContext(ctx context.Context, loginId string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithParameter("loginId", loginId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserByUsername
// Retrieves the user for the given username.
//
//	string username The username of the user.
func (c *FusionAuthClient) RetrieveUserByUsername(username string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserByUsernameWithContext(context.TODO(), username)
}

// RetrieveUserByUsernameWithContext
// Retrieves the user for the given username.
//
//	string username The username of the user.
func (c *FusionAuthClient) RetrieveUserByUsernameWithContext(ctx context.Context, username string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithParameter("username", username).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserByVerificationId
// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//
//	string verificationId The unique verification Id that has been set on the user object.
func (c *FusionAuthClient) RetrieveUserByVerificationId(verificationId string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserByVerificationIdWithContext(context.TODO(), verificationId)
}

// RetrieveUserByVerificationIdWithContext
// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
// password workflow has been initiated and you may not know the user's email or username.
//
//	string verificationId The unique verification Id that has been set on the user object.
func (c *FusionAuthClient) RetrieveUserByVerificationIdWithContext(ctx context.Context, verificationId string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithParameter("verificationId", verificationId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserCode
// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
//
// This API is useful if you want to build your own login workflow to complete a device grant.
//
//	string clientId The client id.
//	string clientSecret The client id.
//	string userCode The end-user verification code.
func (c *FusionAuthClient) RetrieveUserCode(clientId string, clientSecret string, userCode string) (*BaseHTTPResponse, error) {
	return c.RetrieveUserCodeWithContext(context.TODO(), clientId, clientSecret, userCode)
}

// RetrieveUserCodeWithContext
// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
//
// This API is useful if you want to build your own login workflow to complete a device grant.
//
//	string clientId The client id.
//	string clientSecret The client id.
//	string userCode The end-user verification code.
func (c *FusionAuthClient) RetrieveUserCodeWithContext(ctx context.Context, clientId string, clientSecret string, userCode string) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse
	formBody := url.Values{}
	formBody.Set("client_id", clientId)
	formBody.Set("client_secret", clientSecret)
	formBody.Set("user_code", userCode)

	err := c.StartAnonymous(&resp, nil).
		WithUri("/oauth2/device/user-code").
		WithFormData(formBody).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserCode
// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
//
// This API is useful if you want to build your own login workflow to complete a device grant.
//
// This request will require an API key.
//
//	string userCode The end-user verification code.
func (c *FusionAuthClient) RetrieveUserCode(userCode string) (*BaseHTTPResponse, error) {
	return c.RetrieveUserCodeWithContext(context.TODO(), userCode)
}

// RetrieveUserCodeWithContext
// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
//
// This API is useful if you want to build your own login workflow to complete a device grant.
//
// This request will require an API key.
//
//	string userCode The end-user verification code.
func (c *FusionAuthClient) RetrieveUserCodeWithContext(ctx context.Context, userCode string) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse
	formBody := url.Values{}
	formBody.Set("user_code", userCode)

	err := c.StartAnonymous(&resp, nil).
		WithUri("/oauth2/device/user-code").
		WithFormData(formBody).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserComments
// Retrieves all the comments for the user with the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUserComments(userId string) (*UserCommentResponse, *Errors, error) {
	return c.RetrieveUserCommentsWithContext(context.TODO(), userId)
}

// RetrieveUserCommentsWithContext
// Retrieves all the comments for the user with the given Id.
//
//	string userId The Id of the user.
func (c *FusionAuthClient) RetrieveUserCommentsWithContext(ctx context.Context, userId string) (*UserCommentResponse, *Errors, error) {
	var resp UserCommentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/comment").
		WithUriSegment(userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserConsent
// Retrieve a single User consent by Id.
//
//	string userConsentId The User consent Id
func (c *FusionAuthClient) RetrieveUserConsent(userConsentId string) (*UserConsentResponse, error) {
	return c.RetrieveUserConsentWithContext(context.TODO(), userConsentId)
}

// RetrieveUserConsentWithContext
// Retrieve a single User consent by Id.
//
//	string userConsentId The User consent Id
func (c *FusionAuthClient) RetrieveUserConsentWithContext(ctx context.Context, userConsentId string) (*UserConsentResponse, error) {
	var resp UserConsentResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/consent").
		WithUriSegment(userConsentId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserConsents
// Retrieves all the consents for a User.
//
//	string userId The User's Id
func (c *FusionAuthClient) RetrieveUserConsents(userId string) (*UserConsentResponse, error) {
	return c.RetrieveUserConsentsWithContext(context.TODO(), userId)
}

// RetrieveUserConsentsWithContext
// Retrieves all the consents for a User.
//
//	string userId The User's Id
func (c *FusionAuthClient) RetrieveUserConsentsWithContext(ctx context.Context, userId string) (*UserConsentResponse, error) {
	var resp UserConsentResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/consent").
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveUserLink
// Retrieve a single Identity Provider user (link).
//
//	string identityProviderId The unique Id of the identity provider.
//	string identityProviderUserId The unique Id of the user in the 3rd party identity provider.
//	string userId The unique Id of the FusionAuth user.
func (c *FusionAuthClient) RetrieveUserLink(identityProviderId string, identityProviderUserId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	return c.RetrieveUserLinkWithContext(context.TODO(), identityProviderId, identityProviderUserId, userId)
}

// RetrieveUserLinkWithContext
// Retrieve a single Identity Provider user (link).
//
//	string identityProviderId The unique Id of the identity provider.
//	string identityProviderUserId The unique Id of the user in the 3rd party identity provider.
//	string userId The unique Id of the FusionAuth user.
func (c *FusionAuthClient) RetrieveUserLinkWithContext(ctx context.Context, identityProviderId string, identityProviderUserId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	var resp IdentityProviderLinkResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/link").
		WithParameter("identityProviderId", identityProviderId).
		WithParameter("identityProviderUserId", identityProviderUserId).
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserLinksByUserId
// Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
//
//	string identityProviderId (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.
//	string userId The unique Id of the user.
func (c *FusionAuthClient) RetrieveUserLinksByUserId(identityProviderId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	return c.RetrieveUserLinksByUserIdWithContext(context.TODO(), identityProviderId, userId)
}

// RetrieveUserLinksByUserIdWithContext
// Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
//
//	string identityProviderId (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.
//	string userId The unique Id of the user.
func (c *FusionAuthClient) RetrieveUserLinksByUserIdWithContext(ctx context.Context, identityProviderId string, userId string) (*IdentityProviderLinkResponse, *Errors, error) {
	var resp IdentityProviderLinkResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/link").
		WithParameter("identityProviderId", identityProviderId).
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserLoginReport
// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	string userId The userId id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReport(applicationId string, userId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	return c.RetrieveUserLoginReportWithContext(context.TODO(), applicationId, userId, start, end)
}

// RetrieveUserLoginReportWithContext
// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	string userId The userId id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReportWithContext(ctx context.Context, applicationId string, userId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	var resp LoginReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/login").
		WithParameter("applicationId", applicationId).
		WithParameter("userId", userId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserLoginReportByLoginId
// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	string loginId The userId id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReportByLoginId(applicationId string, loginId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	return c.RetrieveUserLoginReportByLoginIdWithContext(context.TODO(), applicationId, loginId, start, end)
}

// RetrieveUserLoginReportByLoginIdWithContext
// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
// login counts for that application.
//
//	string applicationId (Optional) The application id.
//	string loginId The userId id.
//	int64 start The start instant as UTC milliseconds since Epoch.
//	int64 end The end instant as UTC milliseconds since Epoch.
func (c *FusionAuthClient) RetrieveUserLoginReportByLoginIdWithContext(ctx context.Context, applicationId string, loginId string, start int64, end int64) (*LoginReportResponse, *Errors, error) {
	var resp LoginReportResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/report/login").
		WithParameter("applicationId", applicationId).
		WithParameter("loginId", loginId).
		WithParameter("start", strconv.FormatInt(start, 10)).
		WithParameter("end", strconv.FormatInt(end, 10)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserRecentLogins
// Retrieves the last number of login records for a user.
//
//	string userId The Id of the user.
//	int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//	int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveUserRecentLogins(userId string, offset int, limit int) (*RecentLoginResponse, *Errors, error) {
	return c.RetrieveUserRecentLoginsWithContext(context.TODO(), userId, offset, limit)
}

// RetrieveUserRecentLoginsWithContext
// Retrieves the last number of login records for a user.
//
//	string userId The Id of the user.
//	int offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
//	int limit (Optional, defaults to 10) The number of records to retrieve.
func (c *FusionAuthClient) RetrieveUserRecentLoginsWithContext(ctx context.Context, userId string, offset int, limit int) (*RecentLoginResponse, *Errors, error) {
	var resp RecentLoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/recent-login").
		WithParameter("userId", userId).
		WithParameter("offset", strconv.Itoa(offset)).
		WithParameter("limit", strconv.Itoa(limit)).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveUserUsingJWT
// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) RetrieveUserUsingJWT(encodedJWT string) (*UserResponse, *Errors, error) {
	return c.RetrieveUserUsingJWTWithContext(context.TODO(), encodedJWT)
}

// RetrieveUserUsingJWTWithContext
// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) RetrieveUserUsingJWTWithContext(ctx context.Context, encodedJWT string) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithAuthorization("Bearer " + encodedJWT).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveVersion
// Retrieves the FusionAuth version string.
func (c *FusionAuthClient) RetrieveVersion() (*VersionResponse, *Errors, error) {
	return c.RetrieveVersionWithContext(context.TODO())
}

// RetrieveVersionWithContext
// Retrieves the FusionAuth version string.
func (c *FusionAuthClient) RetrieveVersionWithContext(ctx context.Context) (*VersionResponse, *Errors, error) {
	var resp VersionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/version").
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveWebAuthnCredential
// Retrieves the WebAuthn credential for the given Id.
//
//	string id The Id of the WebAuthn credential.
func (c *FusionAuthClient) RetrieveWebAuthnCredential(id string) (*WebAuthnCredentialResponse, *Errors, error) {
	return c.RetrieveWebAuthnCredentialWithContext(context.TODO(), id)
}

// RetrieveWebAuthnCredentialWithContext
// Retrieves the WebAuthn credential for the given Id.
//
//	string id The Id of the WebAuthn credential.
func (c *FusionAuthClient) RetrieveWebAuthnCredentialWithContext(ctx context.Context, id string) (*WebAuthnCredentialResponse, *Errors, error) {
	var resp WebAuthnCredentialResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn").
		WithUriSegment(id).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveWebAuthnCredentialsForUser
// Retrieves all WebAuthn credentials for the given user.
//
//	string userId The user's ID.
func (c *FusionAuthClient) RetrieveWebAuthnCredentialsForUser(userId string) (*WebAuthnCredentialResponse, *Errors, error) {
	return c.RetrieveWebAuthnCredentialsForUserWithContext(context.TODO(), userId)
}

// RetrieveWebAuthnCredentialsForUserWithContext
// Retrieves all WebAuthn credentials for the given user.
//
//	string userId The user's ID.
func (c *FusionAuthClient) RetrieveWebAuthnCredentialsForUserWithContext(ctx context.Context, userId string) (*WebAuthnCredentialResponse, *Errors, error) {
	var resp WebAuthnCredentialResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn").
		WithParameter("userId", userId).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RetrieveWebhook
// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
//
//	string webhookId (Optional) The Id of the webhook.
func (c *FusionAuthClient) RetrieveWebhook(webhookId string) (*WebhookResponse, error) {
	return c.RetrieveWebhookWithContext(context.TODO(), webhookId)
}

// RetrieveWebhookWithContext
// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
//
//	string webhookId (Optional) The Id of the webhook.
func (c *FusionAuthClient) RetrieveWebhookWithContext(ctx context.Context, webhookId string) (*WebhookResponse, error) {
	var resp WebhookResponse

	err := c.Start(&resp, nil).
		WithUri("/api/webhook").
		WithUriSegment(webhookId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RetrieveWebhooks
// Retrieves all the webhooks.
func (c *FusionAuthClient) RetrieveWebhooks() (*WebhookResponse, error) {
	return c.RetrieveWebhooksWithContext(context.TODO())
}

// RetrieveWebhooksWithContext
// Retrieves all the webhooks.
func (c *FusionAuthClient) RetrieveWebhooksWithContext(ctx context.Context) (*WebhookResponse, error) {
	var resp WebhookResponse

	err := c.Start(&resp, nil).
		WithUri("/api/webhook").
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// RevokeRefreshToken
// Revokes refresh tokens.
//
// Usage examples:
//
//   - Delete a single refresh token, pass in only the token.
//     revokeRefreshToken(token)
//
//   - Delete all refresh tokens for a user, pass in only the userId.
//     revokeRefreshToken(null, userId)
//
//   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
//     revokeRefreshToken(null, userId, applicationId)
//
//   - Delete all refresh tokens for an application
//     revokeRefreshToken(null, null, applicationId)
//
// Note: <code>null</code> may be handled differently depending upon the programming language.
//
// See also: (method names may vary by language... but you'll figure it out)
//
//   - revokeRefreshTokenById
//   - revokeRefreshTokenByToken
//   - revokeRefreshTokensByUserId
//   - revokeRefreshTokensByApplicationId
//   - revokeRefreshTokensByUserIdForApplication
//     string token (Optional) The refresh token to delete.
//     string userId (Optional) The user id whose tokens to delete.
//     string applicationId (Optional) The application id of the tokens to delete.
func (c *FusionAuthClient) RevokeRefreshToken(token string, userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokenWithContext(context.TODO(), token, userId, applicationId)
}

// RevokeRefreshTokenWithContext
// Revokes refresh tokens.
//
// Usage examples:
//
//   - Delete a single refresh token, pass in only the token.
//     revokeRefreshToken(token)
//
//   - Delete all refresh tokens for a user, pass in only the userId.
//     revokeRefreshToken(null, userId)
//
//   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
//     revokeRefreshToken(null, userId, applicationId)
//
//   - Delete all refresh tokens for an application
//     revokeRefreshToken(null, null, applicationId)
//
// Note: <code>null</code> may be handled differently depending upon the programming language.
//
// See also: (method names may vary by language... but you'll figure it out)
//
//   - revokeRefreshTokenById
//   - revokeRefreshTokenByToken
//   - revokeRefreshTokensByUserId
//   - revokeRefreshTokensByApplicationId
//   - revokeRefreshTokensByUserIdForApplication
//     string token (Optional) The refresh token to delete.
//     string userId (Optional) The user id whose tokens to delete.
//     string applicationId (Optional) The application id of the tokens to delete.
func (c *FusionAuthClient) RevokeRefreshTokenWithContext(ctx context.Context, token string, userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("token", token).
		WithParameter("userId", userId).
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokenById
// Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
//
//	string tokenId The unique Id of the token to delete.
func (c *FusionAuthClient) RevokeRefreshTokenById(tokenId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokenByIdWithContext(context.TODO(), tokenId)
}

// RevokeRefreshTokenByIdWithContext
// Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
//
//	string tokenId The unique Id of the token to delete.
func (c *FusionAuthClient) RevokeRefreshTokenByIdWithContext(ctx context.Context, tokenId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithUriSegment(tokenId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokenByToken
// Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
//
//	string token The refresh token to delete.
func (c *FusionAuthClient) RevokeRefreshTokenByToken(token string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokenByTokenWithContext(context.TODO(), token)
}

// RevokeRefreshTokenByTokenWithContext
// Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
//
//	string token The refresh token to delete.
func (c *FusionAuthClient) RevokeRefreshTokenByTokenWithContext(ctx context.Context, token string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("token", token).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokensByApplicationId
// Revoke all refresh tokens that belong to an application by applicationId.
//
//	string applicationId The unique Id of the application that you want to delete all refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByApplicationId(applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokensByApplicationIdWithContext(context.TODO(), applicationId)
}

// RevokeRefreshTokensByApplicationIdWithContext
// Revoke all refresh tokens that belong to an application by applicationId.
//
//	string applicationId The unique Id of the application that you want to delete all refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByApplicationIdWithContext(ctx context.Context, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokensByUserId
// Revoke all refresh tokens that belong to a user by user Id.
//
//	string userId The unique Id of the user that you want to delete all refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByUserId(userId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokensByUserIdWithContext(context.TODO(), userId)
}

// RevokeRefreshTokensByUserIdWithContext
// Revoke all refresh tokens that belong to a user by user Id.
//
//	string userId The unique Id of the user that you want to delete all refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByUserIdWithContext(ctx context.Context, userId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("userId", userId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokensByUserIdForApplication
// Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
//
//	string userId The unique Id of the user that you want to delete all refresh tokens for.
//	string applicationId The unique Id of the application that you want to delete refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByUserIdForApplication(userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokensByUserIdForApplicationWithContext(context.TODO(), userId, applicationId)
}

// RevokeRefreshTokensByUserIdForApplicationWithContext
// Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
//
//	string userId The unique Id of the user that you want to delete all refresh tokens for.
//	string applicationId The unique Id of the application that you want to delete refresh tokens for.
func (c *FusionAuthClient) RevokeRefreshTokensByUserIdForApplicationWithContext(ctx context.Context, userId string, applicationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithParameter("userId", userId).
		WithParameter("applicationId", applicationId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeRefreshTokensWithRequest
// Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
// and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
//
//	RefreshTokenRevokeRequest request The request information used to revoke the refresh tokens.
func (c *FusionAuthClient) RevokeRefreshTokensWithRequest(request RefreshTokenRevokeRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.RevokeRefreshTokensWithRequestWithContext(context.TODO(), request)
}

// RevokeRefreshTokensWithRequestWithContext
// Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
// and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
//
//	RefreshTokenRevokeRequest request The request information used to revoke the refresh tokens.
func (c *FusionAuthClient) RevokeRefreshTokensWithRequestWithContext(ctx context.Context, request RefreshTokenRevokeRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/refresh").
		WithJSONBody(request).
		WithMethod(http.MethodDelete).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// RevokeUserConsent
// Revokes a single User consent by Id.
//
//	string userConsentId The User Consent Id
func (c *FusionAuthClient) RevokeUserConsent(userConsentId string) (*BaseHTTPResponse, error) {
	return c.RevokeUserConsentWithContext(context.TODO(), userConsentId)
}

// RevokeUserConsentWithContext
// Revokes a single User consent by Id.
//
//	string userConsentId The User Consent Id
func (c *FusionAuthClient) RevokeUserConsentWithContext(ctx context.Context, userConsentId string) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.Start(&resp, nil).
		WithUri("/api/user/consent").
		WithUriSegment(userConsentId).
		WithMethod(http.MethodDelete).
		Do(ctx)
	return &resp, err
}

// SearchApplications
// Searches applications with the specified criteria and pagination.
//
//	ApplicationSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchApplications(request ApplicationSearchRequest) (*ApplicationSearchResponse, *Errors, error) {
	return c.SearchApplicationsWithContext(context.TODO(), request)
}

// SearchApplicationsWithContext
// Searches applications with the specified criteria and pagination.
//
//	ApplicationSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchApplicationsWithContext(ctx context.Context, request ApplicationSearchRequest) (*ApplicationSearchResponse, *Errors, error) {
	var resp ApplicationSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchAuditLogs
// Searches the audit logs with the specified criteria and pagination.
//
//	AuditLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchAuditLogs(request AuditLogSearchRequest) (*AuditLogSearchResponse, *Errors, error) {
	return c.SearchAuditLogsWithContext(context.TODO(), request)
}

// SearchAuditLogsWithContext
// Searches the audit logs with the specified criteria and pagination.
//
//	AuditLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchAuditLogsWithContext(ctx context.Context, request AuditLogSearchRequest) (*AuditLogSearchResponse, *Errors, error) {
	var resp AuditLogSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/audit-log/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchConsents
// Searches consents with the specified criteria and pagination.
//
//	ConsentSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchConsents(request ConsentSearchRequest) (*ConsentSearchResponse, *Errors, error) {
	return c.SearchConsentsWithContext(context.TODO(), request)
}

// SearchConsentsWithContext
// Searches consents with the specified criteria and pagination.
//
//	ConsentSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchConsentsWithContext(ctx context.Context, request ConsentSearchRequest) (*ConsentSearchResponse, *Errors, error) {
	var resp ConsentSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/consent/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEmailTemplates
// Searches email templates with the specified criteria and pagination.
//
//	EmailTemplateSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEmailTemplates(request EmailTemplateSearchRequest) (*EmailTemplateSearchResponse, *Errors, error) {
	return c.SearchEmailTemplatesWithContext(context.TODO(), request)
}

// SearchEmailTemplatesWithContext
// Searches email templates with the specified criteria and pagination.
//
//	EmailTemplateSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEmailTemplatesWithContext(ctx context.Context, request EmailTemplateSearchRequest) (*EmailTemplateSearchResponse, *Errors, error) {
	var resp EmailTemplateSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEntities
// Searches entities with the specified criteria and pagination.
//
//	EntitySearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntities(request EntitySearchRequest) (*EntitySearchResponse, *Errors, error) {
	return c.SearchEntitiesWithContext(context.TODO(), request)
}

// SearchEntitiesWithContext
// Searches entities with the specified criteria and pagination.
//
//	EntitySearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntitiesWithContext(ctx context.Context, request EntitySearchRequest) (*EntitySearchResponse, *Errors, error) {
	var resp EntitySearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEntitiesByIds
// Retrieves the entities for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The entity ids to search for.
func (c *FusionAuthClient) SearchEntitiesByIds(ids []string) (*EntitySearchResponse, *Errors, error) {
	return c.SearchEntitiesByIdsWithContext(context.TODO(), ids)
}

// SearchEntitiesByIdsWithContext
// Retrieves the entities for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The entity ids to search for.
func (c *FusionAuthClient) SearchEntitiesByIdsWithContext(ctx context.Context, ids []string) (*EntitySearchResponse, *Errors, error) {
	var resp EntitySearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/search").
		WithParameter("ids", ids).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEntityGrants
// Searches Entity Grants with the specified criteria and pagination.
//
//	EntityGrantSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntityGrants(request EntityGrantSearchRequest) (*EntityGrantSearchResponse, *Errors, error) {
	return c.SearchEntityGrantsWithContext(context.TODO(), request)
}

// SearchEntityGrantsWithContext
// Searches Entity Grants with the specified criteria and pagination.
//
//	EntityGrantSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntityGrantsWithContext(ctx context.Context, request EntityGrantSearchRequest) (*EntityGrantSearchResponse, *Errors, error) {
	var resp EntityGrantSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/grant/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEntityTypes
// Searches the entity types with the specified criteria and pagination.
//
//	EntityTypeSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntityTypes(request EntityTypeSearchRequest) (*EntityTypeSearchResponse, *Errors, error) {
	return c.SearchEntityTypesWithContext(context.TODO(), request)
}

// SearchEntityTypesWithContext
// Searches the entity types with the specified criteria and pagination.
//
//	EntityTypeSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEntityTypesWithContext(ctx context.Context, request EntityTypeSearchRequest) (*EntityTypeSearchResponse, *Errors, error) {
	var resp EntityTypeSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchEventLogs
// Searches the event logs with the specified criteria and pagination.
//
//	EventLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEventLogs(request EventLogSearchRequest) (*EventLogSearchResponse, *Errors, error) {
	return c.SearchEventLogsWithContext(context.TODO(), request)
}

// SearchEventLogsWithContext
// Searches the event logs with the specified criteria and pagination.
//
//	EventLogSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchEventLogsWithContext(ctx context.Context, request EventLogSearchRequest) (*EventLogSearchResponse, *Errors, error) {
	var resp EventLogSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/event-log/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchGroupMembers
// Searches group members with the specified criteria and pagination.
//
//	GroupMemberSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchGroupMembers(request GroupMemberSearchRequest) (*GroupMemberSearchResponse, *Errors, error) {
	return c.SearchGroupMembersWithContext(context.TODO(), request)
}

// SearchGroupMembersWithContext
// Searches group members with the specified criteria and pagination.
//
//	GroupMemberSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchGroupMembersWithContext(ctx context.Context, request GroupMemberSearchRequest) (*GroupMemberSearchResponse, *Errors, error) {
	var resp GroupMemberSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group/member/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchGroups
// Searches groups with the specified criteria and pagination.
//
//	GroupSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchGroups(request GroupSearchRequest) (*GroupSearchResponse, *Errors, error) {
	return c.SearchGroupsWithContext(context.TODO(), request)
}

// SearchGroupsWithContext
// Searches groups with the specified criteria and pagination.
//
//	GroupSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchGroupsWithContext(ctx context.Context, request GroupSearchRequest) (*GroupSearchResponse, *Errors, error) {
	var resp GroupSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchIPAccessControlLists
// Searches the IP Access Control Lists with the specified criteria and pagination.
//
//	IPAccessControlListSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchIPAccessControlLists(request IPAccessControlListSearchRequest) (*IPAccessControlListSearchResponse, *Errors, error) {
	return c.SearchIPAccessControlListsWithContext(context.TODO(), request)
}

// SearchIPAccessControlListsWithContext
// Searches the IP Access Control Lists with the specified criteria and pagination.
//
//	IPAccessControlListSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchIPAccessControlListsWithContext(ctx context.Context, request IPAccessControlListSearchRequest) (*IPAccessControlListSearchResponse, *Errors, error) {
	var resp IPAccessControlListSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/ip-acl/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchIdentityProviders
// Searches identity providers with the specified criteria and pagination.
//
//	IdentityProviderSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchIdentityProviders(request IdentityProviderSearchRequest) (*IdentityProviderSearchResponse, *Errors, error) {
	return c.SearchIdentityProvidersWithContext(context.TODO(), request)
}

// SearchIdentityProvidersWithContext
// Searches identity providers with the specified criteria and pagination.
//
//	IdentityProviderSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchIdentityProvidersWithContext(ctx context.Context, request IdentityProviderSearchRequest) (*IdentityProviderSearchResponse, *Errors, error) {
	var resp IdentityProviderSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchKeys
// Searches keys with the specified criteria and pagination.
//
//	KeySearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchKeys(request KeySearchRequest) (*KeySearchResponse, *Errors, error) {
	return c.SearchKeysWithContext(context.TODO(), request)
}

// SearchKeysWithContext
// Searches keys with the specified criteria and pagination.
//
//	KeySearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchKeysWithContext(ctx context.Context, request KeySearchRequest) (*KeySearchResponse, *Errors, error) {
	var resp KeySearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchLambdas
// Searches lambdas with the specified criteria and pagination.
//
//	LambdaSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchLambdas(request LambdaSearchRequest) (*LambdaSearchResponse, *Errors, error) {
	return c.SearchLambdasWithContext(context.TODO(), request)
}

// SearchLambdasWithContext
// Searches lambdas with the specified criteria and pagination.
//
//	LambdaSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchLambdasWithContext(ctx context.Context, request LambdaSearchRequest) (*LambdaSearchResponse, *Errors, error) {
	var resp LambdaSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchLoginRecords
// Searches the login records with the specified criteria and pagination.
//
//	LoginRecordSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchLoginRecords(request LoginRecordSearchRequest) (*LoginRecordSearchResponse, *Errors, error) {
	return c.SearchLoginRecordsWithContext(context.TODO(), request)
}

// SearchLoginRecordsWithContext
// Searches the login records with the specified criteria and pagination.
//
//	LoginRecordSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchLoginRecordsWithContext(ctx context.Context, request LoginRecordSearchRequest) (*LoginRecordSearchResponse, *Errors, error) {
	var resp LoginRecordSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system/login-record/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchTenants
// Searches tenants with the specified criteria and pagination.
//
//	TenantSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchTenants(request TenantSearchRequest) (*TenantSearchResponse, *Errors, error) {
	return c.SearchTenantsWithContext(context.TODO(), request)
}

// SearchTenantsWithContext
// Searches tenants with the specified criteria and pagination.
//
//	TenantSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchTenantsWithContext(ctx context.Context, request TenantSearchRequest) (*TenantSearchResponse, *Errors, error) {
	var resp TenantSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchThemes
// Searches themes with the specified criteria and pagination.
//
//	ThemeSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchThemes(request ThemeSearchRequest) (*ThemeSearchResponse, *Errors, error) {
	return c.SearchThemesWithContext(context.TODO(), request)
}

// SearchThemesWithContext
// Searches themes with the specified criteria and pagination.
//
//	ThemeSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchThemesWithContext(ctx context.Context, request ThemeSearchRequest) (*ThemeSearchResponse, *Errors, error) {
	var resp ThemeSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchUserComments
// Searches user comments with the specified criteria and pagination.
//
//	UserCommentSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchUserComments(request UserCommentSearchRequest) (*UserCommentSearchResponse, *Errors, error) {
	return c.SearchUserCommentsWithContext(context.TODO(), request)
}

// SearchUserCommentsWithContext
// Searches user comments with the specified criteria and pagination.
//
//	UserCommentSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchUserCommentsWithContext(ctx context.Context, request UserCommentSearchRequest) (*UserCommentSearchResponse, *Errors, error) {
	var resp UserCommentSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/comment/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchUsers
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The user ids to search for.
//
// Deprecated: This method has been renamed to SearchUsersByIds, use that method instead.
func (c *FusionAuthClient) SearchUsers(ids []string) (*SearchResponse, *Errors, error) {
	return c.SearchUsersWithContext(context.TODO(), ids)
}

// SearchUsersWithContext
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The user ids to search for.
//
// Deprecated: This method has been renamed to SearchUsersByIdsWithContext, use that method instead.
func (c *FusionAuthClient) SearchUsersWithContext(ctx context.Context, ids []string) (*SearchResponse, *Errors, error) {
	var resp SearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/search").
		WithParameter("ids", ids).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchUsersByIds
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The user ids to search for.
func (c *FusionAuthClient) SearchUsersByIds(ids []string) (*SearchResponse, *Errors, error) {
	return c.SearchUsersByIdsWithContext(context.TODO(), ids)
}

// SearchUsersByIdsWithContext
// Retrieves the users for the given ids. If any id is invalid, it is ignored.
//
//	[]string ids The user ids to search for.
func (c *FusionAuthClient) SearchUsersByIdsWithContext(ctx context.Context, ids []string) (*SearchResponse, *Errors, error) {
	var resp SearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/search").
		WithParameter("ids", ids).
		WithMethod(http.MethodGet).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchUsersByQuery
// Retrieves the users for the given search criteria and pagination.
//
//	SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//	and sortFields.
func (c *FusionAuthClient) SearchUsersByQuery(request SearchRequest) (*SearchResponse, *Errors, error) {
	return c.SearchUsersByQueryWithContext(context.TODO(), request)
}

// SearchUsersByQueryWithContext
// Retrieves the users for the given search criteria and pagination.
//
//	SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//	and sortFields.
func (c *FusionAuthClient) SearchUsersByQueryWithContext(ctx context.Context, request SearchRequest) (*SearchResponse, *Errors, error) {
	var resp SearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchUsersByQueryString
// Retrieves the users for the given search criteria and pagination.
//
//	SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//	and sortFields.
//
// Deprecated: This method has been renamed to SearchUsersByQuery, use that method instead.
func (c *FusionAuthClient) SearchUsersByQueryString(request SearchRequest) (*SearchResponse, *Errors, error) {
	return c.SearchUsersByQueryStringWithContext(context.TODO(), request)
}

// SearchUsersByQueryStringWithContext
// Retrieves the users for the given search criteria and pagination.
//
//	SearchRequest request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
//	and sortFields.
//
// Deprecated: This method has been renamed to SearchUsersByQueryWithContext, use that method instead.
func (c *FusionAuthClient) SearchUsersByQueryStringWithContext(ctx context.Context, request SearchRequest) (*SearchResponse, *Errors, error) {
	var resp SearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SearchWebhooks
// Searches webhooks with the specified criteria and pagination.
//
//	WebhookSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchWebhooks(request WebhookSearchRequest) (*WebhookSearchResponse, *Errors, error) {
	return c.SearchWebhooksWithContext(context.TODO(), request)
}

// SearchWebhooksWithContext
// Searches webhooks with the specified criteria and pagination.
//
//	WebhookSearchRequest request The search criteria and pagination information.
func (c *FusionAuthClient) SearchWebhooksWithContext(ctx context.Context, request WebhookSearchRequest) (*WebhookSearchResponse, *Errors, error) {
	var resp WebhookSearchResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webhook/search").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendEmail
// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
// pairs in the email template.
//
//	string emailTemplateId The id for the template.
//	SendRequest request The send email request that contains all the information used to send the email.
func (c *FusionAuthClient) SendEmail(emailTemplateId string, request SendRequest) (*SendResponse, *Errors, error) {
	return c.SendEmailWithContext(context.TODO(), emailTemplateId, request)
}

// SendEmailWithContext
// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
// pairs in the email template.
//
//	string emailTemplateId The id for the template.
//	SendRequest request The send email request that contains all the information used to send the email.
func (c *FusionAuthClient) SendEmailWithContext(ctx context.Context, emailTemplateId string, request SendRequest) (*SendResponse, *Errors, error) {
	var resp SendResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/send").
		WithUriSegment(emailTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendFamilyRequestEmail
// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
//
//	FamilyEmailRequest request The request object that contains the parent email.
func (c *FusionAuthClient) SendFamilyRequestEmail(request FamilyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.SendFamilyRequestEmailWithContext(context.TODO(), request)
}

// SendFamilyRequestEmailWithContext
// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
//
//	FamilyEmailRequest request The request object that contains the parent email.
func (c *FusionAuthClient) SendFamilyRequestEmailWithContext(ctx context.Context, request FamilyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/family/request").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendPasswordlessCode
// Send a passwordless authentication code in an email to complete login.
//
//	PasswordlessSendRequest request The passwordless send request that contains all the information used to send an email containing a code.
func (c *FusionAuthClient) SendPasswordlessCode(request PasswordlessSendRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.SendPasswordlessCodeWithContext(context.TODO(), request)
}

// SendPasswordlessCodeWithContext
// Send a passwordless authentication code in an email to complete login.
//
//	PasswordlessSendRequest request The passwordless send request that contains all the information used to send an email containing a code.
func (c *FusionAuthClient) SendPasswordlessCodeWithContext(ctx context.Context, request PasswordlessSendRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/passwordless/send").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendTwoFactorCode
// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
//
//	TwoFactorSendRequest request The request object that contains all the information used to send the code.
//
// Deprecated: This method has been renamed to SendTwoFactorCodeForEnableDisable, use that method instead.
func (c *FusionAuthClient) SendTwoFactorCode(request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.SendTwoFactorCodeWithContext(context.TODO(), request)
}

// SendTwoFactorCodeWithContext
// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
//
//	TwoFactorSendRequest request The request object that contains all the information used to send the code.
//
// Deprecated: This method has been renamed to SendTwoFactorCodeForEnableDisableWithContext, use that method instead.
func (c *FusionAuthClient) SendTwoFactorCodeWithContext(ctx context.Context, request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/send").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendTwoFactorCodeForEnableDisable
// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
//
//	TwoFactorSendRequest request The request object that contains all the information used to send the code.
func (c *FusionAuthClient) SendTwoFactorCodeForEnableDisable(request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.SendTwoFactorCodeForEnableDisableWithContext(context.TODO(), request)
}

// SendTwoFactorCodeForEnableDisableWithContext
// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
//
//	TwoFactorSendRequest request The request object that contains all the information used to send the code.
func (c *FusionAuthClient) SendTwoFactorCodeForEnableDisableWithContext(ctx context.Context, request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/send").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendTwoFactorCodeForLogin
// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
//
//	string twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
//
// Deprecated: This method has been renamed to SendTwoFactorCodeForLoginUsingMethod, use that method instead.
func (c *FusionAuthClient) SendTwoFactorCodeForLogin(twoFactorId string) (*BaseHTTPResponse, *Errors, error) {
	return c.SendTwoFactorCodeForLoginWithContext(context.TODO(), twoFactorId)
}

// SendTwoFactorCodeForLoginWithContext
// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
//
//	string twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
//
// Deprecated: This method has been renamed to SendTwoFactorCodeForLoginUsingMethodWithContext, use that method instead.
func (c *FusionAuthClient) SendTwoFactorCodeForLoginWithContext(ctx context.Context, twoFactorId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/send").
		WithUriSegment(twoFactorId).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// SendTwoFactorCodeForLoginUsingMethod
// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
//
//	string twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
//	TwoFactorSendRequest request The Two Factor send request that contains all the information used to send the Two Factor code to the user.
func (c *FusionAuthClient) SendTwoFactorCodeForLoginUsingMethod(twoFactorId string, request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.SendTwoFactorCodeForLoginUsingMethodWithContext(context.TODO(), twoFactorId, request)
}

// SendTwoFactorCodeForLoginUsingMethodWithContext
// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
//
//	string twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
//	TwoFactorSendRequest request The Two Factor send request that contains all the information used to send the Two Factor code to the user.
func (c *FusionAuthClient) SendTwoFactorCodeForLoginUsingMethodWithContext(ctx context.Context, twoFactorId string, request TwoFactorSendRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/send").
		WithUriSegment(twoFactorId).
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// StartIdentityProviderLogin
// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
//
//	IdentityProviderStartLoginRequest request The third-party login request that contains information from the third-party login
//	providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) StartIdentityProviderLogin(request IdentityProviderStartLoginRequest) (*IdentityProviderStartLoginResponse, *Errors, error) {
	return c.StartIdentityProviderLoginWithContext(context.TODO(), request)
}

// StartIdentityProviderLoginWithContext
// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
//
//	IdentityProviderStartLoginRequest request The third-party login request that contains information from the third-party login
//	providers that FusionAuth uses to reconcile the user's account.
func (c *FusionAuthClient) StartIdentityProviderLoginWithContext(ctx context.Context, request IdentityProviderStartLoginRequest) (*IdentityProviderStartLoginResponse, *Errors, error) {
	var resp IdentityProviderStartLoginResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/identity-provider/start").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// StartPasswordlessLogin
// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
//
//	PasswordlessStartRequest request The passwordless start request that contains all the information used to begin the passwordless login request.
func (c *FusionAuthClient) StartPasswordlessLogin(request PasswordlessStartRequest) (*PasswordlessStartResponse, *Errors, error) {
	return c.StartPasswordlessLoginWithContext(context.TODO(), request)
}

// StartPasswordlessLoginWithContext
// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
//
//	PasswordlessStartRequest request The passwordless start request that contains all the information used to begin the passwordless login request.
func (c *FusionAuthClient) StartPasswordlessLoginWithContext(ctx context.Context, request PasswordlessStartRequest) (*PasswordlessStartResponse, *Errors, error) {
	var resp PasswordlessStartResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/passwordless/start").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// StartTwoFactorLogin
// Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send
// API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned
// to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login
// API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
//
// This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
//
//	TwoFactorStartRequest request The Two-Factor start request that contains all the information used to begin the Two-Factor login request.
func (c *FusionAuthClient) StartTwoFactorLogin(request TwoFactorStartRequest) (*TwoFactorStartResponse, *Errors, error) {
	return c.StartTwoFactorLoginWithContext(context.TODO(), request)
}

// StartTwoFactorLoginWithContext
// Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send
// API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned
// to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login
// API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
//
// This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
//
//	TwoFactorStartRequest request The Two-Factor start request that contains all the information used to begin the Two-Factor login request.
func (c *FusionAuthClient) StartTwoFactorLoginWithContext(ctx context.Context, request TwoFactorStartRequest) (*TwoFactorStartResponse, *Errors, error) {
	var resp TwoFactorStartResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/start").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// StartWebAuthnLogin
// Start a WebAuthn authentication ceremony by generating a new challenge for the user
//
//	WebAuthnStartRequest request An object containing data necessary for starting the authentication ceremony
func (c *FusionAuthClient) StartWebAuthnLogin(request WebAuthnStartRequest) (*WebAuthnStartResponse, *Errors, error) {
	return c.StartWebAuthnLoginWithContext(context.TODO(), request)
}

// StartWebAuthnLoginWithContext
// Start a WebAuthn authentication ceremony by generating a new challenge for the user
//
//	WebAuthnStartRequest request An object containing data necessary for starting the authentication ceremony
func (c *FusionAuthClient) StartWebAuthnLoginWithContext(ctx context.Context, request WebAuthnStartRequest) (*WebAuthnStartResponse, *Errors, error) {
	var resp WebAuthnStartResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/start").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// StartWebAuthnRegistration
// Start a WebAuthn registration ceremony by generating a new challenge for the user
//
//	WebAuthnRegisterStartRequest request An object containing data necessary for starting the registration ceremony
func (c *FusionAuthClient) StartWebAuthnRegistration(request WebAuthnRegisterStartRequest) (*WebAuthnRegisterStartResponse, *Errors, error) {
	return c.StartWebAuthnRegistrationWithContext(context.TODO(), request)
}

// StartWebAuthnRegistrationWithContext
// Start a WebAuthn registration ceremony by generating a new challenge for the user
//
//	WebAuthnRegisterStartRequest request An object containing data necessary for starting the registration ceremony
func (c *FusionAuthClient) StartWebAuthnRegistrationWithContext(ctx context.Context, request WebAuthnRegisterStartRequest) (*WebAuthnRegisterStartResponse, *Errors, error) {
	var resp WebAuthnRegisterStartResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webauthn/register/start").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// TwoFactorLogin
// Complete login using a 2FA challenge
//
//	TwoFactorLoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) TwoFactorLogin(request TwoFactorLoginRequest) (*LoginResponse, *Errors, error) {
	return c.TwoFactorLoginWithContext(context.TODO(), request)
}

// TwoFactorLoginWithContext
// Complete login using a 2FA challenge
//
//	TwoFactorLoginRequest request The login request that contains the user credentials used to log them in.
func (c *FusionAuthClient) TwoFactorLoginWithContext(ctx context.Context, request TwoFactorLoginRequest) (*LoginResponse, *Errors, error) {
	var resp LoginResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/two-factor/login").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateAPIKey
// Updates an API key by given id
//
//	string apiKeyId The Id of the API key to update.
//	APIKeyRequest request The request object that contains all the information used to create the API Key.
func (c *FusionAuthClient) UpdateAPIKey(apiKeyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	return c.UpdateAPIKeyWithContext(context.TODO(), apiKeyId, request)
}

// UpdateAPIKeyWithContext
// Updates an API key by given id
//
//	string apiKeyId The Id of the API key to update.
//	APIKeyRequest request The request object that contains all the information used to create the API Key.
func (c *FusionAuthClient) UpdateAPIKeyWithContext(ctx context.Context, apiKeyId string, request APIKeyRequest) (*APIKeyResponse, *Errors, error) {
	var resp APIKeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/api-key").
		WithUriSegment(apiKeyId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateApplication
// Updates the application with the given Id.
//
//	string applicationId The Id of the application to update.
//	ApplicationRequest request The request that contains all the new application information.
func (c *FusionAuthClient) UpdateApplication(applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	return c.UpdateApplicationWithContext(context.TODO(), applicationId, request)
}

// UpdateApplicationWithContext
// Updates the application with the given Id.
//
//	string applicationId The Id of the application to update.
//	ApplicationRequest request The request that contains all the new application information.
func (c *FusionAuthClient) UpdateApplicationWithContext(ctx context.Context, applicationId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateApplicationRole
// Updates the application role with the given id for the application.
//
//	string applicationId The Id of the application that the role belongs to.
//	string roleId The Id of the role to update.
//	ApplicationRequest request The request that contains all the new role information.
func (c *FusionAuthClient) UpdateApplicationRole(applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	return c.UpdateApplicationRoleWithContext(context.TODO(), applicationId, roleId, request)
}

// UpdateApplicationRoleWithContext
// Updates the application role with the given id for the application.
//
//	string applicationId The Id of the application that the role belongs to.
//	string roleId The Id of the role to update.
//	ApplicationRequest request The request that contains all the new role information.
func (c *FusionAuthClient) UpdateApplicationRoleWithContext(ctx context.Context, applicationId string, roleId string, request ApplicationRequest) (*ApplicationResponse, *Errors, error) {
	var resp ApplicationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/application").
		WithUriSegment(applicationId).
		WithUriSegment("role").
		WithUriSegment(roleId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateConnector
// Updates the connector with the given Id.
//
//	string connectorId The Id of the connector to update.
//	ConnectorRequest request The request object that contains all the new connector information.
func (c *FusionAuthClient) UpdateConnector(connectorId string, request ConnectorRequest) (*ConnectorResponse, *Errors, error) {
	return c.UpdateConnectorWithContext(context.TODO(), connectorId, request)
}

// UpdateConnectorWithContext
// Updates the connector with the given Id.
//
//	string connectorId The Id of the connector to update.
//	ConnectorRequest request The request object that contains all the new connector information.
func (c *FusionAuthClient) UpdateConnectorWithContext(ctx context.Context, connectorId string, request ConnectorRequest) (*ConnectorResponse, *Errors, error) {
	var resp ConnectorResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/connector").
		WithUriSegment(connectorId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateConsent
// Updates the consent with the given Id.
//
//	string consentId The Id of the consent to update.
//	ConsentRequest request The request that contains all the new consent information.
func (c *FusionAuthClient) UpdateConsent(consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
	return c.UpdateConsentWithContext(context.TODO(), consentId, request)
}

// UpdateConsentWithContext
// Updates the consent with the given Id.
//
//	string consentId The Id of the consent to update.
//	ConsentRequest request The request that contains all the new consent information.
func (c *FusionAuthClient) UpdateConsentWithContext(ctx context.Context, consentId string, request ConsentRequest) (*ConsentResponse, *Errors, error) {
	var resp ConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/consent").
		WithUriSegment(consentId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateEmailTemplate
// Updates the email template with the given Id.
//
//	string emailTemplateId The Id of the email template to update.
//	EmailTemplateRequest request The request that contains all the new email template information.
func (c *FusionAuthClient) UpdateEmailTemplate(emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
	return c.UpdateEmailTemplateWithContext(context.TODO(), emailTemplateId, request)
}

// UpdateEmailTemplateWithContext
// Updates the email template with the given Id.
//
//	string emailTemplateId The Id of the email template to update.
//	EmailTemplateRequest request The request that contains all the new email template information.
func (c *FusionAuthClient) UpdateEmailTemplateWithContext(ctx context.Context, emailTemplateId string, request EmailTemplateRequest) (*EmailTemplateResponse, *Errors, error) {
	var resp EmailTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/email/template").
		WithUriSegment(emailTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateEntity
// Updates the Entity with the given Id.
//
//	string entityId The Id of the Entity to update.
//	EntityRequest request The request that contains all the new Entity information.
func (c *FusionAuthClient) UpdateEntity(entityId string, request EntityRequest) (*EntityResponse, *Errors, error) {
	return c.UpdateEntityWithContext(context.TODO(), entityId, request)
}

// UpdateEntityWithContext
// Updates the Entity with the given Id.
//
//	string entityId The Id of the Entity to update.
//	EntityRequest request The request that contains all the new Entity information.
func (c *FusionAuthClient) UpdateEntityWithContext(ctx context.Context, entityId string, request EntityRequest) (*EntityResponse, *Errors, error) {
	var resp EntityResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateEntityType
// Updates the Entity Type with the given Id.
//
//	string entityTypeId The Id of the Entity Type to update.
//	EntityTypeRequest request The request that contains all the new Entity Type information.
func (c *FusionAuthClient) UpdateEntityType(entityTypeId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	return c.UpdateEntityTypeWithContext(context.TODO(), entityTypeId, request)
}

// UpdateEntityTypeWithContext
// Updates the Entity Type with the given Id.
//
//	string entityTypeId The Id of the Entity Type to update.
//	EntityTypeRequest request The request that contains all the new Entity Type information.
func (c *FusionAuthClient) UpdateEntityTypeWithContext(ctx context.Context, entityTypeId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateEntityTypePermission
// Updates the permission with the given id for the entity type.
//
//	string entityTypeId The Id of the entityType that the permission belongs to.
//	string permissionId The Id of the permission to update.
//	EntityTypeRequest request The request that contains all the new permission information.
func (c *FusionAuthClient) UpdateEntityTypePermission(entityTypeId string, permissionId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	return c.UpdateEntityTypePermissionWithContext(context.TODO(), entityTypeId, permissionId, request)
}

// UpdateEntityTypePermissionWithContext
// Updates the permission with the given id for the entity type.
//
//	string entityTypeId The Id of the entityType that the permission belongs to.
//	string permissionId The Id of the permission to update.
//	EntityTypeRequest request The request that contains all the new permission information.
func (c *FusionAuthClient) UpdateEntityTypePermissionWithContext(ctx context.Context, entityTypeId string, permissionId string, request EntityTypeRequest) (*EntityTypeResponse, *Errors, error) {
	var resp EntityTypeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity/type").
		WithUriSegment(entityTypeId).
		WithUriSegment("permission").
		WithUriSegment(permissionId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateForm
// Updates the form with the given Id.
//
//	string formId The Id of the form to update.
//	FormRequest request The request object that contains all the new form information.
func (c *FusionAuthClient) UpdateForm(formId string, request FormRequest) (*FormResponse, *Errors, error) {
	return c.UpdateFormWithContext(context.TODO(), formId, request)
}

// UpdateFormWithContext
// Updates the form with the given Id.
//
//	string formId The Id of the form to update.
//	FormRequest request The request object that contains all the new form information.
func (c *FusionAuthClient) UpdateFormWithContext(ctx context.Context, formId string, request FormRequest) (*FormResponse, *Errors, error) {
	var resp FormResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form").
		WithUriSegment(formId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateFormField
// Updates the form field with the given Id.
//
//	string fieldId The Id of the form field to update.
//	FormFieldRequest request The request object that contains all the new form field information.
func (c *FusionAuthClient) UpdateFormField(fieldId string, request FormFieldRequest) (*FormFieldResponse, *Errors, error) {
	return c.UpdateFormFieldWithContext(context.TODO(), fieldId, request)
}

// UpdateFormFieldWithContext
// Updates the form field with the given Id.
//
//	string fieldId The Id of the form field to update.
//	FormFieldRequest request The request object that contains all the new form field information.
func (c *FusionAuthClient) UpdateFormFieldWithContext(ctx context.Context, fieldId string, request FormFieldRequest) (*FormFieldResponse, *Errors, error) {
	var resp FormFieldResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/form/field").
		WithUriSegment(fieldId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateGroup
// Updates the group with the given Id.
//
//	string groupId The Id of the group to update.
//	GroupRequest request The request that contains all the new group information.
func (c *FusionAuthClient) UpdateGroup(groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
	return c.UpdateGroupWithContext(context.TODO(), groupId, request)
}

// UpdateGroupWithContext
// Updates the group with the given Id.
//
//	string groupId The Id of the group to update.
//	GroupRequest request The request that contains all the new group information.
func (c *FusionAuthClient) UpdateGroupWithContext(ctx context.Context, groupId string, request GroupRequest) (*GroupResponse, *Errors, error) {
	var resp GroupResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group").
		WithUriSegment(groupId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateGroupMembers
// Creates a member in a group.
//
//	MemberRequest request The request object that contains all the information used to create the group member(s).
func (c *FusionAuthClient) UpdateGroupMembers(request MemberRequest) (*MemberResponse, *Errors, error) {
	return c.UpdateGroupMembersWithContext(context.TODO(), request)
}

// UpdateGroupMembersWithContext
// Creates a member in a group.
//
//	MemberRequest request The request object that contains all the information used to create the group member(s).
func (c *FusionAuthClient) UpdateGroupMembersWithContext(ctx context.Context, request MemberRequest) (*MemberResponse, *Errors, error) {
	var resp MemberResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/group/member").
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateIPAccessControlList
// Updates the IP Access Control List with the given Id.
//
//	string accessControlListId The Id of the IP Access Control List to update.
//	IPAccessControlListRequest request The request that contains all the new IP Access Control List information.
func (c *FusionAuthClient) UpdateIPAccessControlList(accessControlListId string, request IPAccessControlListRequest) (*IPAccessControlListResponse, *Errors, error) {
	return c.UpdateIPAccessControlListWithContext(context.TODO(), accessControlListId, request)
}

// UpdateIPAccessControlListWithContext
// Updates the IP Access Control List with the given Id.
//
//	string accessControlListId The Id of the IP Access Control List to update.
//	IPAccessControlListRequest request The request that contains all the new IP Access Control List information.
func (c *FusionAuthClient) UpdateIPAccessControlListWithContext(ctx context.Context, accessControlListId string, request IPAccessControlListRequest) (*IPAccessControlListResponse, *Errors, error) {
	var resp IPAccessControlListResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/ip-acl").
		WithUriSegment(accessControlListId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateIntegrations
// Updates the available integrations.
//
//	IntegrationRequest request The request that contains all the new integration information.
func (c *FusionAuthClient) UpdateIntegrations(request IntegrationRequest) (*IntegrationResponse, *Errors, error) {
	return c.UpdateIntegrationsWithContext(context.TODO(), request)
}

// UpdateIntegrationsWithContext
// Updates the available integrations.
//
//	IntegrationRequest request The request that contains all the new integration information.
func (c *FusionAuthClient) UpdateIntegrationsWithContext(ctx context.Context, request IntegrationRequest) (*IntegrationResponse, *Errors, error) {
	var resp IntegrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/integration").
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateKey
// Updates the key with the given Id.
//
//	string keyId The Id of the key to update.
//	KeyRequest request The request that contains all the new key information.
func (c *FusionAuthClient) UpdateKey(keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	return c.UpdateKeyWithContext(context.TODO(), keyId, request)
}

// UpdateKeyWithContext
// Updates the key with the given Id.
//
//	string keyId The Id of the key to update.
//	KeyRequest request The request that contains all the new key information.
func (c *FusionAuthClient) UpdateKeyWithContext(ctx context.Context, keyId string, request KeyRequest) (*KeyResponse, *Errors, error) {
	var resp KeyResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/key").
		WithUriSegment(keyId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateLambda
// Updates the lambda with the given Id.
//
//	string lambdaId The Id of the lambda to update.
//	LambdaRequest request The request that contains all the new lambda information.
func (c *FusionAuthClient) UpdateLambda(lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
	return c.UpdateLambdaWithContext(context.TODO(), lambdaId, request)
}

// UpdateLambdaWithContext
// Updates the lambda with the given Id.
//
//	string lambdaId The Id of the lambda to update.
//	LambdaRequest request The request that contains all the new lambda information.
func (c *FusionAuthClient) UpdateLambdaWithContext(ctx context.Context, lambdaId string, request LambdaRequest) (*LambdaResponse, *Errors, error) {
	var resp LambdaResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/lambda").
		WithUriSegment(lambdaId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateMessageTemplate
// Updates the message template with the given Id.
//
//	string messageTemplateId The Id of the message template to update.
//	MessageTemplateRequest request The request that contains all the new message template information.
func (c *FusionAuthClient) UpdateMessageTemplate(messageTemplateId string, request MessageTemplateRequest) (*MessageTemplateResponse, *Errors, error) {
	return c.UpdateMessageTemplateWithContext(context.TODO(), messageTemplateId, request)
}

// UpdateMessageTemplateWithContext
// Updates the message template with the given Id.
//
//	string messageTemplateId The Id of the message template to update.
//	MessageTemplateRequest request The request that contains all the new message template information.
func (c *FusionAuthClient) UpdateMessageTemplateWithContext(ctx context.Context, messageTemplateId string, request MessageTemplateRequest) (*MessageTemplateResponse, *Errors, error) {
	var resp MessageTemplateResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/message/template").
		WithUriSegment(messageTemplateId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateMessenger
// Updates the messenger with the given Id.
//
//	string messengerId The Id of the messenger to update.
//	MessengerRequest request The request object that contains all the new messenger information.
func (c *FusionAuthClient) UpdateMessenger(messengerId string, request MessengerRequest) (*MessengerResponse, *Errors, error) {
	return c.UpdateMessengerWithContext(context.TODO(), messengerId, request)
}

// UpdateMessengerWithContext
// Updates the messenger with the given Id.
//
//	string messengerId The Id of the messenger to update.
//	MessengerRequest request The request object that contains all the new messenger information.
func (c *FusionAuthClient) UpdateMessengerWithContext(ctx context.Context, messengerId string, request MessengerRequest) (*MessengerResponse, *Errors, error) {
	var resp MessengerResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/messenger").
		WithUriSegment(messengerId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateRegistration
// Updates the registration for the user with the given id and the application defined in the request.
//
//	string userId The Id of the user whose registration is going to be updated.
//	RegistrationRequest request The request that contains all the new registration information.
func (c *FusionAuthClient) UpdateRegistration(userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
	return c.UpdateRegistrationWithContext(context.TODO(), userId, request)
}

// UpdateRegistrationWithContext
// Updates the registration for the user with the given id and the application defined in the request.
//
//	string userId The Id of the user whose registration is going to be updated.
//	RegistrationRequest request The request that contains all the new registration information.
func (c *FusionAuthClient) UpdateRegistrationWithContext(ctx context.Context, userId string, request RegistrationRequest) (*RegistrationResponse, *Errors, error) {
	var resp RegistrationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/registration").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateSystemConfiguration
// Updates the system configuration.
//
//	SystemConfigurationRequest request The request that contains all the new system configuration information.
func (c *FusionAuthClient) UpdateSystemConfiguration(request SystemConfigurationRequest) (*SystemConfigurationResponse, *Errors, error) {
	return c.UpdateSystemConfigurationWithContext(context.TODO(), request)
}

// UpdateSystemConfigurationWithContext
// Updates the system configuration.
//
//	SystemConfigurationRequest request The request that contains all the new system configuration information.
func (c *FusionAuthClient) UpdateSystemConfigurationWithContext(ctx context.Context, request SystemConfigurationRequest) (*SystemConfigurationResponse, *Errors, error) {
	var resp SystemConfigurationResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/system-configuration").
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateTenant
// Updates the tenant with the given Id.
//
//	string tenantId The Id of the tenant to update.
//	TenantRequest request The request that contains all the new tenant information.
func (c *FusionAuthClient) UpdateTenant(tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
	return c.UpdateTenantWithContext(context.TODO(), tenantId, request)
}

// UpdateTenantWithContext
// Updates the tenant with the given Id.
//
//	string tenantId The Id of the tenant to update.
//	TenantRequest request The request that contains all the new tenant information.
func (c *FusionAuthClient) UpdateTenantWithContext(ctx context.Context, tenantId string, request TenantRequest) (*TenantResponse, *Errors, error) {
	var resp TenantResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/tenant").
		WithUriSegment(tenantId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateTheme
// Updates the theme with the given Id.
//
//	string themeId The Id of the theme to update.
//	ThemeRequest request The request that contains all the new theme information.
func (c *FusionAuthClient) UpdateTheme(themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
	return c.UpdateThemeWithContext(context.TODO(), themeId, request)
}

// UpdateThemeWithContext
// Updates the theme with the given Id.
//
//	string themeId The Id of the theme to update.
//	ThemeRequest request The request that contains all the new theme information.
func (c *FusionAuthClient) UpdateThemeWithContext(ctx context.Context, themeId string, request ThemeRequest) (*ThemeResponse, *Errors, error) {
	var resp ThemeResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/theme").
		WithUriSegment(themeId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateUser
// Updates the user with the given Id.
//
//	string userId The Id of the user to update.
//	UserRequest request The request that contains all the new user information.
func (c *FusionAuthClient) UpdateUser(userId string, request UserRequest) (*UserResponse, *Errors, error) {
	return c.UpdateUserWithContext(context.TODO(), userId, request)
}

// UpdateUserWithContext
// Updates the user with the given Id.
//
//	string userId The Id of the user to update.
//	UserRequest request The request that contains all the new user information.
func (c *FusionAuthClient) UpdateUserWithContext(ctx context.Context, userId string, request UserRequest) (*UserResponse, *Errors, error) {
	var resp UserResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user").
		WithUriSegment(userId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateUserAction
// Updates the user action with the given Id.
//
//	string userActionId The Id of the user action to update.
//	UserActionRequest request The request that contains all the new user action information.
func (c *FusionAuthClient) UpdateUserAction(userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
	return c.UpdateUserActionWithContext(context.TODO(), userActionId, request)
}

// UpdateUserActionWithContext
// Updates the user action with the given Id.
//
//	string userActionId The Id of the user action to update.
//	UserActionRequest request The request that contains all the new user action information.
func (c *FusionAuthClient) UpdateUserActionWithContext(ctx context.Context, userActionId string, request UserActionRequest) (*UserActionResponse, *Errors, error) {
	var resp UserActionResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action").
		WithUriSegment(userActionId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateUserActionReason
// Updates the user action reason with the given Id.
//
//	string userActionReasonId The Id of the user action reason to update.
//	UserActionReasonRequest request The request that contains all the new user action reason information.
func (c *FusionAuthClient) UpdateUserActionReason(userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
	return c.UpdateUserActionReasonWithContext(context.TODO(), userActionReasonId, request)
}

// UpdateUserActionReasonWithContext
// Updates the user action reason with the given Id.
//
//	string userActionReasonId The Id of the user action reason to update.
//	UserActionReasonRequest request The request that contains all the new user action reason information.
func (c *FusionAuthClient) UpdateUserActionReasonWithContext(ctx context.Context, userActionReasonId string, request UserActionReasonRequest) (*UserActionReasonResponse, *Errors, error) {
	var resp UserActionReasonResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user-action-reason").
		WithUriSegment(userActionReasonId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateUserConsent
// Updates a single User consent by Id.
//
//	string userConsentId The User Consent Id
//	UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) UpdateUserConsent(userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
	return c.UpdateUserConsentWithContext(context.TODO(), userConsentId, request)
}

// UpdateUserConsentWithContext
// Updates a single User consent by Id.
//
//	string userConsentId The User Consent Id
//	UserConsentRequest request The request that contains the user consent information.
func (c *FusionAuthClient) UpdateUserConsentWithContext(ctx context.Context, userConsentId string, request UserConsentRequest) (*UserConsentResponse, *Errors, error) {
	var resp UserConsentResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/consent").
		WithUriSegment(userConsentId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpdateWebhook
// Updates the webhook with the given Id.
//
//	string webhookId The Id of the webhook to update.
//	WebhookRequest request The request that contains all the new webhook information.
func (c *FusionAuthClient) UpdateWebhook(webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
	return c.UpdateWebhookWithContext(context.TODO(), webhookId, request)
}

// UpdateWebhookWithContext
// Updates the webhook with the given Id.
//
//	string webhookId The Id of the webhook to update.
//	WebhookRequest request The request that contains all the new webhook information.
func (c *FusionAuthClient) UpdateWebhookWithContext(ctx context.Context, webhookId string, request WebhookRequest) (*WebhookResponse, *Errors, error) {
	var resp WebhookResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/webhook").
		WithUriSegment(webhookId).
		WithJSONBody(request).
		WithMethod(http.MethodPut).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// UpsertEntityGrant
// Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
//
//	string entityId The Id of the Entity that the User/Entity is being granted access to.
//	EntityGrantRequest request The request object that contains all the information used to create the Entity Grant.
func (c *FusionAuthClient) UpsertEntityGrant(entityId string, request EntityGrantRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.UpsertEntityGrantWithContext(context.TODO(), entityId, request)
}

// UpsertEntityGrantWithContext
// Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
//
//	string entityId The Id of the Entity that the User/Entity is being granted access to.
//	EntityGrantRequest request The request object that contains all the information used to create the Entity Grant.
func (c *FusionAuthClient) UpsertEntityGrantWithContext(ctx context.Context, entityId string, request EntityGrantRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/entity").
		WithUriSegment(entityId).
		WithUriSegment("grant").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// ValidateDevice
// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
//
//	string userCode The end-user verification code.
//	string clientId The client id.
func (c *FusionAuthClient) ValidateDevice(userCode string, clientId string) (*BaseHTTPResponse, error) {
	return c.ValidateDeviceWithContext(context.TODO(), userCode, clientId)
}

// ValidateDeviceWithContext
// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
//
//	string userCode The end-user verification code.
//	string clientId The client id.
func (c *FusionAuthClient) ValidateDeviceWithContext(ctx context.Context, userCode string, clientId string) (*BaseHTTPResponse, error) {
	var resp BaseHTTPResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/oauth2/device/validate").
		WithParameter("user_code", userCode).
		WithParameter("client_id", clientId).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// ValidateJWT
// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
// signed and not expired.
// <p>
// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) ValidateJWT(encodedJWT string) (*ValidateResponse, error) {
	return c.ValidateJWTWithContext(context.TODO(), encodedJWT)
}

// ValidateJWTWithContext
// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
// signed and not expired.
// <p>
// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
//
//	string encodedJWT The encoded JWT (access token).
func (c *FusionAuthClient) ValidateJWTWithContext(ctx context.Context, encodedJWT string) (*ValidateResponse, error) {
	var resp ValidateResponse

	err := c.StartAnonymous(&resp, nil).
		WithUri("/api/jwt/validate").
		WithAuthorization("Bearer " + encodedJWT).
		WithMethod(http.MethodGet).
		Do(ctx)
	return &resp, err
}

// VendJWT
// It's a JWT vending machine!
//
// Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form
// token that will contain what claims you provide.
// <p>
// The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
//
// If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either
// by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
//
//	JWTVendRequest request The request that contains all the claims for this JWT.
func (c *FusionAuthClient) VendJWT(request JWTVendRequest) (*JWTVendResponse, *Errors, error) {
	return c.VendJWTWithContext(context.TODO(), request)
}

// VendJWTWithContext
// It's a JWT vending machine!
//
// Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form
// token that will contain what claims you provide.
// <p>
// The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
//
// If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either
// by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
//
//	JWTVendRequest request The request that contains all the claims for this JWT.
func (c *FusionAuthClient) VendJWTWithContext(ctx context.Context, request JWTVendRequest) (*JWTVendResponse, *Errors, error) {
	var resp JWTVendResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/jwt/vend").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// VerifyEmail
// Confirms a email verification. The Id given is usually from an email sent to the user.
//
//	string verificationId The email verification id sent to the user.
//
// Deprecated: This method has been renamed to VerifyEmailAddress and changed to take a JSON request body, use that method instead.
func (c *FusionAuthClient) VerifyEmail(verificationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.VerifyEmailWithContext(context.TODO(), verificationId)
}

// VerifyEmailWithContext
// Confirms a email verification. The Id given is usually from an email sent to the user.
//
//	string verificationId The email verification id sent to the user.
//
// Deprecated: This method has been renamed to VerifyEmailAddressWithContext and changed to take a JSON request body, use that method instead.
func (c *FusionAuthClient) VerifyEmailWithContext(ctx context.Context, verificationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-email").
		WithUriSegment(verificationId).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// VerifyEmailAddress
// Confirms a user's email address.
//
// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
// the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one.
// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
// two values together are able to confirm a user's email address and mark the user's email address as verified.
//
//	VerifyEmailRequest request The request that contains the verificationId and optional one-time use code paired with the verificationId.
func (c *FusionAuthClient) VerifyEmailAddress(request VerifyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.VerifyEmailAddressWithContext(context.TODO(), request)
}

// VerifyEmailAddressWithContext
// Confirms a user's email address.
//
// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
// the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one.
// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
// two values together are able to confirm a user's email address and mark the user's email address as verified.
//
//	VerifyEmailRequest request The request that contains the verificationId and optional one-time use code paired with the verificationId.
func (c *FusionAuthClient) VerifyEmailAddressWithContext(ctx context.Context, request VerifyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-email").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// VerifyEmailAddressByUserId
// Administratively verify a user's email address. Use this method to bypass email verification for the user.
//
// The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
//
//	VerifyEmailRequest request The request that contains the userId to verify.
func (c *FusionAuthClient) VerifyEmailAddressByUserId(request VerifyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.VerifyEmailAddressByUserIdWithContext(context.TODO(), request)
}

// VerifyEmailAddressByUserIdWithContext
// Administratively verify a user's email address. Use this method to bypass email verification for the user.
//
// The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
//
//	VerifyEmailRequest request The request that contains the userId to verify.
func (c *FusionAuthClient) VerifyEmailAddressByUserIdWithContext(ctx context.Context, request VerifyEmailRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.Start(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-email").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// VerifyRegistration
// Confirms an application registration. The Id given is usually from an email sent to the user.
//
//	string verificationId The registration verification Id sent to the user.
//
// Deprecated: This method has been renamed to VerifyUserRegistration and changed to take a JSON request body, use that method instead.
func (c *FusionAuthClient) VerifyRegistration(verificationId string) (*BaseHTTPResponse, *Errors, error) {
	return c.VerifyRegistrationWithContext(context.TODO(), verificationId)
}

// VerifyRegistrationWithContext
// Confirms an application registration. The Id given is usually from an email sent to the user.
//
//	string verificationId The registration verification Id sent to the user.
//
// Deprecated: This method has been renamed to VerifyUserRegistrationWithContext and changed to take a JSON request body, use that method instead.
func (c *FusionAuthClient) VerifyRegistrationWithContext(ctx context.Context, verificationId string) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-registration").
		WithUriSegment(verificationId).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}

// VerifyUserRegistration
// Confirms a user's registration.
//
// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
// the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one.
// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
// two values together are able to confirm a user's registration and mark the user's registration as verified.
//
//	VerifyRegistrationRequest request The request that contains the verificationId and optional one-time use code paired with the verificationId.
func (c *FusionAuthClient) VerifyUserRegistration(request VerifyRegistrationRequest) (*BaseHTTPResponse, *Errors, error) {
	return c.VerifyUserRegistrationWithContext(context.TODO(), request)
}

// VerifyUserRegistrationWithContext
// Confirms a user's registration.
//
// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
// the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one.
// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
// two values together are able to confirm a user's registration and mark the user's registration as verified.
//
//	VerifyRegistrationRequest request The request that contains the verificationId and optional one-time use code paired with the verificationId.
func (c *FusionAuthClient) VerifyUserRegistrationWithContext(ctx context.Context, request VerifyRegistrationRequest) (*BaseHTTPResponse, *Errors, error) {
	var resp BaseHTTPResponse
	var errors Errors

	restClient := c.StartAnonymous(&resp, &errors)
	err := restClient.WithUri("/api/user/verify-registration").
		WithJSONBody(request).
		WithMethod(http.MethodPost).
		Do(ctx)
	if restClient.ErrorRef == nil {
		return &resp, nil, err
	}
	return &resp, &errors, err
}
