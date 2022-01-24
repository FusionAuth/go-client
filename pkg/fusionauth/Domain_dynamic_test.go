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
	"fmt"
	"testing"
)

func Test_AlgorithmImplementsStringer(t *testing.T) {
	var enum interface{} = Algorithm("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("Algorithm does not implement stringer interface\n")
	}
}

func Test_AuthenticationThreatsImplementsStringer(t *testing.T) {
	var enum interface{} = AuthenticationThreats("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("AuthenticationThreats does not implement stringer interface\n")
	}
}

func Test_BreachActionImplementsStringer(t *testing.T) {
	var enum interface{} = BreachAction("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("BreachAction does not implement stringer interface\n")
	}
}

func Test_BreachedPasswordStatusImplementsStringer(t *testing.T) {
	var enum interface{} = BreachedPasswordStatus("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("BreachedPasswordStatus does not implement stringer interface\n")
	}
}

func Test_BreachMatchModeImplementsStringer(t *testing.T) {
	var enum interface{} = BreachMatchMode("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("BreachMatchMode does not implement stringer interface\n")
	}
}

func Test_CanonicalizationMethodImplementsStringer(t *testing.T) {
	var enum interface{} = CanonicalizationMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("CanonicalizationMethod does not implement stringer interface\n")
	}
}

func Test_CaptchaMethodImplementsStringer(t *testing.T) {
	var enum interface{} = CaptchaMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("CaptchaMethod does not implement stringer interface\n")
	}
}

func Test_ChangePasswordReasonImplementsStringer(t *testing.T) {
	var enum interface{} = ChangePasswordReason("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ChangePasswordReason does not implement stringer interface\n")
	}
}

func Test_ClientAuthenticationMethodImplementsStringer(t *testing.T) {
	var enum interface{} = ClientAuthenticationMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ClientAuthenticationMethod does not implement stringer interface\n")
	}
}

func Test_ClientAuthenticationPolicyImplementsStringer(t *testing.T) {
	var enum interface{} = ClientAuthenticationPolicy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ClientAuthenticationPolicy does not implement stringer interface\n")
	}
}

func Test_ConnectorTypeImplementsStringer(t *testing.T) {
	var enum interface{} = ConnectorType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ConnectorType does not implement stringer interface\n")
	}
}

func Test_ConsentStatusImplementsStringer(t *testing.T) {
	var enum interface{} = ConsentStatus("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ConsentStatus does not implement stringer interface\n")
	}
}

func Test_ContentStatusImplementsStringer(t *testing.T) {
	var enum interface{} = ContentStatus("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ContentStatus does not implement stringer interface\n")
	}
}

func Test_DeviceTypeImplementsStringer(t *testing.T) {
	var enum interface{} = DeviceType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("DeviceType does not implement stringer interface\n")
	}
}

func Test_EmailSecurityTypeImplementsStringer(t *testing.T) {
	var enum interface{} = EmailSecurityType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("EmailSecurityType does not implement stringer interface\n")
	}
}

func Test_EventLogTypeImplementsStringer(t *testing.T) {
	var enum interface{} = EventLogType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("EventLogType does not implement stringer interface\n")
	}
}

func Test_EventTypeImplementsStringer(t *testing.T) {
	var enum interface{} = EventType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("EventType does not implement stringer interface\n")
	}
}

func Test_ExpiryUnitImplementsStringer(t *testing.T) {
	var enum interface{} = ExpiryUnit("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ExpiryUnit does not implement stringer interface\n")
	}
}

func Test_FamilyRoleImplementsStringer(t *testing.T) {
	var enum interface{} = FamilyRole("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("FamilyRole does not implement stringer interface\n")
	}
}

func Test_FormControlImplementsStringer(t *testing.T) {
	var enum interface{} = FormControl("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("FormControl does not implement stringer interface\n")
	}
}

func Test_FormDataTypeImplementsStringer(t *testing.T) {
	var enum interface{} = FormDataType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("FormDataType does not implement stringer interface\n")
	}
}

func Test_FormFieldAdminPolicyImplementsStringer(t *testing.T) {
	var enum interface{} = FormFieldAdminPolicy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("FormFieldAdminPolicy does not implement stringer interface\n")
	}
}

func Test_FormTypeImplementsStringer(t *testing.T) {
	var enum interface{} = FormType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("FormType does not implement stringer interface\n")
	}
}

func Test_GrantTypeImplementsStringer(t *testing.T) {
	var enum interface{} = GrantType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("GrantType does not implement stringer interface\n")
	}
}

func Test_HTTPMethodImplementsStringer(t *testing.T) {
	var enum interface{} = HTTPMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("HTTPMethod does not implement stringer interface\n")
	}
}

func Test_IdentityProviderLinkingStrategyImplementsStringer(t *testing.T) {
	var enum interface{} = IdentityProviderLinkingStrategy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("IdentityProviderLinkingStrategy does not implement stringer interface\n")
	}
}

func Test_IdentityProviderLoginMethodImplementsStringer(t *testing.T) {
	var enum interface{} = IdentityProviderLoginMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("IdentityProviderLoginMethod does not implement stringer interface\n")
	}
}

func Test_IdentityProviderTypeImplementsStringer(t *testing.T) {
	var enum interface{} = IdentityProviderType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("IdentityProviderType does not implement stringer interface\n")
	}
}

func Test_IPAccessControlEntryActionImplementsStringer(t *testing.T) {
	var enum interface{} = IPAccessControlEntryAction("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("IPAccessControlEntryAction does not implement stringer interface\n")
	}
}

func Test_KeyAlgorithmImplementsStringer(t *testing.T) {
	var enum interface{} = KeyAlgorithm("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("KeyAlgorithm does not implement stringer interface\n")
	}
}

func Test_KeyTypeImplementsStringer(t *testing.T) {
	var enum interface{} = KeyType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("KeyType does not implement stringer interface\n")
	}
}

func Test_KeyUseImplementsStringer(t *testing.T) {
	var enum interface{} = KeyUse("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("KeyUse does not implement stringer interface\n")
	}
}

func Test_LambdaTypeImplementsStringer(t *testing.T) {
	var enum interface{} = LambdaType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("LambdaType does not implement stringer interface\n")
	}
}

func Test_LDAPSecurityMethodImplementsStringer(t *testing.T) {
	var enum interface{} = LDAPSecurityMethod("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("LDAPSecurityMethod does not implement stringer interface\n")
	}
}

func Test_LoginIdTypeImplementsStringer(t *testing.T) {
	var enum interface{} = LoginIdType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("LoginIdType does not implement stringer interface\n")
	}
}

func Test_LogoutBehaviorImplementsStringer(t *testing.T) {
	var enum interface{} = LogoutBehavior("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("LogoutBehavior does not implement stringer interface\n")
	}
}

func Test_MessageTypeImplementsStringer(t *testing.T) {
	var enum interface{} = MessageType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("MessageType does not implement stringer interface\n")
	}
}

func Test_MessengerTypeImplementsStringer(t *testing.T) {
	var enum interface{} = MessengerType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("MessengerType does not implement stringer interface\n")
	}
}

func Test_OAuthErrorReasonImplementsStringer(t *testing.T) {
	var enum interface{} = OAuthErrorReason("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("OAuthErrorReason does not implement stringer interface\n")
	}
}

func Test_OAuthErrorTypeImplementsStringer(t *testing.T) {
	var enum interface{} = OAuthErrorType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("OAuthErrorType does not implement stringer interface\n")
	}
}

func Test_ObjectStateImplementsStringer(t *testing.T) {
	var enum interface{} = ObjectState("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ObjectState does not implement stringer interface\n")
	}
}

func Test_ProofKeyForCodeExchangePolicyImplementsStringer(t *testing.T) {
	var enum interface{} = ProofKeyForCodeExchangePolicy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ProofKeyForCodeExchangePolicy does not implement stringer interface\n")
	}
}

func Test_RateLimitedRequestTypeImplementsStringer(t *testing.T) {
	var enum interface{} = RateLimitedRequestType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("RateLimitedRequestType does not implement stringer interface\n")
	}
}

func Test_ReactorFeatureStatusImplementsStringer(t *testing.T) {
	var enum interface{} = ReactorFeatureStatus("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("ReactorFeatureStatus does not implement stringer interface\n")
	}
}

func Test_RefreshTokenExpirationPolicyImplementsStringer(t *testing.T) {
	var enum interface{} = RefreshTokenExpirationPolicy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("RefreshTokenExpirationPolicy does not implement stringer interface\n")
	}
}

func Test_RefreshTokenUsagePolicyImplementsStringer(t *testing.T) {
	var enum interface{} = RefreshTokenUsagePolicy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("RefreshTokenUsagePolicy does not implement stringer interface\n")
	}
}

func Test_RegistrationTypeImplementsStringer(t *testing.T) {
	var enum interface{} = RegistrationType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("RegistrationType does not implement stringer interface\n")
	}
}

func Test_SAMLLogoutBehaviorImplementsStringer(t *testing.T) {
	var enum interface{} = SAMLLogoutBehavior("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("SAMLLogoutBehavior does not implement stringer interface\n")
	}
}

func Test_SecureGeneratorTypeImplementsStringer(t *testing.T) {
	var enum interface{} = SecureGeneratorType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("SecureGeneratorType does not implement stringer interface\n")
	}
}

func Test_SortImplementsStringer(t *testing.T) {
	var enum interface{} = Sort("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("Sort does not implement stringer interface\n")
	}
}

func Test_TokenTypeImplementsStringer(t *testing.T) {
	var enum interface{} = TokenType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("TokenType does not implement stringer interface\n")
	}
}

func Test_TOTPAlgorithmImplementsStringer(t *testing.T) {
	var enum interface{} = TOTPAlgorithm("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("TOTPAlgorithm does not implement stringer interface\n")
	}
}

func Test_TransactionTypeImplementsStringer(t *testing.T) {
	var enum interface{} = TransactionType("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("TransactionType does not implement stringer interface\n")
	}
}

func Test_UniqueUsernameStrategyImplementsStringer(t *testing.T) {
	var enum interface{} = UniqueUsernameStrategy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("UniqueUsernameStrategy does not implement stringer interface\n")
	}
}

func Test_UnverifiedBehaviorImplementsStringer(t *testing.T) {
	var enum interface{} = UnverifiedBehavior("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("UnverifiedBehavior does not implement stringer interface\n")
	}
}

func Test_UserActionPhaseImplementsStringer(t *testing.T) {
	var enum interface{} = UserActionPhase("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("UserActionPhase does not implement stringer interface\n")
	}
}

func Test_UserStateImplementsStringer(t *testing.T) {
	var enum interface{} = UserState("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("UserState does not implement stringer interface\n")
	}
}

func Test_VerificationStrategyImplementsStringer(t *testing.T) {
	var enum interface{} = VerificationStrategy("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("VerificationStrategy does not implement stringer interface\n")
	}
}

func Test_XMLSignatureLocationImplementsStringer(t *testing.T) {
	var enum interface{} = XMLSignatureLocation("Test")
	if _, ok := enum.(fmt.Stringer); !ok {
		t.Errorf("XMLSignatureLocation does not implement stringer interface\n")
	}
}
