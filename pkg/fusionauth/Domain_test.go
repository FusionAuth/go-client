/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestErrorsPresentReturnsTrueWhenFieldErrorsExist(t *testing.T) {
	errors := Errors{
		FieldErrors: map[string][]Error{
			"user.username": []Error{
				Error{
					Code:    "[duplicate.email]",
					Message: "The email 'example@example.com' is already registered.",
				},
			},
		},
		GeneralErrors: []Error{},
	}
	assert.True(t, errors.Present())
}

func TestErrorsPresentReturnsTrueWhenGeneralErrorsExist(t *testing.T) {
	errors := Errors{
		GeneralErrors: []Error{
			Error{
				Code:    "",
				Message: "Token has expired.",
			},
		},
	}
	assert.True(t, errors.Present())
}

func TestErrorsPresentReturnsTrueWhenBothFieldAndGeneralErrorsExist(t *testing.T) {
	errors := Errors{
		FieldErrors: map[string][]Error{
			"user.username": []Error{
				Error{
					Code:    "[duplicate.email]",
					Message: "The email 'example@example.com' is already registered.",
				},
			},
		},
		GeneralErrors: []Error{
			Error{
				Code:    "",
				Message: "Token has expired.",
			},
		},
	}
	assert.True(t, errors.Present())
}

func TestErrorsPresentReturnsFalseWhenNeitherFieldAndGeneralErrorsExist(t *testing.T) {
	errors := Errors{
		FieldErrors:   map[string][]Error{},
		GeneralErrors: []Error{},
	}
	assert.False(t, errors.Present())
}

func TestErrorsPrintedToReadableStringByDefault(t *testing.T) {
	errors := Errors{
		FieldErrors: map[string][]Error{
			"user.username": []Error{
				Error{
					Code:    "[duplicate.email]",
					Message: "The email 'example@example.com' is already registered.",
				},
			},
		},
		GeneralErrors: []Error{
			Error{
				Code:    "",
				Message: "Token has expired.",
			},
		},
	}

	assert.Equal(t, "Token has expired. user.username: The email 'example@example.com' is already registered.", errors.Error())
}
