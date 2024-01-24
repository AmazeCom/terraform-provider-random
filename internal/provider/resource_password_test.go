// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	// "context" .
	// "errors" .
	"fmt"
	"regexp"
	// "runtime" .
	"testing"

	// "github.com/google/go-cmp/cmp" .
	// "github.com/hashicorp/terraform-plugin-framework/path" .
	// res "github.com/hashicorp/terraform-plugin-framework/resource" .
	// "github.com/hashicorp/terraform-plugin-framework/tfsdk" .
	// "github.com/hashicorp/terraform-plugin-go/tftypes" .
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"golang.org/x/crypto/bcrypt"

	"github.com/AmazeCom/terraform-provider-random/internal/random"
)

func TestGenerateHash(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input random.StringParams
	}{
		"defaults": {
			input: random.StringParams{
				Length:  73, // Required
				Lower:   true,
				Numeric: true,
				Special: true,
				Upper:   true,
			},
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			randomBytes, err := random.CreateString(testCase.input)

			if err != nil {
				t.Fatalf("unexpected random.CreateString error: %s", err)
			}

			hash, err := generateHash(string(randomBytes))

			if err != nil {
				t.Fatalf("unexpected generateHash error: %s", err)
			}

			err = bcrypt.CompareHashAndPassword([]byte(hash), randomBytes)

			if err != nil {
				t.Fatalf("unexpected bcrypt.CompareHashAndPassword error: %s", err)
			}
		})
	}
}

func TestAccResourcePassword_Import(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "random_password" "basic" {
							length = 12
						}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("random_password.basic", "result", testCheckLen(12)),
				),
			},
			{
				ResourceName: "random_password.basic",
				// Usage of ImportStateIdFunc is required as the value passed to the `terraform import` command needs
				// to be the password itself, as the password resource sets ID to "none" and "result" to the password
				// supplied during import.
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					id := "random_password.basic"
					rs, ok := s.RootModule().Resources[id]
					if !ok {
						return "", fmt.Errorf("not found: %s", id)
					}
					if rs.Primary.ID == "" {
						return "", fmt.Errorf("no ID is set")
					}

					return rs.Primary.Attributes["result"], nil
				},
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"bcrypt_hash"},
			},
		},
	})
}

func TestAccResourcePassword_BcryptHash(t *testing.T) {
	t.Parallel()

	var result, bcryptHash string

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "random_password" "test" {
							length = 73
						}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "bcrypt_hash", &bcryptHash),
					testExtractResourceAttr("random_password.test", "result", &result),
					testBcryptHashValid(&bcryptHash, &result),
				),
			},
		},
	})
}

func TestAccResourcePassword_Override(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "random_password" "override" {
							length = 4
							override_special = "!"
							lower = false
							upper = false
							numeric = false
						}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("random_password.override", "result", testCheckLen(4)),
					resource.TestCheckResourceAttr("random_password.override", "result", "!!!!"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Min(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "random_password" "min" {
							length = 12
							override_special = "!#@"
							min_lower = 2
							min_upper = 3
							min_special = 1
							min_numeric = 4
						}`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("random_password.min", "result", testCheckLen(12)),
					resource.TestMatchResourceAttr("random_password.min", "result", regexp.MustCompile(`([a-z].*){2,}`)),
					resource.TestMatchResourceAttr("random_password.min", "result", regexp.MustCompile(`([A-Z].*){3,}`)),
					resource.TestMatchResourceAttr("random_password.min", "result", regexp.MustCompile(`([0-9].*){4,}`)),
					resource.TestMatchResourceAttr("random_password.min", "result", regexp.MustCompile(`([!#@])`)),
				),
			},
		},
	})
}

func TestAccResourcePassword_NumberNumericErrors(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "random_password" "number_numeric_differ" {
  							length = 1
							number = false
  							numeric = true
						}`,
				ExpectError: regexp.MustCompile(`.*Number and numeric are both configured with different values`),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_EmptyMap(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_EmptyMapToNullValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_NullMap(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_NullMapToNullValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_NullValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_NullValues(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key1" = null
						"key2" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "2"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key1" = null
						"key2" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "2"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_Value(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Keep_Values(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key1" = "123"
						"key2" = "456"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "2"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key1" = "123"
						"key2" = "456"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesEqual(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "2"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_EmptyMapToValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_NullMapToValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_NullValueToValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_ValueToEmptyMap(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_ValueToNullMap(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "0"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_ValueToNullValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = null
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func TestAccResourcePassword_Keepers_Replace_ValueToNewValue(t *testing.T) {
	var result1, result2 string

	resource.ParallelTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "123"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result1),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `resource "random_password" "test" {
					length = 12
					keepers = {
						"key" = "456"
					}
				}`,
				Check: resource.ComposeTestCheckFunc(
					testExtractResourceAttr("random_password.test", "result", &result2),
					testCheckAttributeValuesDiffer(&result1, &result2),
					resource.TestCheckResourceAttr("random_password.test", "keepers.%", "1"),
				),
			},
		},
	})
}

func testBcryptHashValid(hash *string, password *string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		if hash == nil || *hash == "" {
			return fmt.Errorf("expected hash value")
		}

		if password == nil || *password == "" {
			return fmt.Errorf("expected password value")
		}

		return bcrypt.CompareHashAndPassword([]byte(*hash), []byte(*password))
	}
}

func composeImportStateCheck(fs ...resource.ImportStateCheckFunc) resource.ImportStateCheckFunc {
	return func(s []*terraform.InstanceState) error {
		for i, f := range fs {
			if err := f(s); err != nil {
				return fmt.Errorf("check %d/%d error: %s", i+1, len(fs), err)
			}
		}

		return nil
	}
}

//nolint:unparam
func testExtractResourceAttrInstanceState(attributeName string, attributeValue *string) resource.ImportStateCheckFunc {
	return func(is []*terraform.InstanceState) error {
		if len(is) != 1 {
			return fmt.Errorf("unexpected number of instance states: %d", len(is))
		}

		s := is[0]

		attrValue, ok := s.Attributes[attributeName]
		if !ok {
			return fmt.Errorf("attribute %s not found in instance state", attributeName)
		}

		*attributeValue = attrValue

		return nil
	}
}

func testCheckNoResourceAttrInstanceState(attributeName string) resource.ImportStateCheckFunc {
	return func(is []*terraform.InstanceState) error {
		if len(is) != 1 {
			return fmt.Errorf("unexpected number of instance states: %d", len(is))
		}

		s := is[0]

		_, ok := s.Attributes[attributeName]
		if ok {
			return fmt.Errorf("attribute %s found in instance state", attributeName)
		}

		return nil
	}
}

func testCheckResourceAttrInstanceState(attributeName string) resource.ImportStateCheckFunc {
	return func(is []*terraform.InstanceState) error {
		if len(is) != 1 {
			return fmt.Errorf("unexpected number of instance states: %d", len(is))
		}

		s := is[0]

		_, ok := s.Attributes[attributeName]
		if !ok {
			return fmt.Errorf("attribute %s not found in instance state", attributeName)
		}

		return nil
	}
}
