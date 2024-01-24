// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/bcrypt"

	"github.com/AmazeCom/terraform-provider-random/internal/diagnostics"
	boolplanmodifiers "github.com/AmazeCom/terraform-provider-random/internal/planmodifiers/bool"
	mapplanmodifiers "github.com/AmazeCom/terraform-provider-random/internal/planmodifiers/map"
	stringplanmodifiers "github.com/AmazeCom/terraform-provider-random/internal/planmodifiers/string"
	"github.com/AmazeCom/terraform-provider-random/internal/random"
)

var (
	_ resource.Resource                 = (*passwordResource)(nil)
	_ resource.ResourceWithImportState  = (*passwordResource)(nil)
	_ resource.ResourceWithUpgradeState = (*passwordResource)(nil)
)

func NewPasswordResource() resource.Resource {
	return &passwordResource{}
}

type passwordResource struct{}

func (r *passwordResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password"
}

func (r *passwordResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = passwordSchemaV0()
}

func (r *passwordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan passwordModelV0

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ImportOnly.ValueBool() {
		resp.Diagnostics.Append(diagnostics.ImportOnlyError()...)
		return
	}

	params := random.StringParams{
		Length:          plan.Length.ValueInt64(),
		Upper:           plan.Upper.ValueBool(),
		MinUpper:        plan.MinUpper.ValueInt64(),
		Lower:           plan.Lower.ValueBool(),
		MinLower:        plan.MinLower.ValueInt64(),
		Numeric:         plan.Numeric.ValueBool(),
		MinNumeric:      plan.MinNumeric.ValueInt64(),
		Special:         plan.Special.ValueBool(),
		MinSpecial:      plan.MinSpecial.ValueInt64(),
		OverrideSpecial: plan.OverrideSpecial.ValueString(),
	}

	result, err := random.CreateString(params)
	if err != nil {
		resp.Diagnostics.Append(diagnostics.RandomReadError(err.Error())...)
		return
	}

	hash, err := generateHash(string(result))
	if err != nil {
		resp.Diagnostics.Append(diagnostics.HashGenerationError(err.Error())...)
	}

	plan.BcryptHash = types.StringValue(hash)
	plan.ID = types.StringValue("none")
	plan.Result = types.StringValue(string(result))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read does not need to perform any operations as the state in ReadResourceResponse is already populated.
func (r *passwordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update ensures the plan value is copied to the state to complete the update.
func (r *passwordResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model passwordModelV0

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// Delete does not need to explicitly call resp.State.RemoveResource() as this is automatically handled by the
// [framework](https://github.com/hashicorp/terraform-plugin-framework/pull/301).
func (r *passwordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *passwordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	state := passwordModelV0{
		ID:              types.StringValue("none"),
		Result:          types.StringValue(id),
		Length:          types.Int64Value(int64(len(id))),
		Special:         types.BoolValue(true),
		Upper:           types.BoolValue(true),
		Lower:           types.BoolValue(true),
		Number:          types.BoolValue(true),
		Numeric:         types.BoolValue(true),
		MinSpecial:      types.Int64Value(0),
		MinUpper:        types.Int64Value(0),
		MinLower:        types.Int64Value(0),
		MinNumeric:      types.Int64Value(0),
		Keepers:         types.MapNull(types.StringType),
		OverrideSpecial: types.StringNull(),
		ImportOnly:      types.BoolValue(false),
	}

	hash, err := generateHash(id)
	if err != nil {
		resp.Diagnostics.Append(diagnostics.HashGenerationError(err.Error())...)
	}

	state.BcryptHash = types.StringValue(hash)

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *passwordResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{}
}

// generateHash truncates strings that are longer than 72 bytes in
// order to avoid the error returned from bcrypt.GenerateFromPassword
// in versions v0.5.0 and above: https://pkg.go.dev/golang.org/x/crypto@v0.8.0/bcrypt#GenerateFromPassword
func generateHash(toHash string) (string, error) {
	bytesHash := []byte(toHash)
	bytesToHash := bytesHash

	if len(bytesHash) > 72 {
		bytesToHash = bytesHash[:72]
	}

	hash, err := bcrypt.GenerateFromPassword(bytesToHash, bcrypt.DefaultCost)

	return string(hash), err
}

func passwordSchemaV0() schema.Schema {
	return schema.Schema{
		Version: 0,
		Description: "Identical to [random_string](string.html) with the exception that the result is " +
			"treated as sensitive and, thus, _not_ displayed in console output. Read more about sensitive " +
			"data handling in the " +
			"[Terraform documentation](https://www.terraform.io/docs/language/state/sensitive-data.html).\n\n" +
			"This resource *does* use a cryptographic random number generator.",
		Attributes: map[string]schema.Attribute{
			"keepers": schema.MapAttribute{
				Description: "Arbitrary map of values that, when changed, will trigger recreation of " +
					"resource. See [the main provider documentation](../index.html) for more information.",
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Map{
					mapplanmodifiers.RequiresReplaceIfValuesNotNull(),
				},
			},

			"length": schema.Int64Attribute{
				Description: "The length of the string desired. The minimum value for length is 1 and, length " +
					"must also be >= (`min_upper` + `min_lower` + `min_numeric` + `min_special`).",
				Required: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
					int64validator.AtLeastSumOf(
						path.MatchRoot("min_upper"),
						path.MatchRoot("min_lower"),
						path.MatchRoot("min_numeric"),
						path.MatchRoot("min_special"),
					),
				},
			},

			"special": schema.BoolAttribute{
				Description: "Include special characters in the result. These are `!@#$%&*()-_=+[]{}<>:?`. Default value is `true`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},

			"upper": schema.BoolAttribute{
				Description: "Include uppercase alphabet characters in the result. Default value is `true`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				}},

			"lower": schema.BoolAttribute{
				Description: "Include lowercase alphabet characters in the result. Default value is `true`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},

			"number": schema.BoolAttribute{
				Description: "Include numeric characters in the result. Default value is `true`. " +
					"**NOTE**: This is deprecated, use `numeric` instead.",
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifiers.NumberNumericAttributePlanModifier(),
					boolplanmodifier.RequiresReplace(),
				},
				DeprecationMessage: "**NOTE**: This is deprecated, use `numeric` instead.",
			},

			"numeric": schema.BoolAttribute{
				Description: "Include numeric characters in the result. Default value is `true`.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifiers.NumberNumericAttributePlanModifier(),
					boolplanmodifier.RequiresReplace(),
				},
			},

			"min_numeric": schema.Int64Attribute{
				Description: "Minimum number of numeric characters in the result. Default value is `0`.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},

			"min_upper": schema.Int64Attribute{
				Description: "Minimum number of uppercase alphabet characters in the result. Default value is `0`.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},

			"min_lower": schema.Int64Attribute{
				Description: "Minimum number of lowercase alphabet characters in the result. Default value is `0`.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},

			"min_special": schema.Int64Attribute{
				Description: "Minimum number of special characters in the result. Default value is `0`.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},

			"override_special": schema.StringAttribute{
				Description: "Supply your own list of special characters to use for string generation.  This " +
					"overrides the default character list in the special argument.  The `special` argument must " +
					"still be set to true for any overwritten characters to be used in generation.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						stringplanmodifiers.RequiresReplaceUnlessEmptyStringToNull(),
						"Replace on modification unless updating from empty string (\"\") to null.",
						"Replace on modification unless updating from empty string (`\"\"`) to `null`.",
					),
				},
			},

			"import_only": schema.BoolAttribute{
				Description: "Only allow import, password generation will throw an error. Default value is `false`.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},

			"result": schema.StringAttribute{
				Description: "The generated random string.",
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"bcrypt_hash": schema.StringAttribute{
				Description: "A bcrypt hash of the generated random string. " +
					"**NOTE**: If the generated random string is greater than 72 bytes in length, " +
					"`bcrypt_hash` will contain a hash of the first 72 bytes.",
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"id": schema.StringAttribute{
				Description: "A static value used internally by Terraform, this should not be referenced in configurations.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

type passwordModelV0 struct {
	ID              types.String `tfsdk:"id"`
	Keepers         types.Map    `tfsdk:"keepers"`
	Length          types.Int64  `tfsdk:"length"`
	Special         types.Bool   `tfsdk:"special"`
	Upper           types.Bool   `tfsdk:"upper"`
	Lower           types.Bool   `tfsdk:"lower"`
	Number          types.Bool   `tfsdk:"number"`
	Numeric         types.Bool   `tfsdk:"numeric"`
	MinNumeric      types.Int64  `tfsdk:"min_numeric"`
	MinUpper        types.Int64  `tfsdk:"min_upper"`
	MinLower        types.Int64  `tfsdk:"min_lower"`
	MinSpecial      types.Int64  `tfsdk:"min_special"`
	OverrideSpecial types.String `tfsdk:"override_special"`
	ImportOnly      types.Bool   `tfsdk:"import_only"`
	Result          types.String `tfsdk:"result"`
	BcryptHash      types.String `tfsdk:"bcrypt_hash"`
}
