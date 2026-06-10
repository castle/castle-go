package castle

import "context"

// RequestUserData requests an export of the data Castle holds about a user.
// Required fields: identifier, identifier_type.
func (c *Castle) RequestUserData(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "POST", "privacy/users", params)
}

// DeleteUserData deletes the data Castle holds about a user. Required fields:
// identifier, identifier_type.
func (c *Castle) DeleteUserData(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "DELETE", "privacy/users", params)
}
