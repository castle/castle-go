package castle

import "context"

// EventsSchema returns the event schema for the authenticated account.
func (c *Castle) EventsSchema(ctx context.Context) (Params, error) {
	return c.request(ctx, "GET", "events/schema", nil)
}

// QueryEvents returns events matching the supplied filters.
func (c *Castle) QueryEvents(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "POST", "events/query", params)
}

// GroupEvents returns aggregated event counts grouped by the supplied criteria.
func (c *Castle) GroupEvents(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "POST", "events/group", params)
}
