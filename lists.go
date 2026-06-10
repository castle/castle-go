package castle

import (
	"context"
	"net/url"
)

// CreateList creates a new list. Required fields: name, color, primary_field.
func (c *Castle) CreateList(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "POST", "lists", params)
}

// GetAllLists returns every list for the authenticated account.
func (c *Castle) GetAllLists(ctx context.Context) (Params, error) {
	return c.request(ctx, "GET", "lists", nil)
}

// GetList returns a single list by ID.
func (c *Castle) GetList(ctx context.Context, listID string) (Params, error) {
	return c.request(ctx, "GET", "lists/"+url.PathEscape(listID), nil)
}

// QueryLists returns lists matching the supplied filters.
func (c *Castle) QueryLists(ctx context.Context, params Params) (Params, error) {
	return c.request(ctx, "POST", "lists/query", params)
}

// UpdateList updates a list by ID.
func (c *Castle) UpdateList(ctx context.Context, listID string, params Params) (Params, error) {
	return c.request(ctx, "PUT", "lists/"+url.PathEscape(listID), params)
}

// DeleteList deletes a list by ID.
func (c *Castle) DeleteList(ctx context.Context, listID string) (Params, error) {
	return c.request(ctx, "DELETE", "lists/"+url.PathEscape(listID), nil)
}

// CreateListItem adds an item to a list. Required fields: author, primary_value.
func (c *Castle) CreateListItem(ctx context.Context, listID string, params Params) (Params, error) {
	return c.request(ctx, "POST", listItemsPath(listID), params)
}

// CreateListItemsBatch adds multiple items to a list in a single request.
func (c *Castle) CreateListItemsBatch(ctx context.Context, listID string, items []Params) (Params, error) {
	return c.request(ctx, "POST", listItemsPath(listID)+"/batch", Params{"items": items})
}

// GetListItem returns a single list item by ID.
func (c *Castle) GetListItem(ctx context.Context, listID, itemID string) (Params, error) {
	return c.request(ctx, "GET", listItemPath(listID, itemID), nil)
}

// QueryListItems returns list items matching the supplied filters.
func (c *Castle) QueryListItems(ctx context.Context, listID string, params Params) (Params, error) {
	return c.request(ctx, "POST", listItemsPath(listID)+"/query", params)
}

// CountListItems returns the number of list items matching the supplied filters.
func (c *Castle) CountListItems(ctx context.Context, listID string, params Params) (Params, error) {
	return c.request(ctx, "POST", listItemsPath(listID)+"/count", params)
}

// UpdateListItem updates a list item by ID. Required field: comment.
func (c *Castle) UpdateListItem(ctx context.Context, listID, itemID string, params Params) (Params, error) {
	return c.request(ctx, "PUT", listItemPath(listID, itemID), params)
}

// ArchiveListItem archives a list item by ID.
func (c *Castle) ArchiveListItem(ctx context.Context, listID, itemID string) (Params, error) {
	return c.request(ctx, "DELETE", listItemPath(listID, itemID)+"/archive", nil)
}

// UnarchiveListItem restores a previously archived list item.
func (c *Castle) UnarchiveListItem(ctx context.Context, listID, itemID string) (Params, error) {
	return c.request(ctx, "PUT", listItemPath(listID, itemID)+"/unarchive", nil)
}

func listItemsPath(listID string) string {
	return "lists/" + url.PathEscape(listID) + "/items"
}

func listItemPath(listID, itemID string) string {
	return listItemsPath(listID) + "/" + url.PathEscape(itemID)
}
