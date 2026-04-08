// Package web embeds all static web assets (templates and JS/CSS).
// This package exists solely so that the embed directive can reference
// the templates/ and static/ directories as siblings (no ".." needed).
package web

import "embed"

//go:embed templates static
var FS embed.FS
