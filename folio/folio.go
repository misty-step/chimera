// Package folio embeds the Folio's canonical assets (folio/assets/**) so that
// generated reports ship them byte-for-byte. The files themselves are part
// of the Intent and are never edited here.
package folio

import "embed"

// Assets holds folio/assets/trail-reference: the reference stylesheet, the
// self-hosted fonts, the favicon, and the reference media.
//
//go:embed assets/trail-reference
var Assets embed.FS

// TrailReference is the root of the reference bundle inside Assets.
const TrailReference = "assets/trail-reference"
