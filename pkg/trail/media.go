package trail

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Fallback dimensions for a media file whose header does not give its size.
const (
	fallbackWidth  = 1280
	fallbackHeight = 720
)

var mediaKinds = map[string]string{
	".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image", ".webp": "image", ".svg": "image",
	".mp4": "video", ".webm": "video",
}

var (
	unsafeNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	idTokenRE    = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])([a-z][a-z0-9]*-[0-9]+)`)
)

// addMedia copies the watchable members of a Capsule's proof/ into the
// report: images and video, byte for byte, named media/<capsule12>-<name>.
func (r *Report) addMedia(l *loaded, info *intentInfo) {
	var members []string
	for name := range l.local.Members {
		if _, ok := mediaKinds[strings.ToLower(path.Ext(name))]; ok && strings.HasPrefix(name, "proof/") {
			members = append(members, name)
		}
	}
	sort.Strings(members)
	for _, member := range members {
		data := l.local.Members[member]
		rel := strings.TrimPrefix(member, "proof/")
		file := "media/" + hex12(l.addr) + "-" + unsafeNameRE.ReplaceAllString(strings.ReplaceAll(rel, "/", "-"), "-")
		for n := 2; r.media[file] != nil; n++ {
			ext := path.Ext(file)
			file = strings.TrimSuffix(file, ext) + "-" + strconv.Itoa(n) + ext
		}
		sum := sha256.Sum256(data)
		m := Media{File: file, Name: path.Base(member), Member: member, Kind: mediaKinds[strings.ToLower(path.Ext(member))],
			Capsule: l.addr, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
		m.Width, m.Height = dimensions(strings.ToLower(path.Ext(member)), data)
		m.ID = mediaID(l, info, member)
		r.media[file] = data
		r.Media = append(r.Media, m)
	}
}

// mediaID finds the acceptance ID a proof file belongs to: the verdict whose
// evidence names the file, else an ID spelled in the file name
// ("m2-1-walkthrough.mp4" → [M2-1]) that the Capsule or its Intent knows.
func mediaID(l *loaded, info *intentInfo, member string) string {
	base := path.Base(member)
	for _, v := range l.verdicts {
		if strings.Contains(v.Evidence, member) || strings.Contains(v.Evidence, base) {
			return v.ID
		}
	}
	for _, m := range idTokenRE.FindAllStringSubmatch(base, -1) {
		id := "[" + strings.ToUpper(m[1]) + "]"
		if info != nil && info.declared[id] {
			return id
		}
		for _, v := range l.verdicts {
			if v.ID == id {
				return id
			}
		}
	}
	return ""
}

// dimensions reads the pixel size from a media file's own header.
func dimensions(ext string, data []byte) (w, h int) {
	switch ext {
	case ".png":
		w, h = pngSize(data)
	case ".gif":
		w, h = gifSize(data)
	case ".jpg", ".jpeg":
		w, h = jpegSize(data)
	case ".webp":
		w, h = webpSize(data)
	case ".svg":
		w, h = svgSize(data)
	case ".mp4":
		w, h = mp4Size(data, 0)
	case ".webm":
		w, h = webmSize(data)
	}
	if w <= 0 || h <= 0 || w > 1<<15 || h > 1<<15 {
		return fallbackWidth, fallbackHeight
	}
	return w, h
}

func pngSize(d []byte) (int, int) {
	if len(d) < 24 || !bytes.HasPrefix(d, []byte("\x89PNG\r\n\x1a\n")) {
		return 0, 0
	}
	return int(binary.BigEndian.Uint32(d[16:])), int(binary.BigEndian.Uint32(d[20:]))
}

func gifSize(d []byte) (int, int) {
	if len(d) < 10 || !bytes.HasPrefix(d, []byte("GIF8")) {
		return 0, 0
	}
	return int(binary.LittleEndian.Uint16(d[6:])), int(binary.LittleEndian.Uint16(d[8:]))
}

func jpegSize(d []byte) (int, int) {
	if len(d) < 4 || d[0] != 0xff || d[1] != 0xd8 {
		return 0, 0
	}
	for i := 2; i+9 < len(d); {
		if d[i] != 0xff {
			return 0, 0
		}
		marker := d[i+1]
		if marker == 0xff {
			i++
			continue
		}
		if marker >= 0xc0 && marker <= 0xcf && marker != 0xc4 && marker != 0xc8 && marker != 0xcc {
			return int(binary.BigEndian.Uint16(d[i+7:])), int(binary.BigEndian.Uint16(d[i+5:]))
		}
		i += 2 + int(binary.BigEndian.Uint16(d[i+2:]))
	}
	return 0, 0
}

func webpSize(d []byte) (int, int) {
	if len(d) < 30 || string(d[:4]) != "RIFF" || string(d[8:12]) != "WEBP" {
		return 0, 0
	}
	switch string(d[12:16]) {
	case "VP8X":
		return 1 + (int(d[24]) | int(d[25])<<8 | int(d[26])<<16), 1 + (int(d[27]) | int(d[28])<<8 | int(d[29])<<16)
	case "VP8 ":
		return int(binary.LittleEndian.Uint16(d[26:]) & 0x3fff), int(binary.LittleEndian.Uint16(d[28:]) & 0x3fff)
	case "VP8L":
		b := binary.LittleEndian.Uint32(d[21:])
		return int(b&0x3fff) + 1, int((b>>14)&0x3fff) + 1
	}
	return 0, 0
}

var (
	svgTagRE     = regexp.MustCompile(`(?s)<svg\b[^>]*>`)
	svgWidthRE   = regexp.MustCompile(`\swidth\s*=\s*["']\s*([0-9.]+)(?:px)?\s*["']`)
	svgHeightRE  = regexp.MustCompile(`\sheight\s*=\s*["']\s*([0-9.]+)(?:px)?\s*["']`)
	svgViewBoxRE = regexp.MustCompile(`\sviewBox\s*=\s*["']\s*[-0-9.]+[\s,]+[-0-9.]+[\s,]+([0-9.]+)[\s,]+([0-9.]+)\s*["']`)
)

func svgSize(d []byte) (int, int) {
	if len(d) > 1<<16 {
		d = d[:1<<16]
	}
	tag := svgTagRE.Find(d)
	if tag == nil {
		return 0, 0
	}
	num := func(m [][]byte, i int) int {
		if m == nil {
			return 0
		}
		f, _ := strconv.ParseFloat(string(m[i]), 64)
		return int(f + 0.5)
	}
	w, h := num(svgWidthRE.FindSubmatch(tag), 1), num(svgHeightRE.FindSubmatch(tag), 1)
	if w > 0 && h > 0 {
		return w, h
	}
	vb := svgViewBoxRE.FindSubmatch(tag)
	return num(vb, 1), num(vb, 2)
}

// mp4Size walks the ISO BMFF boxes moov → trak → tkhd and returns the first
// track with a picture size (16.16 fixed point at the end of tkhd).
func mp4Size(d []byte, depth int) (int, int) {
	for len(d) >= 8 && depth < 4 {
		size := int(binary.BigEndian.Uint32(d))
		kind := string(d[4:8])
		hdr := 8
		if size == 1 && len(d) >= 16 {
			size, hdr = int(binary.BigEndian.Uint64(d[8:])), 16
		} else if size == 0 {
			size = len(d)
		}
		if size < hdr || size > len(d) {
			return 0, 0
		}
		body := d[hdr:size]
		switch kind {
		case "moov", "trak":
			if w, h := mp4Size(body, depth+1); w > 0 && h > 0 {
				return w, h
			}
		case "tkhd":
			if len(body) >= 8 {
				w := int(binary.BigEndian.Uint32(body[len(body)-8:]) >> 16)
				h := int(binary.BigEndian.Uint32(body[len(body)-4:]) >> 16)
				if w > 0 && h > 0 {
					return w, h
				}
			}
		}
		d = d[size:]
	}
	return 0, 0
}

// EBML element IDs on the way to a WebM picture size.
const (
	ebmlSegment     = 0x18538067
	ebmlTracks      = 0x1654AE6B
	ebmlTrackEntry  = 0xAE
	ebmlVideo       = 0xE0
	ebmlPixelWidth  = 0xB0
	ebmlPixelHeight = 0xBA
	ebmlCluster     = 0x1F43B675
)

// webmSize walks Segment → Tracks → TrackEntry → Video for PixelWidth and
// PixelHeight. It stops at the first Cluster: track headers come first.
func webmSize(d []byte) (int, int) {
	var w, h int
	var walk func(d []byte, depth int) bool
	walk = func(d []byte, depth int) bool {
		for len(d) >= 2 && depth < 6 {
			id, n := ebmlID(d)
			if n == 0 || n >= len(d) {
				return false
			}
			size, m, unknown := ebmlVint(d[n:])
			if m == 0 {
				return false
			}
			start := n + m
			end := start + int(size)
			if unknown || size > uint64(len(d)-start) {
				end = len(d)
			}
			body := d[start:end]
			switch id {
			case ebmlCluster:
				return true
			case ebmlSegment, ebmlTracks, ebmlTrackEntry, ebmlVideo:
				if walk(body, depth+1) {
					return true
				}
			case ebmlPixelWidth:
				w = ebmlUint(body)
			case ebmlPixelHeight:
				h = ebmlUint(body)
			}
			if w > 0 && h > 0 {
				return true
			}
			d = d[end:]
		}
		return false
	}
	walk(d, 0)
	return w, h
}

func ebmlID(d []byte) (uint32, int) {
	n := 1
	for mask := byte(0x80); n <= 4 && d[0]&mask == 0; mask >>= 1 {
		n++
	}
	if n > 4 || n > len(d) {
		return 0, 0
	}
	var id uint32
	for i := 0; i < n; i++ {
		id = id<<8 | uint32(d[i])
	}
	return id, n
}

func ebmlVint(d []byte) (value uint64, n int, unknown bool) {
	if len(d) == 0 {
		return 0, 0, false
	}
	n = 1
	mask := byte(0x80)
	for ; n <= 8 && d[0]&mask == 0; mask >>= 1 {
		n++
	}
	if n > 8 || n > len(d) {
		return 0, 0, false
	}
	value = uint64(d[0] & (mask - 1))
	ones := d[0]&(mask-1) == mask-1
	for i := 1; i < n; i++ {
		value = value<<8 | uint64(d[i])
		ones = ones && d[i] == 0xff
	}
	return value, n, ones
}

func ebmlUint(d []byte) int {
	if len(d) == 0 || len(d) > 4 {
		return 0
	}
	v := 0
	for _, b := range d {
		v = v<<8 | int(b)
	}
	return v
}
