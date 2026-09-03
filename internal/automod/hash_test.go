package automod

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/image/draw"
)

// gradient genera una imagen con estructura suficiente para que el pHash no sea trivial.
func gradient(w, h int, seed uint8) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r := uint8((x*7 + int(seed)*13) % 256)
			g := uint8((y*5 + x*3 + int(seed)*29) % 256)
			b := uint8(((x ^ y) + int(seed)*41) % 256)
			if (x/16+y/16+int(seed))%3 == 0 {
				r, g, b = 255-r, 255-g, 255-b
			}
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}
	return img
}

func rescale(img image.Image, w, h int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	return dst
}

func writePNG(t *testing.T, path string, img image.Image) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

func TestMatchRescaledImage(t *testing.T) {
	dir := t.TempDir()
	original := gradient(400, 300, 1)
	writePNG(t, filepath.Join(dir, "scam.png"), original)

	list := NewHashList(filepath.Join(dir, "hashes.json"))
	if err := list.LoadSeed(dir); err != nil {
		t.Fatal(err)
	}

	state, name, dist, _ := list.Match(rescale(original, 200, 150))
	if state != HashMatched {
		t.Fatalf("esperaba HashMatched, obtuve %v (dist %d)", state, dist)
	}
	if name != "scam.png" {
		t.Fatalf("esperaba scam.png, obtuve %q", name)
	}
}

func TestUnrelatedImageDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	writePNG(t, filepath.Join(dir, "scam.png"), gradient(400, 300, 1))

	list := NewHashList(filepath.Join(dir, "hashes.json"))
	if err := list.LoadSeed(dir); err != nil {
		t.Fatal(err)
	}

	state, _, dist, _ := list.Match(gradient(400, 300, 200))
	if state == HashMatched {
		t.Fatalf("una imagen sin relación no debería matchear (dist %d)", dist)
	}
}

func TestAddPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hashes.json")

	list := NewHashList(path)
	img := gradient(300, 300, 7)
	hash, err := ComputeHash(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Add(hash, "learned.png", "model"); err != nil {
		t.Fatal(err)
	}
	// Duplicado exacto: no debe crecer la lista
	if err := list.Add(hash, "dup.png", "model"); err != nil {
		t.Fatal(err)
	}
	if list.Len() != 1 {
		t.Fatalf("esperaba 1 entrada, hay %d", list.Len())
	}

	reloaded := NewHashList(path)
	if err := reloaded.LoadLearned(); err != nil {
		t.Fatal(err)
	}
	if reloaded.Len() != 1 {
		t.Fatalf("esperaba 1 entrada tras recargar, hay %d", reloaded.Len())
	}
	state, name, _, _ := reloaded.Match(img)
	if state != HashMatched || name != "learned.png" {
		t.Fatalf("esperaba match con learned.png, obtuve %v %q", state, name)
	}
}

func TestLoadLearnedMissingFileIsNotError(t *testing.T) {
	list := NewHashList(filepath.Join(t.TempDir(), "nope.json"))
	if err := list.LoadLearned(); err != nil {
		t.Fatalf("archivo inexistente no debería ser error: %v", err)
	}
}

func TestEmptyListNoMatch(t *testing.T) {
	list := NewHashList(filepath.Join(t.TempDir(), "hashes.json"))
	state, _, dist, hash := list.Match(gradient(100, 100, 3))
	if state != HashNoMatch || dist != -1 || hash == nil {
		t.Fatalf("lista vacía: esperaba HashNoMatch/-1/hash!=nil, obtuve %v/%d/%v", state, dist, hash)
	}
}
