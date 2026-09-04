package automod

import (
	"encoding/json"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/corona10/goimagehash"
)

// Umbral de distancia de Hamming sobre pHash de 64 bits.
//
// Dos imágenes sin relación tienen una distancia ~Binomial(64, 0.5): media 32,
// desviación ~4. Con <= 10 estamos hablando de la misma imagen recomprimida,
// reescalada o con ajustes menores. El hash solo decide el caso positivo: si no
// hay match, la imagen sigue al modelo como hasta ahora.
const HashMatchThreshold = 10

// Lado máximo de la copia reducida sobre la que se calculan las variantes
// geométricas. El hash de la imagen original se calcula a tamaño completo.
const variantSide = 256

type HashEntry struct {
	Hashes  []string  `json:"hashes"`
	Name    string    `json:"name"`
	Source  string    `json:"source"` // seed | manual | model
	AddedAt time.Time `json:"added_at"`

	parsed []*goimagehash.ImageHash
}

// HashList mantiene los pHash de las imágenes de scam conocidas.
// Cada entrada guarda el hash de la imagen y de sus 7 transformaciones del grupo
// diedral (espejos y rotaciones de 90°), de modo que espejar o rotar el scam no
// sirva para esquivar el nivel 1. La imagen entrante solo calcula un hash.
//
// Las entradas "seed" se calculan al arrancar desde assets/scam; las aprendidas
// (manual/model) se persisten en un JSON aparte para sobrevivir reinicios sin
// guardar la imagen completa.
type HashList struct {
	entries []HashEntry
	mu      sync.RWMutex
	path    string
}

func NewHashList(path string) *HashList {
	return &HashList{path: path}
}

func ComputeHash(img image.Image) (*goimagehash.ImageHash, error) {
	return goimagehash.PerceptionHash(img)
}

// remap construye una imagen de w×h tomando cada píxel de src según fn.
func remap(src image.Image, w, h int, fn func(x, y int) (int, int)) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx, sy := fn(x, y)
			dst.Set(x, y, src.At(b.Min.X+sx, b.Min.Y+sy))
		}
	}
	return dst
}

// dihedralVariants devuelve las 7 transformaciones no triviales del grupo diedral D4.
func dihedralVariants(img image.Image) []image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	return []image.Image{
		remap(img, w, h, func(x, y int) (int, int) { return w - 1 - x, y }),         // espejo horizontal
		remap(img, w, h, func(x, y int) (int, int) { return x, h - 1 - y }),         // espejo vertical
		remap(img, w, h, func(x, y int) (int, int) { return w - 1 - x, h - 1 - y }), // rotación 180°
		remap(img, h, w, func(x, y int) (int, int) { return y, h - 1 - x }),         // rotación 90°
		remap(img, h, w, func(x, y int) (int, int) { return w - 1 - y, x }),         // rotación 270°
		remap(img, h, w, func(x, y int) (int, int) { return y, x }),                 // transpuesta
		remap(img, h, w, func(x, y int) (int, int) { return w - 1 - y, h - 1 - x }), // antitranspuesta
	}
}

// computeAllHashes calcula el pHash de la imagen a tamaño completo más el de sus
// variantes geométricas sobre una copia reducida.
func computeAllHashes(img image.Image) ([]*goimagehash.ImageHash, error) {
	base, err := ComputeHash(img)
	if err != nil {
		return nil, err
	}
	hashes := []*goimagehash.ImageHash{base}

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > variantSide || h > variantSide {
		if w >= h {
			h = max(1, h*variantSide/w)
			w = variantSide
		} else {
			w = max(1, w*variantSide/h)
			h = variantSide
		}
		img = resizeImage(img, w, h)
	}

	for _, v := range dihedralVariants(img) {
		hv, err := ComputeHash(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hv)
	}
	return hashes, nil
}

func newEntry(img image.Image, name, source string) (HashEntry, error) {
	hashes, err := computeAllHashes(img)
	if err != nil {
		return HashEntry{}, err
	}
	strs := make([]string, len(hashes))
	for i, h := range hashes {
		strs[i] = h.ToString()
	}
	return HashEntry{
		Hashes:  strs,
		Name:    name,
		Source:  source,
		AddedAt: time.Now(),
		parsed:  hashes,
	}, nil
}

// LoadSeed calcula los pHash de cada imagen del directorio y los agrega como "seed".
func (h *HashList) LoadSeed(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var loaded []HashEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		img, err := loadImage(path)
		if err != nil {
			fmt.Printf("Error cargando %s para pHash: %v\n", path, err)
			continue
		}
		e, err := newEntry(img, entry.Name(), "seed")
		if err != nil {
			fmt.Printf("Error calculando pHash de %s: %v\n", path, err)
			continue
		}
		loaded = append(loaded, e)
	}

	h.mu.Lock()
	h.entries = append(h.entries, loaded...)
	h.mu.Unlock()

	fmt.Printf("Cargados %d pHash de imágenes de scam (seed)\n", len(loaded))
	return nil
}

// LoadLearned carga las entradas persistidas (manual/model). Si el archivo no existe no es error.
func (h *HashList) LoadLearned() error {
	data, err := os.ReadFile(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded []HashEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	valid := make([]HashEntry, 0, len(loaded))
	for _, e := range loaded {
		for _, s := range e.Hashes {
			parsed, err := goimagehash.ImageHashFromString(s)
			if err != nil {
				fmt.Printf("pHash inválido en %s (%s): %v\n", h.path, e.Name, err)
				continue
			}
			e.parsed = append(e.parsed, parsed)
		}
		if len(e.parsed) > 0 {
			valid = append(valid, e)
		}
	}

	h.mu.Lock()
	h.entries = append(h.entries, valid...)
	h.mu.Unlock()

	fmt.Printf("Cargados %d pHash aprendidos desde %s\n", len(valid), h.path)
	return nil
}

// Match devuelve si la imagen está dentro del umbral de alguna entrada, el nombre
// de la entrada más cercana y la distancia (-1 si la lista está vacía).
func (h *HashList) Match(img image.Image) (bool, string, int) {
	hash, err := ComputeHash(img)
	if err != nil {
		return false, "", -1
	}
	name, dist := h.closest(hash)
	return dist >= 0 && dist <= HashMatchThreshold, name, dist
}

func (h *HashList) closest(hash *goimagehash.ImageHash) (string, int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	bestName, bestDist := "", -1
	for _, e := range h.entries {
		for _, p := range e.parsed {
			d, err := hash.Distance(p)
			if err != nil {
				continue
			}
			if bestDist < 0 || d < bestDist {
				bestName, bestDist = e.Name, d
			}
		}
	}
	return bestName, bestDist
}

// Add calcula los hashes de la imagen, la agrega a la lista y persiste. Si ya hay
// una entrada dentro del umbral de match no se duplica.
func (h *HashList) Add(img image.Image, name, source string) error {
	e, err := newEntry(img, name, source)
	if err != nil {
		return err
	}
	if _, dist := h.closest(e.parsed[0]); dist >= 0 && dist <= HashMatchThreshold {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e)
	return h.save()
}

// AddFile carga una imagen de disco y la agrega.
func (h *HashList) AddFile(path, source string) error {
	img, err := loadImage(path)
	if err != nil {
		return err
	}
	return h.Add(img, filepath.Base(path), source)
}

func (h *HashList) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// save persiste solo las entradas aprendidas; las seed se recalculan al arrancar.
// Debe llamarse con h.mu tomado en escritura.
func (h *HashList) save() error {
	learned := make([]HashEntry, 0, len(h.entries))
	for _, e := range h.entries {
		if e.Source != "seed" {
			learned = append(learned, e)
		}
	}

	data, err := json.MarshalIndent(learned, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(h.path, data, 0644)
}
