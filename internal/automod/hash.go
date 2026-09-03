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

// Umbrales de distancia de Hamming sobre pHash de 64 bits.
//
// Dos imágenes sin relación tienen una distancia ~Binomial(64, 0.5): media 32,
// desviación ~4. Con <= 10 estamos hablando de la misma imagen recomprimida,
// reescalada o con ajustes menores. Entre 11 y 20 es "se parece pero no es
// idéntica" (mismo layout con otro texto/logo, recorte, marca de agua), y ahí
// dejamos que el modelo decida. Por encima de 20 ni siquiera se corre el modelo.
const (
	HashMatchThreshold = 10
	HashGrayThreshold  = 20
)

type HashMatch int

const (
	HashNoMatch HashMatch = iota
	HashGray
	HashMatched
)

type HashEntry struct {
	Hash    string    `json:"hash"`
	Name    string    `json:"name"`
	Source  string    `json:"source"` // seed | manual | model
	AddedAt time.Time `json:"added_at"`

	parsed *goimagehash.ImageHash
}

// HashList mantiene los pHash de las imágenes de scam conocidas.
// Las entradas "seed" se calculan al arrancar desde assets/scam; las
// aprendidas (manual/model) se persisten en un JSON aparte para que
// sobrevivan reinicios sin tener que guardar la imagen completa.
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

// LoadSeed calcula el pHash de cada imagen del directorio y lo agrega como "seed".
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
		hash, err := ComputeHash(img)
		if err != nil {
			fmt.Printf("Error calculando pHash de %s: %v\n", path, err)
			continue
		}
		loaded = append(loaded, HashEntry{
			Hash:    hash.ToString(),
			Name:    entry.Name(),
			Source:  "seed",
			AddedAt: time.Now(),
			parsed:  hash,
		})
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
		parsed, err := goimagehash.ImageHashFromString(e.Hash)
		if err != nil {
			fmt.Printf("pHash inválido en %s (%s): %v\n", h.path, e.Name, err)
			continue
		}
		e.parsed = parsed
		valid = append(valid, e)
	}

	h.mu.Lock()
	h.entries = append(h.entries, valid...)
	h.mu.Unlock()

	fmt.Printf("Cargados %d pHash aprendidos desde %s\n", len(valid), h.path)
	return nil
}

// Match devuelve el estado según la entrada más cercana, su nombre y la distancia.
// El hash calculado se devuelve para que el caller pueda agregarlo si el fallback confirma.
func (h *HashList) Match(img image.Image) (HashMatch, string, int, *goimagehash.ImageHash) {
	hash, err := ComputeHash(img)
	if err != nil {
		return HashNoMatch, "", -1, nil
	}

	name, dist := h.closest(hash)
	switch {
	case dist < 0:
		return HashNoMatch, "", dist, hash
	case dist <= HashMatchThreshold:
		return HashMatched, name, dist, hash
	case dist <= HashGrayThreshold:
		return HashGray, name, dist, hash
	default:
		return HashNoMatch, name, dist, hash
	}
}

func (h *HashList) closest(hash *goimagehash.ImageHash) (string, int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	bestName, bestDist := "", -1
	for _, e := range h.entries {
		d, err := hash.Distance(e.parsed)
		if err != nil {
			continue
		}
		if bestDist < 0 || d < bestDist {
			bestName, bestDist = e.Name, d
		}
	}
	return bestName, bestDist
}

// Add agrega el hash a la lista y lo persiste. Si ya hay una entrada dentro del
// umbral de match no se duplica.
func (h *HashList) Add(hash *goimagehash.ImageHash, name, source string) error {
	if _, dist := h.closest(hash); dist >= 0 && dist <= HashMatchThreshold {
		return nil
	}

	h.mu.Lock()
	h.entries = append(h.entries, HashEntry{
		Hash:    hash.ToString(),
		Name:    name,
		Source:  source,
		AddedAt: time.Now(),
		parsed:  hash,
	})
	h.mu.Unlock()

	return h.save()
}

// AddFile calcula el pHash de una imagen en disco y la agrega.
func (h *HashList) AddFile(path, source string) error {
	img, err := loadImage(path)
	if err != nil {
		return err
	}
	hash, err := ComputeHash(img)
	if err != nil {
		return err
	}
	return h.Add(hash, filepath.Base(path), source)
}

func (h *HashList) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// save persiste solo las entradas aprendidas; las seed se recalculan al arrancar.
func (h *HashList) save() error {
	h.mu.RLock()
	learned := make([]HashEntry, 0, len(h.entries))
	for _, e := range h.entries {
		if e.Source != "seed" {
			learned = append(learned, e)
		}
	}
	h.mu.RUnlock()

	data, err := json.MarshalIndent(learned, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(h.path, data, 0644)
}
