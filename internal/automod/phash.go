package automod

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corona10/goimagehash"
	"github.com/revrost/go-openrouter"
)

type ScamImage struct {
	Name  string
	PHash *goimagehash.ImageHash
	DHash *goimagehash.ImageHash
	AHash *goimagehash.ImageHash
}

type PhashScanner struct {
	scamHashes []ScamImage
	mu         sync.RWMutex
}

func NewPhashScanner() *PhashScanner {
	return &PhashScanner{
		scamHashes: []ScamImage{},
	}
}

func (s *PhashScanner) LoadScamImages(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded []ScamImage
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			fmt.Printf("Error abriendo %s: %v\n", path, err)
			continue
		}

		img, _, err := image.Decode(file)
		file.Close()
		if err != nil {
			fmt.Printf("Error decodificando %s: %v\n", path, err)
			continue
		}

		phash, _ := goimagehash.PerceptionHash(img)
		dhash, _ := goimagehash.DifferenceHash(img)
		ahash, _ := goimagehash.AverageHash(img)

		loaded = append(loaded, ScamImage{
			Name:  entry.Name(),
			PHash: phash,
			DHash: dhash,
			AHash: ahash,
		})
	}

	s.mu.Lock()
	s.scamHashes = loaded
	s.mu.Unlock()

	fmt.Printf("Cargadas %d imágenes de scam (Triple Hash)\n", len(loaded))
	return nil
}

// CompareResult contiene los detalles de la comparación
type CompareResult struct {
	Match    bool
	Name     string
	PDist    int
	DDist    int
	ADist    int
	AvgDist  int
	CropJPEG []byte // Fragmento central en JPEG
}

func (s *PhashScanner) Compare(img image.Image) CompareResult {
	phash, err := goimagehash.PerceptionHash(img)
	if err != nil {
		return CompareResult{Match: false}
	}
	dhash, _ := goimagehash.DifferenceHash(img)
	ahash, _ := goimagehash.AverageHash(img)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, scam := range s.scamHashes {
		pDist, _ := phash.Distance(scam.PHash)
		dDist, _ := dhash.Distance(scam.DHash)
		aDist, _ := ahash.Distance(scam.AHash)

		avgDist := (pDist + dDist + aDist) / 3

		// Threshold aumentado y lógica de match
		if (pDist <= 18 && dDist <= 18) || avgDist <= 18 {

			// Generar fragmento central
			bounds := img.Bounds()
			width := bounds.Dx()
			height := bounds.Dy()

			// Tomar un cuadrado central del 65% del tamaño menor
			cropSize := width
			if height < width {
				cropSize = height
			}
			cropSize = int(float64(cropSize) * 0.65)
			if cropSize < 100 {
				cropSize = width
			} // fallback si es muy pequeña

			startX := bounds.Min.X + (width-cropSize)/2
			startY := bounds.Min.Y + (height-cropSize)/2

			cropRect := image.Rect(0, 0, cropSize, cropSize)
			cropped := image.NewRGBA(cropRect)
			draw.Draw(cropped, cropRect, img, image.Point{startX, startY}, draw.Src)

			var buf bytes.Buffer
			jpeg.Encode(&buf, cropped, &jpeg.Options{Quality: 75})

			return CompareResult{
				Match:    true,
				Name:     scam.Name,
				PDist:    pDist,
				DDist:    dDist,
				ADist:    aDist,
				AvgDist:  avgDist,
				CropJPEG: buf.Bytes(),
			}
		}
	}

	return CompareResult{Match: false}
}

func DownloadImage(url string) (image.Image, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Falla descargando imagen: %s", resp.Status)
	}

	img, _, err := image.Decode(resp.Body)
	if err != nil {
		return nil, err
	}

	return img, nil
}

func CheckNSFW(imageURL string) (bool, error) {

	ext := strings.ToLower(filepath.Ext(imageURL))
	if ext == ".avif" || ext == ".gif" {
		fmt.Println("Imagen ignorada por ser AVIF o GIF:", imageURL)
		return false, nil
	}

	ctx := context.Background()
	client := openrouter.NewClient(os.Getenv("OPENROUTER_API_KEY"))

	type ImageClassification struct {
		Classification string `json:"classification"`
		Confidence     int    `json:"confidence"`
	}

	example := ImageClassification{
		Classification: "SAFE",
		Confidence:     100,
	}
	exampleJSON, _ := json.Marshal(example)

	models := []string{
		"allenai/molmo-2-8b:free",
		"google/gemma-3-27b-it:free",
	}

	for _, modelName := range models {
		request := openrouter.ChatCompletionRequest{
			Model: modelName,
			Messages: []openrouter.ChatCompletionMessage{
				{
					Role: openrouter.ChatMessageRoleSystem,
					Content: openrouter.Content{
						Text: "Ejemplo de respuesta: " + string(exampleJSON),
					},
				},
				{
					Role: openrouter.ChatMessageRoleUser,
					Content: openrouter.Content{
						Multi: []openrouter.ChatMessagePart{
							{
								Type: openrouter.ChatMessagePartTypeText,
								Text: "Clasifica esta imagen como SAFE o NSFW. NSFW incluye contenido sexual explícito o pornográfico, sangre, gore, etc.",
							},
							{
								Type: openrouter.ChatMessagePartTypeImageURL,
								ImageURL: &openrouter.ChatMessageImageURL{
									URL: imageURL,
								},
							},
						},
					},
				},
			},
			ResponseFormat: &openrouter.ChatCompletionResponseFormat{
				Type: openrouter.ChatCompletionResponseFormatTypeJSONObject,
			},
		}

		res, err := client.CreateChatCompletion(ctx, request)
		if err != nil {
			fmt.Printf("Error clasificando con %s: %v. Probando siguiente...\n", modelName, err)
			continue
		}

		if len(res.Choices) > 0 {
			choice := res.Choices[0]
			if choice.Message.Content.Text == "" {
				fmt.Printf("Respuesta vacía de %s. Probando siguiente...\n", modelName)
				continue
			}

			var classification ImageClassification
			if err := json.Unmarshal([]byte(choice.Message.Content.Text), &classification); err != nil {
				fmt.Printf("Error parsing JSON de %s: %v. Probando siguiente...\n", modelName, err)
				continue
			}

			fmt.Printf("Modelo: %s | Clasificación: %s, Confianza: %d%%\n", modelName, classification.Classification, classification.Confidence)
			return classification.Classification == "NSFW", nil
		}
	}

	return false, fmt.Errorf("no se pudo clasificar la imagen con ningún modelo disponible")
}
