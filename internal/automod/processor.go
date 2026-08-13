package automod

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

type ScamImage struct {
	Name      string
	Embedding []float32
}

type ImageScanner interface {
	Compare(img image.Image) (bool, string, float32, []byte)
	LoadScamImages(dir string) error
	Close()
}

type CLIPScanner struct {
	scamImages []ScamImage
	mu         sync.RWMutex

	session *AdvancedSessionWrapper
}

type AdvancedSessionWrapper struct {
	session      *ort.AdvancedSession
	inputTensor  *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
	mu           sync.Mutex
}

func SessionWrapper() *AdvancedSessionWrapper {
	inputData := make([]float32, 3*224*224)
	session, inputTensor, outputTensor := createCLIPSession(inputData)

	return &AdvancedSessionWrapper{
		session:      session,
		inputTensor:  inputTensor,
		outputTensor: outputTensor,
	}
}

func (s *AdvancedSessionWrapper) Run(img image.Image) []float32 {
	data := preprocess(img)
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	copy(s.inputTensor.GetData(), data)

	if err := s.session.Run(); err != nil {
		panic(err)
	}

	embedding := s.outputTensor.GetData()
	out := make([]float32, len(embedding))
	copy(out, embedding)
	normalize(out)
	return out
}

func (s *AdvancedSessionWrapper) Close() {
	s.session.Destroy()
	s.inputTensor.Destroy()
	s.outputTensor.Destroy()
}

func CLIPScan() *CLIPScanner {
	return &CLIPScanner{
		scamImages: []ScamImage{},
		session:    SessionWrapper(),
	}
}

func (c *CLIPScanner) Close() {
	c.session.Close()
}

func (c *CLIPScanner) LoadScamImages(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var loaded []ScamImage
	sem := make(chan struct{}, runtime.NumCPU())

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(entry os.DirEntry) {
			defer wg.Done()
			defer func() { <-sem }()

			path := filepath.Join(dir, entry.Name())
			img, err := loadImage(path)
			if err != nil {
				fmt.Printf("Error cargando %s: %v\n", path, err)
				return
			}

			emb := c.session.Run(img)
			img = nil

			mu.Lock()
			loaded = append(loaded, ScamImage{
				Name:      entry.Name(),
				Embedding: emb,
			})
			mu.Unlock()
		}(entry)
	}

	wg.Wait()

	c.mu.Lock()
	c.scamImages = loaded
	c.mu.Unlock()

	fmt.Printf("Cargadas %d imágenes de scam (CLIP)\n", len(loaded))
	return nil
}

func (c *CLIPScanner) Compare(img image.Image) (bool, string, float32, []byte) {
	emb := c.session.Run(img)

	c.mu.RLock()
	defer c.mu.RUnlock()

	var bestScore float32
	var bestName string
	var bestImg image.Image

	for _, scam := range c.scamImages {
		score := cosineSimilarity(emb, scam.Embedding)
		if score > bestScore {
			bestScore = score
			bestName = scam.Name
			bestImg = img
		}
	}

	if bestScore > 0.95 {
		// generar crop central
		bounds := bestImg.Bounds()
		w, h := bounds.Dx(), bounds.Dy()
		cropSize := int(float64(min(w, h)) * 0.65)
		if cropSize < 100 {
			cropSize = min(w, h)
		}

		startX := bounds.Min.X + (w-cropSize)/2
		startY := bounds.Min.Y + (h-cropSize)/2
		cropRect := image.Rect(0, 0, cropSize, cropSize)
		cropped := image.NewRGBA(cropRect)
		draw.Draw(cropped, cropRect, bestImg, image.Point{startX, startY}, draw.Src)

		var buf bytes.Buffer
		jpeg.Encode(&buf, cropped, &jpeg.Options{Quality: 75})

		return true, bestName, bestScore, buf.Bytes()
	}

	return false, "", bestScore, nil
}

const nsfwModelPath = "models/vit_nsfw.onnx"

type NSFWDetector struct {
	session      *ort.AdvancedSession
	inputTensor  *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
	mu           sync.Mutex
}

func NewNSFWDetector() (*NSFWDetector, error) {
	inputData := make([]float32, 3*384*384)
	session, inputTensor, outputTensor, err := createNSFWSession(inputData)
	if err != nil {
		return nil, err
	}
	return &NSFWDetector{
		session:      session,
		inputTensor:  inputTensor,
		outputTensor: outputTensor,
	}, nil
}

func (d *NSFWDetector) Close() {
	d.session.Destroy()
	d.inputTensor.Destroy()
	d.outputTensor.Destroy()
}

func (d *NSFWDetector) Classify(img image.Image) (bool, float32, error) {
	data := preprocessNSFW(img)

	d.mu.Lock()
	defer d.mu.Unlock()

	copy(d.inputTensor.GetData(), data)
	if err := d.session.Run(); err != nil {
		return false, 0, err
	}

	logits := d.outputTensor.GetData()
	// Softmax sobre las 2 clases: 0=sfw, 1=nsfw
	max := logits[0]
	if logits[1] > max {
		max = logits[1]
	}
	e0 := float32(math.Exp(float64(logits[0] - max)))
	e1 := float32(math.Exp(float64(logits[1] - max)))
	nsfwScore := e1 / (e0 + e1)

	return nsfwScore >= 0.5, nsfwScore, nil
}

func createNSFWSession(imageData []float32) (*ort.AdvancedSession, *ort.Tensor[float32], *ort.Tensor[float32], error) {
	inputShape := ort.NewShape(1, 3, 384, 384)
	outputShape := ort.NewShape(1, 2)

	inputTensor, err := ort.NewTensor(inputShape, imageData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creando tensor input NSFW: %w", err)
	}

	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		inputTensor.Destroy()
		return nil, nil, nil, fmt.Errorf("creando tensor output NSFW: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		nsfwModelPath,
		[]string{"pixel_values"},
		[]string{"logits"},
		[]ort.Value{inputTensor},
		[]ort.Value{outputTensor},
		nil,
	)
	if err != nil {
		inputTensor.Destroy()
		outputTensor.Destroy()
		return nil, nil, nil, fmt.Errorf("creando sesión NSFW: %w", err)
	}

	return session, inputTensor, outputTensor, nil
}

func preprocessNSFW(img image.Image) []float32 {
	img = resizeImage(img, 384, 384)

	data := make([]float32, 3*384*384)
	for y := 0; y < 384; y++ {
		for x := 0; x < 384; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			rf := float32(r>>8)/255/0.5 - 1
			gf := float32(g>>8)/255/0.5 - 1
			bf := float32(b>>8)/255/0.5 - 1

			idx := y*384 + x
			data[idx] = rf
			data[384*384+idx] = gf
			data[2*384*384+idx] = bf
		}
	}
	return data
}

func preprocess(img image.Image) []float32 {
	img = resizeImage(img, 224, 224)

	data := make([]float32, 3*224*224)

	mean := []float32{0.485, 0.456, 0.406}
	std := []float32{0.229, 0.224, 0.225}

	for y := 0; y < 224; y++ {
		for x := 0; x < 224; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			rf := float32(r>>8) / 255
			gf := float32(g>>8) / 255
			bf := float32(b>>8) / 255

			rf = (rf - mean[0]) / std[0]
			gf = (gf - mean[1]) / std[1]
			bf = (bf - mean[2]) / std[2]

			idx := y*224 + x
			data[idx] = rf
			data[224*224+idx] = gf
			data[2*224*224+idx] = bf
		}
	}
	return data
}

func createCLIPSession(imageData []float32) (
	*ort.AdvancedSession,
	*ort.Tensor[float32],
	*ort.Tensor[float32],
) {
	inputShape := ort.NewShape(1, 3, 224, 224)
	outputShape := ort.NewShape(1, 1000)

	inputTensor, err := ort.NewTensor(inputShape, imageData)
	if err != nil {
		panic(fmt.Errorf("failed to create input tensor: %w", err))
	}

	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		panic(fmt.Errorf("failed to create output tensor: %w", err))
	}

	session, err := ort.NewAdvancedSession(
		"models/efficientnet_lite0_Opset17.onnx",
		[]string{"x"},
		[]string{"505"},
		[]ort.Value{inputTensor},
		[]ort.Value{outputTensor},
		nil,
	)

	if err != nil {
		panic(err)
	}

	return session, inputTensor, outputTensor
}

func normalize(v []float32) {
	var sum float32
	for _, x := range v {
		sum += x * x
	}
	norm := float32(math.Sqrt(float64(sum)))
	for i := range v {
		v[i] /= norm
	}
}

func cosineSimilarity(a, b []float32) float32 {
	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

func GetSharedLibPath() string {
	exePath, err := os.Executable()
	if err != nil {
		panic(fmt.Errorf("no se pudo obtener path del ejecutable: %w", err))
	}

	exeDir := filepath.Dir(exePath)

	var libName string
	if runtime.GOOS == "windows" {
		libName = "onnxruntime.dll"
	} else {
		libName = "libonnxruntime.so"
	}

	libPath := filepath.Join(exeDir, "runtime", libName)
	return libPath
}
