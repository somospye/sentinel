package automod

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"os"

	_ "golang.org/x/image/webp"

	"golang.org/x/image/draw"
)

func resizeImage(img image.Image, width, height int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	return dst
}

func loadImage(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("No se pudo abrir %s: %w", path, err)
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("No se pudo decodificar %s: %w", path, err)
	}

	return img, nil
}

func centerCrop(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	cropSize := int(float64(min(w, h)) * 0.65)
	if cropSize < 100 {
		cropSize = min(w, h)
	}
	startX := bounds.Min.X + (w-cropSize)/2
	startY := bounds.Min.Y + (h-cropSize)/2
	cropRect := image.Rect(0, 0, cropSize, cropSize)
	cropped := image.NewRGBA(cropRect)
	draw.Draw(cropped, cropRect, img, image.Point{startX, startY}, draw.Src)
	return cropped
}

func pixelate(img image.Image, blockSize int) image.Image {
	bounds := img.Bounds()
	smallW := bounds.Dx() / blockSize
	smallH := bounds.Dy() / blockSize
	if smallW < 1 {
		smallW = 1
	}
	if smallH < 1 {
		smallH = 1
	}
	small := image.NewRGBA(image.Rect(0, 0, smallW, smallH))
	draw.NearestNeighbor.Scale(small, small.Bounds(), img, bounds, draw.Over, nil)
	dst := image.NewRGBA(bounds)
	draw.NearestNeighbor.Scale(dst, bounds, small, small.Bounds(), draw.Over, nil)
	return dst
}

var DownloadImage = defaultDownloadImage

func defaultDownloadImage(url string) (image.Image, error) {
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
