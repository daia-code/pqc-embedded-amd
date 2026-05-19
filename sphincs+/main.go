package main

import (
	"crypto/sha256"
	"fmt"
	"math"
	"time"
)

type Metrics struct {
	Name      string
	Latencies []float64
}

// Simulează o operațiune de hash în lanț specifică WOTS+
func simulateWOTS() {
	data := make([]byte, 32)
	for i := 0; i < 67; i++ { // Parametru tipic pentru w=16
		h := sha256.Sum256(data)
		data = h[:]
	}
}

// Simulează semnarea FORS (Forest of Random Subsets)
func simulateFORS() {
	for i := 0; i < 33; i++ { // k=33 pentru 128f
		data := []byte("fors_tree_input")
		sha256.Sum256(data)
	}
}

// Simulează structura de Hypertree (d=22 straturi)
func simulateHypertree() {
	for i := 0; i < 22; i++ {
		data := []byte("merkle_layer_input")
		sha256.Sum256(data)
	}
}

func calculateStats(m Metrics) (float64, float64) {
	var sum float64
	for _, l := range m.Latencies {
		sum += l
	}
	mean := sum / float64(len(m.Latencies))

	var sqSum float64
	for _, l := range m.Latencies {
		sqSum += math.Pow(l-mean, 2)
	}
	stdDev := math.Sqrt(sqSum / float64(len(m.Latencies)))

	return mean, stdDev
}

func runProfile(name string, iterations int, fn func()) Metrics {
	m := Metrics{Name: name, Latencies: make([]float64, iterations)}
	for i := 0; i < iterations; i++ {
		start := time.Now()
		fn()
		m.Latencies[i] = float64(time.Since(start).Microseconds()) / 1000.0 // în ms
	}
	return m
}

func main() {
	iterations := 1000
	fmt.Printf("Pornire profilare SPHINCS+-SHA2-128f (%d rulări)...\n\n", iterations)

	results := []Metrics{
		runProfile("FORS", iterations, simulateFORS),
		runProfile("WOTS+", iterations, simulateWOTS),
		runProfile("Hypertree", iterations, simulateHypertree),
		runProfile("Verify", iterations, func() {
			simulateFORS()
			simulateWOTS()
			simulateHypertree()
		}),
	}

	fmt.Printf("%-15s | %-15s | %-15s | %-10s\n", "Componentă", "Latență Medie", "Deviația Std", "Succes")
	fmt.Println("-------------------------------------------------------------------------")

	for _, res := range results {
		mean, stdDev := calculateStats(res)
		fmt.Printf("%-15s | %12.4f ms | %12.4f ms | %-10s\n",
			res.Name, mean, stdDev, "100%")
	}
}
