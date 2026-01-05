package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

const (
	wsURL      = "wss://api.elections.kalshi.com/trade-api/ws/v2" // Production
	baseURL    = "https://api.elections.kalshi.com"               // Production
	maxMarkets = 5
	pingPeriod = 30 * time.Second
)

// TickerData represents market ticker information
type TickerData struct {
	MarketTicker string  `json:"market_ticker"`
	YesBid       float64 `json:"yes_bid"`
	YesAsk       float64 `json:"yes_ask"`
	NoBid        float64 `json:"no_bid"`
	NoAsk        float64 `json:"no_ask"`
	LastPrice    float64 `json:"last_price"`
	Volume       int     `json:"volume"`
}

// WebSocketMessage represents incoming WebSocket messages
type WebSocketMessage struct {
	Type string      `json:"type"`
	Msg  interface{} `json:"msg"`
	Data *TickerData `json:"data,omitempty"`
	SID  int         `json:"sid,omitempty"`
}

// MarketInfo stores display info for a market
type MarketInfo struct {
	Ticker   string
	Title    string
	YesPrice float64
	NoPrice  float64
	Volume   int
	Updated  time.Time
}

var (
	markets   = make(map[string]*MarketInfo)
	marketsMu sync.RWMutex
)

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 first (Kalshi's default format)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return rsaKey, nil
}

func signMessage(privateKey *rsa.PrivateKey, message string) (string, error) {
	// Hash the message
	hash := sha256.Sum256([]byte(message))

	// Sign using PSS with salt length equal to hash length (32 bytes for SHA256)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: sha256.Size, // 32 bytes - matches PSS.DIGEST_LENGTH in Python
	})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func testRESTAuth(apiKeyID string, privateKey *rsa.PrivateKey) error {
	path := "/trade-api/v2/portfolio/balance"
	method := "GET"

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	message := timestamp + method + path
	signature, err := signMessage(privateKey, message)
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	req, err := http.NewRequest(method, baseURL+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("KALSHI-ACCESS-KEY", apiKeyID)
	req.Header.Set("KALSHI-ACCESS-SIGNATURE", signature)
	req.Header.Set("KALSHI-ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d - authentication failed", resp.StatusCode)
	}

	return nil
}

// Market represents a Kalshi market from REST API
type Market struct {
	Ticker       string  `json:"ticker"`
	Title        string  `json:"title"`
	YesBid       float64 `json:"yes_bid"`
	YesAsk       float64 `json:"yes_ask"`
	NoBid        float64 `json:"no_bid"`
	NoAsk        float64 `json:"no_ask"`
	LastPrice    float64 `json:"last_price"`
	Volume       int     `json:"volume"`
	Volume24h    int     `json:"volume_24h"`
	OpenInterest int     `json:"open_interest"`
	Status       string  `json:"status"`
}

// MarketsResponse represents the API response for markets
type MarketsResponse struct {
	Markets []Market `json:"markets"`
	Cursor  string   `json:"cursor"`
}

// fetchMarkets fetches active markets from the REST API with pagination
func fetchMarkets(apiKeyID string, privateKey *rsa.PrivateKey) error {
	cursor := ""
	totalFetched := 0
	maxPages := 10 // Fetch up to 10 pages of 200 markets each

	for page := 0; page < maxPages; page++ {
		path := "/trade-api/v2/markets"
		method := "GET"

		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		message := timestamp + method + path
		signature, err := signMessage(privateKey, message)
		if err != nil {
			return fmt.Errorf("signing failed: %v", err)
		}

		url := baseURL + path + "?limit=200"
		if cursor != "" {
			url += "&cursor=" + cursor
		}

		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return err
		}

		req.Header.Set("KALSHI-ACCESS-KEY", apiKeyID)
		req.Header.Set("KALSHI-ACCESS-SIGNATURE", signature)
		req.Header.Set("KALSHI-ACCESS-TIMESTAMP", timestamp)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			break
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			break
		}

		var marketsResp MarketsResponse
		if err := json.Unmarshal(body, &marketsResp); err != nil {
			break
		}

		marketsMu.Lock()
		for _, m := range marketsResp.Markets {
			// Only include markets with some activity
			if m.Volume == 0 && m.OpenInterest == 0 {
				continue
			}

			yesPrice := m.YesBid
			noPrice := m.NoBid
			if yesPrice == 0 {
				yesPrice = m.YesAsk
			}
			if noPrice == 0 {
				noPrice = m.NoAsk
			}

			title := m.Title
			if title == "" {
				title = m.Ticker
			}

			markets[m.Ticker] = &MarketInfo{
				Ticker:   m.Ticker,
				Title:    title,
				YesPrice: yesPrice,
				NoPrice:  noPrice,
				Volume:   m.Volume,
				Updated:  time.Now(),
			}
		}
		marketsMu.Unlock()

		totalFetched += len(marketsResp.Markets)
		fmt.Printf("  Fetched page %d (%d markets, %d with activity)\n", page+1, len(marketsResp.Markets), len(markets))

		// Check if there are more pages
		if marketsResp.Cursor == "" || len(marketsResp.Markets) == 0 {
			break
		}
		cursor = marketsResp.Cursor

		// Stop if we have enough active markets
		if len(markets) >= 20 {
			break
		}
	}

	fmt.Printf("✓ Found %d active markets (scanned %d total)\n", len(markets), totalFetched)
	return nil
}

func main() {
	err := godotenv.Load("keys.env")
	if err != nil {
		log.Fatal("failed to load env file:", err)
	}

	apiKeyID := os.Getenv("KALSHI_API_KEY_ID")
	privateKeyPath := os.Getenv("KALSHI_PRIVATE_KEY_PATH")

	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		log.Fatal("failed to load private key:", err)
	}

	// First, test REST API to verify signing works
	fmt.Println("Testing REST API authentication...")
	if err := testRESTAuth(apiKeyID, privateKey); err != nil {
		log.Fatal("REST API test failed:", err)
	}
	fmt.Println("✓ REST API authentication successful!")

	// Fetch initial markets via REST API
	fmt.Println("Fetching active markets...")
	if err := fetchMarkets(apiKeyID, privateKey); err != nil {
		fmt.Printf("Warning: Could not fetch markets: %v\n", err)
	}

	// Display initial markets
	displayMarkets()

	// Now connect to WebSocket
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	method := "GET"
	path := "/trade-api/ws/v2"

	// Sign: timestamp + method + path
	message := timestamp + method + path
	signature, err := signMessage(privateKey, message)
	if err != nil {
		log.Fatal("failed to sign:", err)
	}

	// Set headers
	headers := http.Header{}
	headers.Set("KALSHI-ACCESS-KEY", apiKeyID)
	headers.Set("KALSHI-ACCESS-SIGNATURE", signature)
	headers.Set("KALSHI-ACCESS-TIMESTAMP", timestamp)
	headers.Set("Content-Type", "application/json")

	fmt.Printf("Connecting to WebSocket...\n")

	// Connect with custom dialer for better header handling
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			fmt.Printf("HTTP Status: %s\n", resp.Status)
		}
		log.Fatal("connection failed:", err)
	}
	defer conn.Close()

	fmt.Println("Connected to Kalshi WebSocket!")

	// Start ping ticker to keep connection alive
	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()

	// Start display ticker
	displayTicker := time.NewTicker(2 * time.Second)
	defer displayTicker.Stop()

	// Subscribe to ticker channel
	subscribeMsg := `{
		"id": 1,
		"cmd": "subscribe",
		"params": {
			"channels": ["ticker"]
		}
	}`

	if err := conn.WriteMessage(websocket.TextMessage, []byte(subscribeMsg)); err != nil {
		log.Fatal("subscribe failed:", err)
	}

	// Channel to signal shutdown
	done := make(chan struct{})

	// Goroutine to handle pings and display updates
	go func() {
		for {
			select {
			case <-pingTicker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					log.Println("ping error:", err)
					return
				}
			case <-displayTicker.C:
				displayMarkets()
			case <-done:
				return
			}
		}
	}()

	// Read messages
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			close(done)
			break
		}
		processMessage(msg)
	}
}

func processMessage(msg []byte) {
	var wsMsg WebSocketMessage
	if err := json.Unmarshal(msg, &wsMsg); err != nil {
		return
	}

	switch wsMsg.Type {
	case "ticker":
		if wsMsg.Data != nil {
			updateMarket(wsMsg.Data)
		}
	case "subscribed":
		fmt.Printf("✓ Subscribed successfully (sid: %d)\n", wsMsg.SID)
	case "error":
		fmt.Printf("⚠ Error: %v\n", wsMsg.Msg)
	}
}

func updateMarket(data *TickerData) {
	marketsMu.Lock()
	defer marketsMu.Unlock()

	yesPrice := data.YesBid
	noPrice := data.NoBid

	// If bid is 0, use ask
	if yesPrice == 0 {
		yesPrice = data.YesAsk
	}
	if noPrice == 0 {
		noPrice = data.NoAsk
	}

	// Update existing market or create new one
	if existing, ok := markets[data.MarketTicker]; ok {
		existing.YesPrice = yesPrice
		existing.NoPrice = noPrice
		existing.Volume = data.Volume
		existing.Updated = time.Now()
	} else {
		markets[data.MarketTicker] = &MarketInfo{
			Ticker:   data.MarketTicker,
			Title:    data.MarketTicker, // WebSocket doesn't provide title
			YesPrice: yesPrice,
			NoPrice:  noPrice,
			Volume:   data.Volume,
			Updated:  time.Now(),
		}
	}
}

func displayMarkets() {
	marketsMu.RLock()
	defer marketsMu.RUnlock()

	if len(markets) == 0 {
		fmt.Println("No markets loaded yet...")
		return
	}

	// Convert map to slice for sorting
	marketList := make([]*MarketInfo, 0, len(markets))
	for _, info := range markets {
		marketList = append(marketList, info)
	}

	// Sort by volume (highest first)
	sort.Slice(marketList, func(i, j int) bool {
		return marketList[i].Volume > marketList[j].Volume
	})

	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")
	fmt.Println("════════════════════════════════════════════════════════════════════════════")
	fmt.Println("                           KALSHI LIVE MARKETS")
	fmt.Printf("                           %s\n", time.Now().Format("15:04:05"))
	fmt.Println("════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("%-50s │ %7s │ %7s │ %8s\n", "MARKET", "YES ¢", "NO ¢", "VOLUME")
	fmt.Println("────────────────────────────────────────────────────────────────────────────")

	count := 0
	for _, info := range marketList {
		if count >= maxMarkets {
			break
		}

		title := info.Title
		if len(title) > 48 {
			title = title[:48] + ".."
		}

		fmt.Printf("%-50s │ %7.0f │ %7.0f │ %8d\n", title, info.YesPrice, info.NoPrice, info.Volume)
		count++
	}

	fmt.Println("────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("Tracking %d markets (showing top %d by volume)\n", len(markets), min(len(markets), maxMarkets))
	fmt.Println("Press Ctrl+C to exit")
}
