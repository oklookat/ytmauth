package ytmauth

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func TestNew(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		t.Fatalf("load env: %s", err.Error())
	}

	token, err := New(context.Background(), func(url, code string) {
		fmt.Printf("go to %s and type %s", url, code)
	})

	if err != nil {
		t.Fatalf("new: %s", err.Error())
	}

	if len(token.AccessToken) == 0 ||
		len(token.TokenType) == 0 ||
		len(token.RefreshToken) == 0 || token.Expiry.Unix() == 0 {
		t.Fatalf("invalid token")
	}
}

func TestRefresh(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		t.Fatalf("load env: %s", err.Error())
	}

	//access := os.Getenv("ACCESS_TOKEN")
	refresh := os.Getenv("REFRESH_TOKEN")

	refreshed, err := Refresh(context.Background(), refresh)
	if err != nil {
		t.Fatalf(err.Error())
	}
	fmt.Printf("%s", refreshed.TokenType)
}
