package providers

import (
	"testing"
	"time"

	"github.com/bmizerany/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}
	refreshed, cloudfrontSlice, err := p.RefreshSessionIfNeeded(&SessionState{
		ExpiresOn: time.Now().Add(time.Duration(-11) * time.Minute),
	})
	testCloudfront := []string{""}
	assert.Equal(t, testCloudfront, cloudfrontSlice)
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}
