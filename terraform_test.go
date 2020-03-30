package gitlab

import (
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformService_LockState(t *testing.T) {
	mux, server, client := setup()
	defer teardown(server)

	lockInfo := LockInfo{
		ID:        "id1",
		Operation: "op",
		Info:      "info",
		Who:       "who",
		Version:   "version",
		Created:   time.Now().UTC(),
		Path:      "path",
	}
	mux.HandleFunc("/api/v4/projects/1/terraform/state/test1/lock", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		body := testBodyJSON(t, r, &lockInfo)
		assertMD5HeaderMatchesBody(t, r, body)
	})

	lockData, err := client.Terraform.LockState(1, "test1", &lockInfo)
	require.NoError(t, err)

	assert.Equal(t, lockInfo, lockData.RequestedLockInfo)
	assert.Equal(t, "1", lockData.Project)
	assert.Equal(t, "test1", lockData.StateName)
}

func assertMD5HeaderMatchesBody(t *testing.T, r *http.Request, body []byte) {
	md5Header := r.Header.Get("Content-MD5")
	hash := md5.Sum(body)
	assert.Equal(t, md5Header, base64.StdEncoding.EncodeToString(hash[:]))
}
