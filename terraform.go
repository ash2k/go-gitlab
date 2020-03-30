package gitlab

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// LockInfo stores lock metadata.
//
// Only Operation and Info are required to be set by the caller of LockState.
type LockInfo struct {
	// Unique ID for the lock. This may be overridden by the lock implementation.
	// The final value of ID will be returned by the call to LockState.
	ID string `json:"ID"`

	// Terraform operation, provided by the caller.
	Operation string `json:"Operation"`

	// Extra information to store with the lock, provided by the caller.
	Info string `json:"Info"`

	// user@hostname when available
	Who string `json:"Who"`

	// Terraform version
	Version string `json:"Version"`

	// Time that the lock was taken.
	Created time.Time `json:"Created"`

	// Path to the state file when applicable.
	Path string `json:"Path"`
}

type LockData struct {
	Project           string
	StateName         string
	RequestedLockInfo LockInfo
}

// Payload is the return value from the remote state storage.
type Payload struct {
	MD5  []byte
	Data []byte
}

// TerraformService handles communication with the Terraform backend
// related methods of the GitLab API.
//
// GitLab API docs: TODO
type TerraformService struct {
	client *Client
}

func (c *TerraformService) newRequestWithMD5(method, path string, body []byte, options []OptionFunc) (*retryablehttp.Request, error) {
	req, err := c.client.NewRequest(method, path, body, options)
	if err != nil {
		return nil, err
	}
	hash := md5.Sum(body)
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	req.Header.Set("Content-MD5", b64)

	return req, nil
}

func (c *TerraformService) newJsonRequestWithMD5(method, path string, opt interface{}, options []OptionFunc) (*retryablehttp.Request, error) {
	body, err := json.Marshal(opt)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequestWithMD5(method, path, body, options)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (c *TerraformService) LockState(pid interface{}, stateName string, lockInfo *LockInfo, options ...OptionFunc) (*LockData, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/lock", terraformStatePath(project, stateName))
	req, err := c.newJsonRequestWithMD5(http.MethodPost, u, lockInfo, options)
	if err != nil {
		return nil, err
	}

	_, err = c.client.Do(req, nil)
	if err != nil {
		// TODO handle various error cases, like the http backend does
		/*
			switch resp.StatusCode {
			case http.StatusForbidden:
				return "", fmt.Errorf("HTTP remote state endpoint invalid auth")
			case http.StatusConflict, http.StatusLocked:
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return "", fmt.Errorf("HTTP remote state already locked, failed to read body")
				}
				existing := state.LockInfo{}
				err = json.Unmarshal(body, &existing)
				if err != nil {
					return "", fmt.Errorf("HTTP remote state already locked, failed to unmarshal body")
				}
				return "", fmt.Errorf("HTTP remote state already locked: ID=%s", existing.ID)
			default:
				return "", fmt.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
			}
		*/
		return nil, err
	}
	return &LockData{
		Project:           project,
		StateName:         stateName,
		RequestedLockInfo: *lockInfo,
	}, nil
}

func (c *TerraformService) UnlockState(lockData *LockData, options ...OptionFunc) error {
	u := fmt.Sprintf("%s/lock", terraformStatePath(lockData.Project, lockData.StateName))

	// NB: lock id is NOT used. Just like in the Terraform HTTP backend
	req, err := c.newJsonRequestWithMD5(http.MethodDelete, u, &lockData.RequestedLockInfo, options)
	if err != nil {
		return err
	}
	_, err = c.client.Do(req, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *TerraformService) GetState(pid interface{}, stateName string, options ...OptionFunc) (*Payload, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := terraformStatePath(project, stateName)
	req, err := c.client.NewRequest(http.MethodGet, u, nil, options)
	if err != nil {
		return nil, err
	}
	req.Header.Del("Accept") // Mimicking the Terraform HTTP backend
	var buf bytes.Buffer
	resp, err := c.client.Do(req, &buf)
	if err != nil {
		return nil, err
	}

	data := buf.Bytes()

	// If there was no data, then return nil
	if len(data) == 0 {
		return nil, nil
	}

	// Check for the MD5
	var MD5 []byte
	if raw := resp.Header.Get("Content-MD5"); raw != "" {
		decodedMD5, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Content-MD5 '%s': %v", raw, err)
		}
		MD5 = decodedMD5
	} else {
		// Generate the MD5
		hash := md5.Sum(data)
		MD5 = hash[:]
	}
	return &Payload{
		MD5:  MD5,
		Data: data,
	}, nil
}

func (c *TerraformService) PutState(lockData *LockData, data []byte, options ...OptionFunc) error {
	u := terraformStatePath(lockData.Project, lockData.StateName)
	req, err := c.newRequestWithMD5(http.MethodPost, u, data, options)
	if err != nil {
		return err
	}
	query := req.URL.Query()
	query.Set("ID", lockData.RequestedLockInfo.ID)
	req.URL.RawQuery = query.Encode()
	_, err = c.client.Do(req, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *TerraformService) DeleteState(pid interface{}, stateName string, options ...OptionFunc) error {
	project, err := parseID(pid)
	if err != nil {
		return err
	}
	u := terraformStatePath(project, stateName)
	req, err := c.client.NewRequest(http.MethodDelete, u, nil, options)
	if err != nil {
		return err
	}
	_, err = c.client.Do(req, nil)
	if err != nil {
		return err
	}
	return nil
}

func terraformStatePath(project, stateName string) string {
	return fmt.Sprintf("projects/%s/terraform/state/%s", pathEscape(project), pathEscape(stateName))
}
