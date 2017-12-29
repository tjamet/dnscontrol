package namedotcom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const defaultAPIBase = "https://api.name.com/api" // API endpoint

type protocolRecordList struct {
	*apiResult
	Records []*protocolRawRecord `json:"records"`
}

type protocolRawRecord struct {
	RecordID string `json:"record_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      string `json:"ttl"`
	Priority string `json:"priority"`
}

// apiResult is the nameDotCom API protocols return status.
type apiResult struct {
	Result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"result"`
}

func (n *nameDotCom) getRecords(domain string) ([]*protocolRawRecord, error) {
	result := &protocolRecordList{}
	err := n.get(n.apiGetRecords(domain), result)
	if err != nil {
		return nil, err
	}
	if err = result.getErr(); err != nil {
		return nil, err
	}
	return result.Records, nil
}

func (n *nameDotCom) apiGetRecords(domain string) string {
	return fmt.Sprintf("%s/dns/list/%s", n.APIUrl, domain)
}
func (n *nameDotCom) apiCreateRecord(domain string) string {
	return fmt.Sprintf("%s/dns/create/%s", n.APIUrl, domain)
}
func (n *nameDotCom) apiDeleteRecord(domain string) string {
	return fmt.Sprintf("%s/dns/delete/%s", n.APIUrl, domain)
}

// get performs a http GET and unmarshals response json into target struct.
func (n *nameDotCom) get(url string, target interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	n.addAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// post performs a http POST, json marshalling the given data into the body.
func (n *nameDotCom) post(url string, data interface{}) (*apiResult, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		return nil, err
	}
	n.addAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result := &apiResult{}
	if err = json.Unmarshal(text, result); err != nil {
		return nil, err
	}
	return result, nil
}

// addAuth adds authentication headers to r.
func (n *nameDotCom) addAuth(r *http.Request) {
	r.Header.Add("Api-Username", n.APIUser)
	r.Header.Add("Api-Token", n.APIKey)
}

// getErr returns nil if the apiResult indicates success. Otherwise, returns an error.
func (r *apiResult) getErr() error {
	if r == nil {
		return nil
	}
	if r.Result.Code != 100 {
		if r.Result.Message == "" {
			return fmt.Errorf("Unknown error from name.com")
		}
		return fmt.Errorf(r.Result.Message)
	}
	return nil
}
