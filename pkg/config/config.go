package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Data struct {
		CmdID string `json:"cmdid"`
		Proto string `json:"proto"`
	} `json:"data"`
	Device string `json:"device"`
	Memory string `json:"memory"`
}

func LoadConfig(name string) (*Config, error) {
	p, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err = json.Unmarshal(p, c); err != nil {
		return nil, err
	}
	return c, nil
}
