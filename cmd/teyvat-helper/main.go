package main

import (
	"github.com/teyvat-helper/teyvat-helper/pkg/config"
	"github.com/teyvat-helper/teyvat-helper/pkg/core"
)

func main() {
	config, err := config.LoadConfig("data/config.json")
	if err != nil {
		panic(err)
	}
	service, err := core.NewService(config)
	if err != nil {
		panic(err)
	}
	if err := service.Start(); err != nil {
		panic(err)
	}
}
