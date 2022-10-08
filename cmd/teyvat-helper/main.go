package main

import (
	"github.com/Jx2f/teyvat-helper/pkg/config"
	"github.com/Jx2f/teyvat-helper/pkg/core"
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
