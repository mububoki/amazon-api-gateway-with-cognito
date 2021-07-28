package main

import (
	"log"
)

func main() {
	interactor, err := build()
	if err != nil {
		log.Panic(err)
	}

	if err := interactor.CreateAPIGatewayWithCognito(); err != nil {
		log.Panic(err)
	}

	log.Println("main successfully")
}
