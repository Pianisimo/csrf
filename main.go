package main

import (
	"github.com/pianisimo/csrf/db"
	"github.com/pianisimo/csrf/server"
	"github.com/pianisimo/csrf/server/middleware/myJwt"
	"log"
)

var (
	host = "localhost"
	port = "9000"
)

func main() {
	db.InitDb()
	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing JWT")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting the server")
		log.Fatal(serverErr)
	}
}
