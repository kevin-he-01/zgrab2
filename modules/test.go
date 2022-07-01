package modules

import (
	"log"

	"github.com/zmap/zgrab2/modules/test"
)

func init() {
	log.Println("Registering module test")
	test.RegisterModule()
}