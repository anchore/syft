package pk1

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func Test() {
	return
}

func NewID() string {
	log.WithFields(log.Fields{
		"animal": "walrus",
	}).Info("A walrus appears")
	return uuid.New().String()
}
