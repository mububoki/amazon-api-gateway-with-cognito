package env

import (
	"log"

	"github.com/kelseyhightower/envconfig"
)

var Cognito CognitoEnv

type CognitoEnv struct {
	PoolName string `envconfig:"POOL_NAME" default:"hoge-pool"`
}

func init() {
	if err := envconfig.Process("COGNITO", &Cognito); err != nil {
		log.Panicf("failed to Process: %s", err.Error())
	}
}
