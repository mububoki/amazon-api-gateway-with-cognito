package main

import (
	"github.com/mububoki/amazon-api-gateway-with-cognito/internal/app/infrastructure/env"
	"github.com/mububoki/amazon-api-gateway-with-cognito/internal/app/usecase/interactor"
)

func build() (*interactor.Interactor, error) {
	return interactor.NewInteractor(env.Cognito.PoolName), nil
}
