package interactor

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"golang.org/x/xerrors"
)

type Interactor struct {
	poolName string
}

func NewInteractor(poolName string) *Interactor {
	return &Interactor{poolName: poolName}
}

func (i *Interactor) CreateAPIGatewayWithCognito() error {
	if err := i.createUserPool(); err != nil {
		return xerrors.Errorf("failed to createUserPool: %w", err)
	}

	return nil
}

func (i *Interactor) createUserPool() error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	roleARN, roleID, err := i.createIAMRole(sess)
	if err != nil {
		return xerrors.Errorf("failed to createIAMRole: %w", err)
	}

	log.Println("roleARN: ", roleARN)
	log.Println("roleID: ", roleID)

	return nil
}

func (i *Interactor) createIAMRole(sess *session.Session) (string, string, error) {
	iamSvc := iam.New(sess)
	doc := "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Sid\": \"\", \"Effect\": \"Allow\", \"Principal\": { \"Service\": \"cognito-idp.amazonaws.com\" }, \"Action\": \"sts:AssumeRole\" } ] }"

	roleARN, roleID, err := i.getRole(sess)
	if err != nil {
		return "", "", xerrors.Errorf("failed to existRole: %w", err)
	}
	if len(roleARN) > 0 {
		return roleARN, roleID, nil
	}

	res, err := iamSvc.CreateRole(
		&iam.CreateRoleInput{
			AssumeRolePolicyDocument: aws.String(doc),
			RoleName:                 aws.String(i.getRoleName()),
			Path:                     aws.String("/service-role/"),
		})
	if err != nil {
		return "", "", xerrors.Errorf("failed to CreateRole: %w", err)
	}

	return *res.Role.Arn, *res.Role.RoleId, nil
}

func (i *Interactor) getRoleName() string {
	name := strings.Replace(i.poolName, "-", "", -1)
	return name + "-SMS-Role"
}

func (i *Interactor) getRole(sess *session.Session) (string, string, error) {
	iamSvc := iam.New(sess)

	res, err := iamSvc.GetRole(&iam.GetRoleInput{RoleName: aws.String(i.getRoleName())})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == iam.ErrCodeNoSuchEntityException {
				return "", "", nil
			}
		}
		return "", "", xerrors.Errorf("failed to GetRole: %w", err)
	}

	return *res.Role.Arn, *res.Role.RoleId, nil
}
