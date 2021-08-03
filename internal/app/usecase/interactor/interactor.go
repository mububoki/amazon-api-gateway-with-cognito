package interactor

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/iam"
	"golang.org/x/xerrors"
)

const (
	msg                 = "{username} {####}"
	subject             = "test-mububoki"
	verifyMSG           = "{####}"
	authMSG             = verifyMSG
	waitDays            = 1
	externalID          = "31ae2116-0aed-630a-b641-9ca9b0a8c050"
	assumeRolePolicyDoc = "{ \"Version\": \"2012-10-17\"," +
		" \"Statement\": [ {" +
		" \"Sid\": \"\"," +
		" \"Effect\": \"Allow\"," +
		" \"Principal\": { \"Service\": \"cognito-idp.amazonaws.com\" }," +
		" \"Action\": \"sts:AssumeRole\"," +
		" \"Condition\": {" +
		" \"StringEquals\": {" +
		" \"sts:ExternalId\": \"" + externalID + "\"" +
		"}" +
		"}" +
		" } ] }"
	policyDoc = "{\"Version\": \"2012-10-17\"," +
		" \"Statement\": [{" +
		" \"Effect\": \"Allow\"," +
		" \"Action\": [\"sns:publish\"]," +
		" \"Resource\": [\"*\"]" +
		"}]" +
		"}"
)

type Interactor struct {
	poolName string
}

func NewInteractor(poolName string) *Interactor {
	return &Interactor{poolName: poolName}
}

func (i *Interactor) CreateAPIGatewayWithCognito() error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	roleARN, roleID, err := i.createIAMRole(sess)
	if err != nil {
		return xerrors.Errorf("failed to createIAMRole: %w", err)
	}
	log.Println("roleARN: ", roleARN)
	log.Println("roleID: ", roleID)

	if err := i.createUserPool(sess, roleARN, roleID); err != nil {
		return xerrors.Errorf("failed to createUserPool: %w", err)
	}

	return nil
}

func (i *Interactor) DeleteAPIGatewayWithCognito() error {
	if err := i.deleteUserPool(); err != nil {
		return xerrors.Errorf("failed to deleteUserPool: %w", err)
	}

	return nil
}

func (i *Interactor) createUserPool(sess *session.Session, roleARN string, roleID string) error {
	cgSvc := cognitoidentityprovider.New(sess)

	input := &cognitoidentityprovider.CreateUserPoolInput{
		PoolName: aws.String(i.poolName),
		AdminCreateUserConfig: &cognitoidentityprovider.AdminCreateUserConfigType{
			AllowAdminCreateUserOnly: aws.Bool(false),
			InviteMessageTemplate: &cognitoidentityprovider.MessageTemplateType{
				EmailMessage: aws.String(msg),
				EmailSubject: aws.String(subject),
				SMSMessage:   aws.String(msg),
			},
			UnusedAccountValidityDays: aws.Int64(waitDays),
		},
		AutoVerifiedAttributes: []*string{
			aws.String("email"),
			aws.String("phone_number"),
		},
		EmailVerificationMessage: aws.String(verifyMSG),
		EmailVerificationSubject: aws.String(subject),
		Policies: &cognitoidentityprovider.UserPoolPolicyType{
			PasswordPolicy: &cognitoidentityprovider.PasswordPolicyType{
				MinimumLength:    aws.Int64(6),
				RequireLowercase: aws.Bool(false),
				RequireNumbers:   aws.Bool(false),
				RequireSymbols:   aws.Bool(false),
				RequireUppercase: aws.Bool(false),
			},
		},
		Schema: []*cognitoidentityprovider.SchemaAttributeType{
			{
				AttributeDataType:      aws.String("String"),
				DeveloperOnlyAttribute: aws.Bool(false),
				Mutable:                aws.Bool(false),
				Name:                   aws.String("user_name"),
				Required:               aws.Bool(false),
				StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
					MaxLength: aws.String("64"),
					MinLength: aws.String("3"),
				},
			},
		},
		SmsAuthenticationMessage: aws.String(authMSG),
		SmsConfiguration: &cognitoidentityprovider.SmsConfigurationType{
			SnsCallerArn: aws.String(roleARN),
			ExternalId:   aws.String(externalID),
		},
		SmsVerificationMessage: aws.String(verifyMSG),
	}

	res, err := cgSvc.CreateUserPool(input)
	if err != nil {
		return xerrors.Errorf("failed to CreateUserPool: %w", err)
	}

	log.Println("res: ", res)

	return nil
}

func (i *Interactor) deleteUserPool() error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	if err := i.deleteIAMRole(sess); err != nil {
		return xerrors.Errorf("failed to createIAMRole: %w", err)
	}

	return nil
}

func (i *Interactor) createIAMRole(sess *session.Session) (string, string, error) {
	iamSvc := iam.New(sess)

	roleARN, roleID, err := i.getRole(sess)
	if err != nil {
		return "", "", xerrors.Errorf("failed to getRole: %w", err)
	}
	if len(roleARN) > 0 {
		return roleARN, roleID, xerrors.Errorf("there already exists role named %s", i.getRoleName())
	}

	res, err := iamSvc.CreateRole(
		&iam.CreateRoleInput{
			AssumeRolePolicyDocument: aws.String(assumeRolePolicyDoc),
			RoleName:                 aws.String(i.getRoleName()),
			Path:                     aws.String("/service-role/"),
		})
	if err != nil {
		return "", "", xerrors.Errorf("failed to CreateRole: %w", err)
	}

	if _, err := iamSvc.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyDocument: aws.String(policyDoc),
		PolicyName:     aws.String(i.getPolicyName()),
		RoleName:       aws.String(i.getRoleName()),
	}); err != nil {
		return "", "", xerrors.Errorf("failed to PutRolePolicy: %w", err)
	}

	return *res.Role.Arn, *res.Role.RoleId, nil
}

func (i *Interactor) deleteIAMRole(sess *session.Session) error {
	iamSvc := iam.New(sess)

	if _, err := iamSvc.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
		PolicyName: aws.String(i.getPolicyName()),
		RoleName:   aws.String(i.getRoleName()),
	}); err != nil {
		return xerrors.Errorf("failed to DeleteRolePolicy: %w", err)
	}

	if _, err := iamSvc.DeleteRole(&iam.DeleteRoleInput{RoleName: aws.String(i.getRoleName())}); err != nil {
		return xerrors.Errorf("failed to DeleteRole: %w", err)
	}

	return nil
}

func (i *Interactor) getRoleName() string {
	name := strings.Replace(i.poolName, "-", "", -1)
	return name + "-SMS-Role"
}

func (i *Interactor) getPolicyName() string {
	name := strings.Replace(i.poolName, "-", "", -1)
	return name + "-SMS-Policy"
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
