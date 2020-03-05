module github.com/m-mizutani/deepalert-virustotal

go 1.12

require (
	github.com/aws/aws-lambda-go v1.14.1 // indirect
	github.com/aws/aws-sdk-go v1.29.17
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/m-mizutani/deepalert v0.0.0-20200304233039-e861e7b185b9
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.9 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4 // indirect
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
	golang.org/x/tools v0.0.0-20190726230722-1bd56024c620 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0 // indirect
)

replace gopkg.in/urfave/cli.v1 => github.com/urfave/cli v1.21.0
