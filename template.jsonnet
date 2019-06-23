local secretArn = 'hoge';
local DeepAlertStackName = 'deepalert-test';

local TaskTopic = {
  'Fn::ImportValue': DeepAlertStackName + '-TaskTopic',
};

local iamRole = {
  LambdaRole: {
    Type: 'AWS::IAM::Role',
    Properties: {
      AssumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: ['lambda.amazonaws.com'] },
            Action: ['sts:AssumeRole'],
          },
        ],
        Path: '/',
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
        Policies: [
          {
            PolicyName: 'PublishReportContent',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['sns:Publish'],
                  Resource: [TaskTopic],
                },
                {
                  Effect: 'Allow',
                  Action: ['secretsmanager:GetSecretValue'],
                  Resource: [{ Ref: 'SecretArn' }],
                },
              ],
            },
          },
        ],
      },
    },
  },
};


{
  AWSTemplateFormatVersion: '2010-09-09',
  Transform: 'AWS::Serverless-2016-10-31',

  Resources: {
    // --------------------------------------------------------
    // Lambda functions
    Handler: {
      Type: 'AWS::Serverless::Function',
      Properties: {
        CodeUri: 'build',
        Handler: 'main',
        Runtime: 'go1.x',
        Timeout: 30,
        MemorySize: 128,
        Role: {
          Ref: 'LambdaRole',
        },

        Environment: {
          Variables: {
            SECRET_ARN: secretArn,
          },
        },
        Events: {
          NotifyTopic: {
            Type: 'SNS',
            Properties: {
              Topic: TaskTopic,
            },
          },
        },
      },
    },
    LambdaRole: iamRole,
  },
}
