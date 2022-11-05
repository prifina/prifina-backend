/*
let AWS = require("aws-sdk");
const CREDS = new AWS.EnvironmentCredentials("AWS");
AWS.config.credentials = CREDS;
AWS.config.update({ region: process.env.REGION });
*/

const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient } = require("@aws-sdk/lib-dynamodb");
const { S3Client } = require("@aws-sdk/client-s3");
const { AthenaClient } = require("@aws-sdk/client-athena");
const { defaultProvider } = require("@aws-sdk/credential-provider-node");

const {
  CognitoIdentityProviderClient,
} = require("@aws-sdk/client-cognito-identity-provider");

const { SESv2Client } = require("@aws-sdk/client-sesv2");
const { SNSClient } = require("@aws-sdk/client-sns");

const { EventBridgeClient } = require("@aws-sdk/client-eventbridge");

const { CloudWatchClient } = require("@aws-sdk/client-cloudwatch");

const defaultCredentials = defaultProvider();


/*
AWS.CredentialProviderChain.defaultProviders = [
  function () { return new AWS.EnvironmentCredentials('AWS'); },
  function () { return new AWS.EnvironmentCredentials('AMAZON'); },
  function () { return new AWS.SharedIniFileCredentials({profile: aws_profile ? aws_profile : 'default' }); },
  function () { return new AWS.EC2MetadataCredentials(); }
];
*/
const clientCredentials = {
  credentials: defaultCredentials,
  region: process.env.REGION,
};

const snsClientCredentials = {
  credentials: defaultCredentials,
  region: process.env.SNS_REGION || process.env.REGION,
};

const sesClientCredentials = {
  credentials: defaultCredentials,
  region: process.env.EMAIL_REGION || process.env.REGION,
};
const ddbClient = new DynamoDBClient(clientCredentials);

const cognitoClient = new CognitoIdentityProviderClient(clientCredentials);

const sesV2Client = new SESv2Client(sesClientCredentials);

const snsClient = new SNSClient(snsClientCredentials);

// Create an Amazon S3 service client object.
const s3Client = new S3Client(clientCredentials);

// Create an Amazon EventBridge service client object.
const ebClient = new EventBridgeClient(clientCredentials);
const athenaClient = new AthenaClient(clientCredentials);
const cwClient = new CloudWatchClient(clientCredentials);


const marshallOptions = {
  // Whether to automatically convert empty strings, blobs, and sets to `null`.
  convertEmptyValues: false, // false, by default.
  // Whether to remove undefined values while marshalling.
  removeUndefinedValues: false, // false, by default.
  // Whether to convert typeof object to map attribute.
  convertClassInstanceToMap: false, // false, by default.
};

const unmarshallOptions = {
  // Whether to return numbers as a string instead of converting them to native JavaScript numbers.
  wrapNumbers: false, // false, by default.
};

const translateConfig = { marshallOptions, unmarshallOptions };

// Create the DynamoDB Document client.
const ddbDocClient = DynamoDBDocumentClient.from(ddbClient, translateConfig);

module.exports = {
  ddbDocClient,
  ddbClient,
  cognitoClient,
  sesV2Client,
  snsClient,
  s3Client,
  ebClient,
  athenaClient,
  cwClient
};
