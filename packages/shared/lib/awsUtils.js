const { urlToHttpOptions } = require("url");

const {
  ddbDocClient,
  cognitoClient,
  sesV2Client,
  snsClient,
  s3Client,
  ebClient,
  athenaClient,
  cwClient
} = require("./aws");

const {
  GetCommand,
  UpdateCommand,
  PutCommand,
  QueryCommand,
  DeleteCommand,
  ScanCommand,
} = require("@aws-sdk/lib-dynamodb");
const {
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,

  PutObjectCommand,
  CopyObjectCommand,
  HeadObjectCommand,
  SelectObjectContentCommand,
  WriteGetObjectResponseCommand,
} = require("@aws-sdk/client-s3");
const {
  AdminAddUserToGroupCommand,
  AdminUpdateUserAttributesCommand,
  AddCustomAttributesCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const {
  CreateConfigurationSetCommand,
  SendEmailCommand,
} = require("@aws-sdk/client-sesv2");
const { PublishCommand } = require("@aws-sdk/client-sns");

const {
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  StartQueryExecutionCommand,
} = require("@aws-sdk/client-athena");

const { ListMetricsCommand, GetMetricDataCommand } = require("@aws-sdk/client-cloudwatch");

const { uCfirst } = require("./libUtils");
const { PutEventsCommand } = require("@aws-sdk/client-eventbridge");

const { HttpRequest } = require("@aws-sdk/protocol-http");
const { SignatureV4 } = require("@aws-sdk/signature-v4");
const { NodeHttpHandler } = require("@aws-sdk/node-http-handler");
const { Sha256 } = require("@aws-crypto/sha256-browser");

const { S3RequestPresigner } = require("@aws-sdk/s3-request-presigner");
const { parseUrl } = require("@aws-sdk/url-parser");
const { Hash } = require("@aws-sdk/hash-node");
const { formatUrl } = require("@aws-sdk/util-format-url");

const {
  CognitoIdentityClient,
  GetIdCommand,
  GetCredentialsForIdentityCommand,
} = require("@aws-sdk/client-cognito-identity");

async function getCredentials({
  idToken,
  userPoolRegion,
  userPoolId,
  userIdPool,
}) {
  //const _currentSession = await Auth.currentSession();
  //const token = currentSession.getIdToken().payload;
  //const userIdPool = localStorage.getItem("LastSessionIdentityPool");
  const provider =
    "cognito-idp." + userPoolRegion + ".amazonaws.com/" + userPoolId;
  //const provider = token["iss"].replace("https://", "");
  let identityParams = {
    IdentityPoolId: userIdPool,
    Logins: {},
  };

  identityParams.Logins[provider] = idToken;
  const cognitoClient = new CognitoIdentityClient({
    region: userIdPool.split(":")[0],
  });
  //console.log(identityParams);
  const cognitoIdentity = await cognitoClient.send(
    new GetIdCommand(identityParams)
  );
  //console.log("COGNITO IDENTITY ", cognitoIdentity);

  let credentialParams = {
    IdentityId: cognitoIdentity.IdentityId,
    Logins: {},
  };

  credentialParams.Logins[provider] = idToken;
  //console.log(credentialParams);
  const cognitoIdentityCredentials = await cognitoClient.send(
    new GetCredentialsForIdentityCommand(credentialParams)
  );
  //console.log("COGNITO IDENTITY CREDS ", cognitoIdentityCredentials);

  const clientCredentials = {
    identityId: cognitoIdentity.IdentityId,
    accessKeyId: cognitoIdentityCredentials.Credentials.AccessKeyId,
    secretAccessKey: cognitoIdentityCredentials.Credentials.SecretKey,
    sessionToken: cognitoIdentityCredentials.Credentials.SessionToken,
    expiration: cognitoIdentityCredentials.Credentials.Expiration,
    authenticated: true,
  };

  return Promise.resolve(clientCredentials);
}
async function awsGetSignedUrl({
  bucket,
  key,
  credentials,
  region,
  expiresIn,
}) {
  const s3ObjectUrl = parseUrl(
    `https://${bucket}.s3.${region}.amazonaws.com/${key}`
  );
  const presigner = new S3RequestPresigner({
    expiresIn,
    credentials,
    region,
    //sha256: Hash.bind(null, "sha256"), // In Node.js
    sha256: Sha256, // In browsers
  });
  // Create a GET request from S3 url.
  const url = await presigner.presign(new HttpRequest(s3ObjectUrl));
  //return presigner.presign(new HttpRequest(s3ObjectUrl));
  return formatUrl(url);
}
async function awsSignedRequest({
  request_api,
  region,
  credentials,
  post_body,
  service,
}) {
  let options = urlToHttpOptions(new URL(request_api));

  //const uri = new URL(request_api);
  //  console.log("URI ",uri);
  /*
  URL {
    href: 'https://localhost:54322/',
    origin: 'https://localhost:54322',
    protocol: 'https:',
    username: '',
    password: '',
    host: 'localhost:54322',
    hostname: 'localhost',
    port: '54322',
    pathname: '/',
    search: '',
    searchParams: URLSearchParams {},
    hash: ''
  }
*/
  /*
  const options={
    hostname: uri.hostname,
    port: uri.port||443,
    headers: { host: uri.host||uri.hostname, "Content-Type": "application/json" },
    method: "POST",
    path: uri.pathname,
    body: JSON.stringify(post_body),
  };
  */
  options.body = JSON.stringify(post_body);
  options.headers = {
    host: options.host || options.hostname,
    "Content-Type": "application/json",
  };
  options.port = options.port || 443;
  options.method = "POST";
  /*  
   httpRequest.headers.host = uri.host;
  httpRequest.headers["Content-Type"] = "application/json";
  httpRequest.method = "POST";
  httpRequest.body = JSON.stringify(post_body);
*/

  console.log("OPTIONS ", options);
  const request = new HttpRequest(options);

  //console.log(request);

  const signer = new SignatureV4({
    credentials: credentials,
    region: region,
    service: service,
    sha256: Sha256,
  });

  console.log(signer);
  const signedRequest = await signer.sign(request);

  const client = new NodeHttpHandler();
  //const { response } = await client.handle(signedRequest);
  //return client.handle(signedRequest);

  const { response } = await client.handle(signedRequest);
  //console.log("STATUS ",response.statusCode );
  //console.log("RESPONSE", response);
  console.log(
    "RESPONSE",
    response.statusCode + " " + response.body.statusMessage
  );

  //console.log(process.env);
  let responseBody = "";
  /*
  return new Promise(
    (resolve) => {
      response.body.on("data", (chunk) => {
        responseBody += chunk;
      });
      response.body.on("end", () => {
        console.log("Response body: " + responseBody);
        client.destroy();
        resolve(responseBody);
      });
    },
    (error) => {
      console.log("Error: " + error);
      client.destroy();
      reject(error);
    }
  );
  */
  try {
    // const res = await nodeHttpHandler.handle(signedHttpRequest);
    const body = await new Promise((resolve, reject) => {
      //let body = "";
      response.body.on("data", (chunk) => {
        responseBody += chunk;
      });
      response.body.on("end", () => {
        client.destroy();
        resolve(responseBody);
      });
      response.body.on("error", (err) => {
        client.destroy();
        reject(err);
      });
    });
    //console.log(body);
  } catch (err) {
    console.error("Error:");
    console.error(err);
    client.destroy();
  }

  //console.log("RES ", responseBody);
  //client.destroy();
  //return responseBody;
}

function ebPutEvents(params) {
  return ebClient.send(new PutEventsCommand(params));
}

function getItem(params) {
  return ddbDocClient.send(new GetCommand(params));
}
function scanItems(params) {
  return ddbDocClient.send(new ScanCommand(params));
}
function updateItem(params) {
  /*
    Convert the attribute JavaScript object you are updating to the required
    Amazon  DynamoDB record. The format of values specifies the datatype. The
    following list demonstrates different datatype formatting requirements:
    String: "String",
    NumAttribute: 1,
    BoolAttribute: true,
    ListAttribute: [1, "two", false],
    MapAttribute: { foo: "bar" },
    NullAttribute: null
     */
  /* 
  // Set the parameters
  const params = {
    TableName: "TABLE_NAME",
   
    Key: {
      primaryKey: "VALUE_1", // For example, 'Season': 2.
      sortKey: "VALUE_2", // For example,  'Episode': 1; (only required if table has sort key).
    },
    // Define expressions for the new or updated attributes
    UpdateExpression: "set ATTRIBUTE_NAME_1 = :t, ATTRIBUTE_NAME_2 = :s", // For example, "'set Title = :t, Subtitle = :s'"
    ExpressionAttributeValues: {
      ":t": "NEW_ATTRIBUTE_VALUE_1", // For example ':t' : 'NEW_TITLE'
      ":s": "NEW_ATTRIBUTE_VALUE_2", // For example ':s' : 'NEW_SUBTITLE'
    },
  };
  */
  return ddbDocClient.send(new UpdateCommand(params));
}

function cognitoAddUserToGroup(payload) {
  const params = {
    GroupName: payload.group,
    UserPoolId: payload.pool_id,
    Username: payload.user_id,
  };
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  /*
  console.log(
    cognitoClient.config.credentials().then((res) => {
      console.log("RES ", res);
    })
  );
  */
  return cognitoClient.send(new AdminAddUserToGroupCommand(params));
}
function cognitoUpdateAttributes(payload) {
  const params = {
    UserAttributes: payload.attributes,
    UserPoolId: payload.pool_id,
    Username: payload.user_id,
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return cognitoClient.send(new AdminUpdateUserAttributesCommand(params));
}

function sendEmail(data) {
  let params2 = {
    Destination: {
      /* required */
      CcAddresses: [
        /* more items */
      ],
      ToAddresses: data.toEmails,
    },
    Message: {
      /* required */
      Body: {
        /* required */
        /*
      Html: {
        Charset: "UTF-8",
        Data: "HTML_FORMAT_BODY",
      },
      Text: {
        Charset: "UTF-8",
        Data: "TEXT_FORMAT_BODY",
      },
      */
      },
      Subject: {
        Charset: "UTF-8",
        Data: data.subject,
      },
    },
    Source: data.fromEmails, // SENDER_ADDRESS
    ReplyToAddresses: [
      /* more items */
    ],
  };

  let params = {
    FromEmailAddress: data.fromEmails,
    Destination: {
      ToAddresses: data.toEmails,
    },
    Content: {
      Simple: {
        Subject: {
          Data: data.subject,
          Charset: "UTF-8",
        },
        Body: {},
      },
    },
  };

  if (data.hasOwnProperty("htmlBody")) {
    /*
    params.Message.Body.Html = data.htmlBody;
    params.Message.Body.Charset = "UTF-8";
    */
    params.Content.Simple.Body.Html = { Data: data.htmlBody, Charset: "UTF-8" };
  }
  if (data.hasOwnProperty("textBody")) {
    //params.Message.Body.Text = data.textBody;
    //params.Message.Body.Charset = "UTF-8";

    params.Content.Simple.Body.Text = { Data: data.textBody, Charset: "UTF-8" };
  }
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return sesV2Client.send(new SendEmailCommand(params));
}

function sendSMS(phoneNumber, message, options) {
  try {
    if (message.length > 160) {
      return Promise.reject("MESSAGE_TOO_LONG");
    }
    let params = { PhoneNumber: phoneNumber, Message: message };
    console.log(options, typeof options);
    if (typeof options !== "undefined" && typeof options !== null) {
      params.MessageAttributes = {};
      if (typeof options.senderID !== "undefined") {
        params.MessageAttributes["AWS.SNS.SMS.SenderID"] = {
          DataType: "String",
          StringValue: options.senderID,
        };
      }
      if (typeof options.smsType !== "undefined") {
        //Promotional/Transactional
        options.smsType = uCfirst(options.smsType);
        if (["Promotional", "Transactional"].indexOf(options.smsType) === -1) {
          return Promise.reject("NOT_VALID_SMS_TYPE");
        }
        params.MessageAttributes["AWS.SNS.SMS.SMSType"] = {
          DataType: "String",
          StringValue: options.smsType,
        };
      }
    }

    if (
      (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
      process.env.hasOwnProperty("JEST_WORKER_ID")
    ) {
      console.log("PARAMS", params);
    }

    return snsClient.send(new PublishCommand(params));
    //return SNS.publish(params).promise();
    //await saveSMS(data.MessageId,networkID,requestID,params,result);
    //console.log('SMS DELIVERY',data);
  } catch (e) {
    return Promise.reject(e);
  }
}
async function s3ObjectInfo(params) {
  try {
    //console.log("PARAMS ", params);
    const info = await s3Client.send(new HeadObjectCommand(params));
    //console.log("INFO ", info);
    return Promise.resolve(info);
  } catch (err) {
    // err.code is now err.name
    // console.log("Error CODE ", typeof err, Object.keys(err));
    // console.log("Error NAME ", err.name);
    // console.log("Error FAULT ", err.$fault);
    // console.log("Error META ", err.$metadata);
    // console.log("Error", err);
    if (err.hasOwnProperty("name") && err.name === "NotFound") {
      return Promise.resolve(false);
    } else {
      return Promise.reject(err);
    }
  }
}

function s3GetObjectStream(params) {
  return s3Client.send(new GetObjectCommand(params));
}

const streamToString = (stream) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });

async function s3GetObject(params) {
  try {
    // Get the object} from the Amazon S3 bucket. It is returned as a ReadableStream.
    //s3://prifina-core-352681697435/integrations/fitbit/9G7RZB.json

    const s3Data = await s3Client.send(new GetObjectCommand(params));
    //console.log("S3", s3Data);
    let bodyContents = "";
    if (s3Data && s3Data.hasOwnProperty("Body")) {
      bodyContents = await streamToString(s3Data.Body);
      //console.log(bodyContents);
    }

    return Promise.resolve({ Body: bodyContents });
  } catch (err) {
    console.log("Error", err);
    return Promise.reject(err);
  }
}

function s3PutObject(params) {
  return s3Client.send(new PutObjectCommand(params));
}

function s3DeleteObject(params) {
  return s3Client.send(new DeleteObjectCommand(params));
}
function s3DeleteObjects(params) {
  return s3Client.send(new DeleteObjectsCommand(params));
}
function s3CopyObject(params) {
  return s3Client.send(new CopyObjectCommand(params));
}

function s3SelectObject(params) {
  return s3Client.send(new SelectObjectContentCommand(params));
}
function s3WriteGetObjectResponse(params) {
  return s3Client.send(new WriteGetObjectResponseCommand(params));
}
function athenaGetQueryExecution(params) {
  return athenaClient.send(new GetQueryExecutionCommand(params));
}

function athenaGetQueryResults(params) {
  return athenaClient.send(new GetQueryResultsCommand(params));
}

function athenaStartQueryExecution(params) {
  return athenaClient.send(new StartQueryExecutionCommand(params));
}


function cloudwatchListMetrics(params) {
  return cwClient.send(new ListMetricsCommand(params));
}

function cloudwatchGetMetricsData(params) {
  return cwClient.send(new GetMetricDataCommand(params));
}


/*
addPrifinaUser({ uuid: "UUID", user_id: "TEST", name: "TRO" }).then((res) => {
  console.log("TEST ", res);
});
*/
/*
cognitoUpdateAttributes({
  attributes: [{ Name: "custom:prifina", Value: "Prifina-id" }],
  pool_id: "us-east-1_Q983m5wFm",
  user_id: "testing",
}).then((res) => {
  console.log("TEST ", res);
});
*/
/*
const msg = {
  fromEmails: '"Prifina"<no-reply@' + process.env.PRIFINA_EMAIL + ">",
  subject: "Your email verification code",
  textBody: "Prifina Email",
  toEmails: ["tro9999@gmail.com"],
};

sendEmail(msg).then((res) => {
  console.log("TEST ", res);
});
*/
/*
sendSMS("+358407077102", "testing sms", {
  senderID: "Prifina",
  smsType: "Transactional",
}).then((res) => {
  console.log("TEST ", res);
});
*/
//s3://prifina-app-data-dev/integrations/5XMCZ6.json
//s3://prifina-core-352681697435-eu-west-1/integrations/fitbit/9G7RZB.json
/*
s3ObjectInfo({
  Bucket: "prifina-core-352681697435-eu-west-1",
  Key: "integrations/fitbit/9G7RZB.json",
}).then((res) => {
  console.log("TEST ", res);
});
*/
/*
s3GetObject({
  Bucket: "prifina-core-352681697435-eu-west-1",
  Key: "integrations/fitbit/9G7RZB.json",
}).then((res) => {
  console.log("TEST ", res);
  console.log("TEST ", typeof res);
  console.log("TEST ", JSON.parse(res.Body.toString()));
});
*/
/*
s3PutObject({
  Bucket: "prifina-app-data-dev",
  Key: "integrations/xxx.json",
  Body: JSON.stringify({ test: "OK" }),
  ContentType: "application/json",
}).then((res) => {
  console.log("TEST ", res);
});
*/
module.exports = {
  getItem,
  updateItem,
  scanItems,
  sendEmail,
  sendSMS,
  cognitoUpdateAttributes,
  cognitoAddUserToGroup,
  s3ObjectInfo,
  s3GetObject,
  s3PutObject,
  s3DeleteObject,
  s3DeleteObjects,
  s3CopyObject,
  s3SelectObject,
  s3WriteGetObjectResponse,
  ebPutEvents,
  awsSignedRequest,
  athenaGetQueryExecution,
  athenaGetQueryResults,
  athenaStartQueryExecution,
  getCredentials,
  awsGetSignedUrl,
  s3GetObjectStream,
  cloudwatchListMetrics,
  cloudwatchGetMetricsData

};

//exports.CognitoUpdateAttributes = CognitoUpdateAttributes;
//exports.CognitoaddUserToGroup = CognitoaddUserToGroup;
