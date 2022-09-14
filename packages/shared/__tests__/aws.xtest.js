/*
const { NodeHttpHandler } = require("@aws-sdk/node-http-handler");
const Readable = require("stream").Readable;
const {
  createMockHttpsServer,
  createResponseFunction,
  createContinueResponseFunction,
} = require("../__mocks__/httpsServerMocks/server.mock");
*/

const Readable = require("stream").Readable;
const {
  ddbDocClient,
  cognitoClient,
  sesV2Client,
  snsClient,
  s3Client,
  ebClient,
} = require("../lib/aws.js");
const {
  getItem,
  updateItem,
  scanItems,
  cognitoUpdateAttributes,
  cognitoAddUserToGroup,
  sendEmail,
  sendSMS,
  s3ObjectInfo,
  s3GetObject,
  s3PutObject,
  ebPutEvents,
} = require("../lib/awsUtils.js");

const {
  dynamoScanItemsResponse,
  dynamoUpdateItemResponse,
  cognitoClientResponse,
  sesClientResponse,
  snsClientResponse,
  s3ClientHeadResponse,
  s3ClientGetResponse,
  s3ClientPutResponse,
  ebPutEventResponse,
} = require("./awsResponses");

const fs = require("fs");
const { join } = require("path");

const dotenv = require("dotenv");
const envConfig = dotenv.parse(fs.readFileSync(join(__dirname, "./aws-env")));

for (const k in envConfig) {
  process.env[k] = envConfig[k];
}

jest.mock("../lib/aws.js");

describe("aws mock", () => {
  beforeEach(() => {
    jest.useFakeTimers("modern");
    jest.setSystemTime(new Date(2021, 0, 1));
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it("should successfully mock sendSMS", async () => {
    snsClient.send.mockResolvedValue(snsClientResponse);

    const phoneNumber = "999-999";
    const msg = "Testing sms";
    const options = {
      senderID: "Prifina",
      smsType: "Transactional",
    };
    // function sendSMS(phoneNumber, message, options) {
    const response = await sendSMS(phoneNumber, msg, options);

    //console.log(snsClient.send.mock.calls[0][0].input);

    expect(snsClient.send).lastCalledWith(
      expect.objectContaining({
        input: {
          PhoneNumber: phoneNumber,
          Message: msg,
          MessageAttributes: {
            "AWS.SNS.SMS.SenderID": {
              DataType: "String",
              StringValue: options.senderID,
            },
            "AWS.SNS.SMS.SMSType": {
              DataType: "String",
              StringValue: options.smsType,
            },
          },
        },
      })
    );

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock sendEmail", async () => {
    sesV2Client.send.mockResolvedValue(sesClientResponse);

    const params = {
      fromEmails: '"Prifina"<no-reply@' + process.env.PRIFINA_EMAIL + ">",
      subject: "Your email verification code",
      textBody: "Prifina Email",
      toEmails: ["anybody@anywhere.org"],
    };

    const response = await sendEmail(params);

    //console.log(sesV2Client.send.mock.calls[0][0].input.Content.Simple);

    expect(sesV2Client.send).lastCalledWith(
      expect.objectContaining({
        input: {
          FromEmailAddress: params.fromEmails,
          Destination: { ToAddresses: params.toEmails },
          Content: {
            Simple: {
              Subject: { Data: params.subject, Charset: "UTF-8" },
              Body: { Text: { Data: params.textBody, Charset: "UTF-8" } },
            },
          },
        },
      })
    );

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock cognitoUpdateAttributes", async () => {
    cognitoClient.send.mockResolvedValue(cognitoClientResponse);

    const params = {
      attributes: [{ Name: "custom:prifina", Value: "Prifina-id" }],
      pool_id: "pool-id",
      user_id: "user-id",
    };

    const response = await cognitoUpdateAttributes(params);
    expect(cognitoClient.send).lastCalledWith(
      expect.objectContaining({
        input: {
          UserAttributes: params.attributes,
          UserPoolId: params.pool_id,
          Username: params.user_id,
        },
      })
    );

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock cognitoUpdateAttributes", async () => {
    cognitoClient.send.mockResolvedValue(cognitoClientResponse);

    const params = {
      attributes: [{ Name: "custom:prifina", Value: "Prifina-id" }],
      pool_id: "pool-id",
      user_id: "user-id",
    };

    const response = await cognitoUpdateAttributes(params);
    expect(cognitoClient.send).lastCalledWith(
      expect.objectContaining({
        input: {
          UserAttributes: params.attributes,
          UserPoolId: params.pool_id,
          Username: params.user_id,
        },
      })
    );

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock cognitoAddUserToGroup", async () => {
    cognitoClient.send.mockResolvedValue(cognitoClientResponse);

    const params = {
      group: "TEST",
      pool_id: "pool-id",
      user_id: "user-id",
    };

    const response = await cognitoAddUserToGroup(params);
    expect(cognitoClient.send).lastCalledWith(
      expect.objectContaining({
        input: {
          GroupName: params.group,
          UserPoolId: params.pool_id,
          Username: params.user_id,
        },
      })
    );

    //console.log(response);
    //{ GroupName: undefined, UserPoolId: undefined, Username: undefined }

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock getItem", async () => {
    // response mockup is incorrect...
    ddbDocClient.send.mockResolvedValue(dynamoUpdateItemResponse);

    const params = {
      TableName: "PrifinaUser",
      Key: { id: "UUID" },
    };

    const response = await getItem(params);
    //console.log(response);

    expect(ddbDocClient.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock updateItem", async () => {
    ddbDocClient.send.mockResolvedValue(dynamoUpdateItemResponse);

    const params = {
      TableName: "PrifinaUser",
      Key: { id: "UUID" },
      UpdateExpression: "set createdAt=:createdAt ",
      ExpressionAttributeValues: {
        ":createdAt": new Date().toISOString(),
      },
      ReturnValues: "ALL_NEW",
    };

    const response = await updateItem(params);
    //console.log(response);

    expect(ddbDocClient.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock scanItems", async () => {
    ddbDocClient.send.mockResolvedValue(dynamoScanItemsResponse);

    const params = {
      TableName: "DataSourceStatus",
    };

    const response = await scanItems(params);
    //console.log(response);

    expect(ddbDocClient.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });

  it("should successfully mock Get S3 Object Info", async () => {
    s3Client.send.mockResolvedValue(s3ClientHeadResponse);

    const params = {
      Bucket: "s3-bucket",
      Key: "s3-key",
    };

    const response = await s3ObjectInfo(params);
    //console.log(response);

    expect(s3Client.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });

  it("should successfully mock Get S3 Object", async () => {
    //s3Client.send.mockResolvedValue(s3ClientGetResponse);
    let s = new Readable();
    const result = { isMock: true };
    s.push(JSON.stringify(result));
    s.push(null); // indicates end-of-file basically - the end of the stream
    s3Client.send.mockResolvedValue({ Body: s });

    const params = {
      Bucket: "s3-bucket",
      Key: "s3-key",
    };

    const response = await s3GetObject(params);
    //console.log(response);

    expect(s3Client.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response).toEqual({ Body: JSON.stringify(result) });
  });

  it("should successfully mock Put S3 Object", async () => {
    s3Client.send.mockResolvedValue(s3ClientPutResponse);

    const params = {
      Bucket: "s3-bucket",
      Key: "s3-key",
      Body: JSON.stringify({ test: "OK" }),
      ContentType: "application/json",
    };

    const response = await s3PutObject(params);
    //console.log(response);

    expect(s3Client.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
  it("should successfully mock Put EB Event", async () => {
    ebClient.send.mockResolvedValue(ebPutEventResponse);

    const params = {
      Entries: [
        {
          Detail: JSON.stringify({
            userId: "user-id",
            eventType: "event-type",
          }),
          DetailType: "lambda",
          Source: "Garmin-Notification",
        },
      ],
    };

    const response = await ebPutEvents(params);
    //console.log(response);

    expect(ebClient.send).lastCalledWith(
      expect.objectContaining({
        input: params,
      })
    );

    //console.log(ddbDocClient.send.mock.calls[0][0].input);

    expect(response["$metadata"].httpStatusCode).toEqual(200);
  });
});

process.on("unhandledRejection", (reason) => {
  console.log("DEBUG: " + reason);
});
