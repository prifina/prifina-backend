
const {
  awsUtils
} = require("@prifina-backend/shared");


const fs = require("fs");
const { join } = require("path");
const dotenv = require("dotenv");
const envConfig = dotenv.parse(fs.readFileSync(join(__dirname, "./test-env")));

for (const k in envConfig) {
  process.env[k] = envConfig[k];
}
const { parsePayload, parseFilter, getMockedData, getSandboxData } = require("@prifina-backend/sandbox");


jest.mock("@prifina-backend/shared");

describe("todo", () => {

  const s3PayloadData = {
    "input": {
      "dataconnector": "Oura/queryActivitySummary",
      "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
      "fields": [],
      "filter": "{\"s3::date\":{\"=\":\"2022-09-13\"}}",
      "appId": "x866fscSq5Ae7bPgUtb6ffB",
      "execId": "7cgbue6ksz",
      "stage": "sandbox"
    },
    "identity": {
      "accountId": "352681697435",
      "cognitoIdentityAuthProvider": "\"cognito-idp.us-east-1.amazonaws.com/us-east-1_L9Jzzwr2V\",\"cognito-idp.us-east-1.amazonaws.com/us-east-1_L9Jzzwr2V:CognitoSignIn:84e7ab65-077c-485a-b0ca-9ee5814b506d\"",
      "cognitoIdentityAuthType": "authenticated",
      "cognitoIdentityId": "eu-west-1:366f606a-cab6-4c31-89d7-6491a7aef8b6",
      "cognitoIdentityPoolId": "eu-west-1:b9c2c5cc-6ac0-4b18-94cc-17cc1ead7e92",
      "sourceIp": [
        "109.240.191.222"
      ],
      "userArn": "arn:aws:sts::352681697435:assumed-role/user-cognito-CognitoUserAuthRole-10J553L3HABQV/CognitoIdentityCredentials",
      "username": "AROAVEHLXUCNRKZV4KZJ2:CognitoIdentityCredentials"
    },
    "dataconnector": {
      "partitions": [
        "day"
      ],
      "bucket": "prifina-user",
      "input": "JSON",
      "mockupModule": "@dynamic-data/oura-mockups",
      "s3Key": "oura/activity/summary",
      "dataModel": "ActivitySummary",
      "objectName": "summary.json",
      "source": "S3",
      "id": "Oura/queryActivitySummary",
      "mockupFunction": "getActivityMockupData",
      "mockup": "queryActivitySummary",
      "queryType": "SYNC"
    },
    "payload": {
      "params": {
        "Bucket": "prifina-user",
        "Key": "datamodels/oura/activity/summary/user=id_6145b3af07fa22f66456e20eca49e98bfe35/2022-09-13/summary.json",
        "ExpressionType": "SQL",
        "Expression": "SELECT * FROM s3object",
        "InputSerialization": {
          "JSON": {
            "Type": "DOCUMENT"
          }
        },
        "OutputSerialization": {
          "JSON": {
            "RecordDelimiter": ","
          }
        },
        "ScanRange": {
          "Start": 0,
          "End": 1048576
        }
      },
      "dataconnector": {
        "partitions": [
          "day"
        ],
        "bucket": "prifina-user",
        "input": "JSON",
        "mockupModule": "@dynamic-data/oura-mockups",
        "s3Key": "oura/activity/summary",
        "dataModel": "ActivitySummary",
        "objectName": "summary.json",
        "source": "S3",
        "id": "Oura/queryActivitySummary",
        "mockupFunction": "getActivityMockupData",
        "mockup": "queryActivitySummary",
        "queryType": "SYNC"
      }
    }
  };
  const athenaPayloadData = {
    "params": {
      "executionId": "83054b7e-95c2-4ade-bcbd-e3fe02d74a9c",
      "args": {
        "input": {
          "dataconnector": "Oura/queryActivitySummariesAsync",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\">=\":\"2022-09-01\"}}",
          "appId": "x866fscSq5Ae7bPgUtb6ffB",
          "execId": "9wuxc8fh59",
          "stage": "sandbox"
        },
        "sql": "SELECT * FROM core_athena_tables.oura_activity_summary where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day >= '2022-09-01' order by day desc"
      },
      "source": "SANDBOX",
      "idToken": "eyJraWQiOiJuem9waFdjc0x1ZEdmeE4wXC9TVHJJblJaRjY2c2JsSFl3MjF1TDc1NkVoaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI4NGU3YWI2NS0wNzdjLTQ4NWEtYjBjYS05ZWU1ODE0YjUwNmQiLCJjb2duaXRvOmdyb3VwcyI6WyJVU0VSIiwiREVWIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206aWRlbnRpdHlQb29sIjoiZXUtd2VzdC0xOmI5YzJjNWNjLTZhYzAtNGIxOC05NGNjLTE3Y2MxZWFkN2U5MiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0w5Snp6d3IyViIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6IjlmODc0NDYyLTJlMDctNGI5MS05ZDUxLWFhNzk4OWJiZTVlNyIsInByZWZlcnJlZF91c2VybmFtZSI6InRhaG9sYSIsImdpdmVuX25hbWUiOiJURVJPIiwib3JpZ2luX2p0aSI6ImQ0YmI0Y2E2LTg3ZDMtNDk5OS1hODBmLTg2OWMyNmIxZTQ3YyIsImF1ZCI6IjF2bTVmNTRhaHM5MzFzNTNuYWFxNGdldG45IiwiZXZlbnRfaWQiOiIxOWM0YzU0NC0zN2JjLTQ5NmMtOTA3YS0wMTJlMjQ4MmQyMTgiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY2MTgzNjg3OCwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjYzMTQ3NDM3LCJpYXQiOjE2NjMxNDM4MzcsImZhbWlseV9uYW1lIjoiQUhPTEEiLCJqdGkiOiJiY2Y1N2EwNC05MzljLTQzNmMtOGI4NC1jN2UyZTI1ZTE2ZTUiLCJlbWFpbCI6InRybzk5OTkrbmV3QGdtYWlsLmNvbSJ9.dwUs0NzJbp5mVGmiK7zBk87xtI6Lx382ogy3AZJiapDPYyvmTgwbRaVcBYxgUlmVvNkjVJjLTGxXw5brDkDr-3v8Ym_xZB31yoBQeWC-K7kiJ0xcZEMuE4XaxZvJ2mXKd7oEe26rPdTJteE7FpO4y9N8z1tvIGRN-nNxvXC0BLTP8Qi9bN4AANI1q7-0jgEJPYrkKBpvwVBYTKVPJUkScw48G6FqQyKvfbaplPM1zwSBZ8uBLDIfd0Xobh_nqKSWZBdWo1sxFTfLuRm55sNxYxIRAvE5GPnOyeeSxc-iU13-Smd_k2Q7_Lcz7MBXoVZW8HfeUZQq6WeXLw-3jXS4xQ",
      "fields": [],
      "dataconnector": {
        "partitions": [
          "day"
        ],
        "mockupModule": "@dynamic-data/oura-mockups",
        "dataModel": "ActivitySummaryAsync",
        "orderBy": "day desc",
        "source": "ATHENA",
        "id": "Oura/queryActivitySummariesAsync",
        "mockupFunction": "getActivityMockupData",
        "mockup": "queryActivitySummariesAsync",
        "queryType": "ASYNC",
        "sql": "SELECT * FROM core_athena_tables.oura_activity_summary"
      }
    }
  };

  const expected = ['dataconnector', 'filter', 'fields', 'format'];

  it.only("Parse S3 request payload", () => {
    const res = parsePayload(s3PayloadData);
    console.log(res);
    expect(Object.keys(res)).toEqual(expect.arrayContaining(expected));

  });
  it("Get sandbox data", async () => {

    const { filter } = parsePayload(athenaPayloadData);
    const { endDate, } = parseFilter(filter);

    awsUtils.getCredentials.mockResolvedValue({
      accessKeyId: "AKID",
      secretAccessKey: "SECRET",
      region: "us-east-1",
    });
    awsUtils.awsSignedRequest.mockResolvedValue({});

    const res = await getSandboxData(athenaPayloadData);
    // console.log(res);
    const jsonContent = res.content
    const lastEntryDate = jsonContent.pop().split(',')[0];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);

  });

});  