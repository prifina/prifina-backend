
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
//const { parsePayload, parseFilter, getMockedData, getSandboxData } = require("@prifina-backend/sandbox");
const { parsePayload, parseFilter, getMockedData, getSandboxData } = require("../src/index");


jest.mock("@prifina-backend/shared");

describe("todo", () => {

  const s3PayloadData = {
    "input": {
      "dataconnector": "Garmin/querySleepsData",
      "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
      "fields": [
        "calendardate",
        "deepsleepdurationinseconds",
        "durationinseconds",
        "lightsleepdurationinseconds",
        "awakedurationinseconds",
        "deepsleepdurationinseconds",
        "remsleepinseconds"
      ],
      "filter": "{\"s3::date\":{\"=\":\"2022-10-01\"}}",
      "appId": "erqEj3oUNcm9a1mSpBPXwt",
      "execId": "cc3cpkdw78",
      "stage": "sandbox"
    },
    "identity": {
      "accountId": "429117803886",
      "cognitoIdentityAuthProvider": "\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP\",\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP:CognitoSignIn:f531f541-2254-4b4a-b44a-f640c2a2e6b7\"",
      "cognitoIdentityAuthType": "authenticated",
      "cognitoIdentityId": "us-east-1:59ec6a11-3585-4ad0-9eb6-c9b7a58295b1",
      "cognitoIdentityPoolId": "us-east-1:1cb638b4-0f0c-4078-9fe0-4dbd3582783d",
      "sourceIp": [
        "109.240.228.137"
      ],
      "userArn": "arn:aws:sts::429117803886:assumed-role/user-cognito-CognitoUserAuthRole-1254IDGURCRYG/CognitoIdentityCredentials",
      "username": "AROAWH2LKBVXCRH33KO3W:CognitoIdentityCredentials"
    },
    "dataconnector": {
      "partitions": [
        "day"
      ],
      "bucket": "prifina-user",
      "input": "JSON",
      "mockupModule": "@dynamic-data/garmin-mockups",
      "s3Key": "garmin/sleeps/data",
      "dataModel": "SleepsData",
      "objectName": "summary.json",
      "source": "S3",
      "id": "Garmin/querySleepsData",
      "mockupFunction": "getSleepsMockupData",
      "queryType": "SYNC"
    },
    "payload": {
      "params": {
        "Bucket": "prifina-user",
        "Key": "datamodels/garmin/sleeps/data/user=id_6145b3af07fa22f66456e20eca49e98bfe35/2022-10-01/summary.json",
        "ExpressionType": "SQL",
        "Expression": "SELECT  d.calendardate, d.deepsleepdurationinseconds, d.durationinseconds, d.lightsleepdurationinseconds, d.awakedurationinseconds, d.deepsleepdurationinseconds, d.remsleepinseconds FROM s3object[*] d",
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
        "mockupModule": "@dynamic-data/garmin-mockups",
        "s3Key": "garmin/sleeps/data",
        "dataModel": "SleepsData",
        "objectName": "summary.json",
        "source": "S3",
        "id": "Garmin/querySleepsData",
        "mockupFunction": "getSleepsMockupData",
        "queryType": "SYNC"
      }
    }
  }
  /*
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
    */
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

  it("Parse S3 request payload", () => {
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
    //garmin has this header... summaryId,calendardate,...
    const lastEntryDate = jsonContent.pop().split(',')[1];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);

  });

  it.only("Get Mocked Sync data", () => {

    const { filter, format, fields, queryType,
      dataModel,
      mockupFunction,
      mockupModule } = parsePayload(s3PayloadData);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);
    const res = getMockedData(mockupModule, queryType, format, dataModel, mockupFunction, { filter, filterCondition, startDate, endDate }, fields);
    console.log(res);
    if (fields.length > 0) {
      //  expect(res[0]).toBe(fields.join(','));
    }
    /*
        console.log(res[0].split('/t')[1]);
        console.log(res[1].split('/t')[1]);
        console.log(res[2].split('/t')[1]);
    */
    //summaryId,calendardate,...
    /*
    const lastEntryDate = res.pop().split(',')[1];
    console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
    */
  });

});  