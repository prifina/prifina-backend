
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
const { parsePayload, parseFilter, getMockedData, getSandboxData } = require("../src/data");


jest.mock("@prifina-backend/shared");

describe("todo", () => {
  //it.todo("can send http requests");
  /*
    {
      "input": {
          "dataconnector": "Oura/queryActivitySummary",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\"like\":\"2022-09\"}}",
          "appId": "866fscSq5Ae7bPgUtb6ffB",
          "execId": "1tgVKTDrnYGAS4hHZHKRHo",
          "stage": "sandbox"
      },
      "identity": {
          "accountId": "429117803886",
          "cognitoIdentityAuthProvider": "\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP\",\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP:CognitoSignIn:f531f541-2254-4b4a-b44a-f640c2a2e6b7\"",
          "cognitoIdentityAuthType": "authenticated",
          "cognitoIdentityId": "us-east-1:59ec6a11-3585-4ad0-9eb6-c9b7a58295b1",
          "cognitoIdentityPoolId": "us-east-1:1cb638b4-0f0c-4078-9fe0-4dbd3582783d",
          "sourceIp": [
              "109.240.191.222"
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
          "s3Key": "oura/activity/summary",
          "objectName": "summary.json",
          "source": "S3",
          "id": "Oura/queryActivitySummary",
          "mockup": "queryActivitySummary",
          "queryType": "SYNC"
      },
      "payload": {
          "params": {
              "Bucket": "prifina-user",
              "Key": "datamodels/oura/activity/summary/user=id_6145b3af07fa22f66456e20eca49e98bfe35/2022-09/summary.json",
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
              "s3Key": "oura/activity/summary",
              "objectName": "summary.json",
              "source": "S3",
              "id": "Oura/queryActivitySummary",
              "mockup": "queryActivitySummary",
              "queryType": "SYNC"
          }
      }
  }
  
  
  {
    "params": {
        "executionId": "0e2ac2fb-7cf8-40cf-89b7-ae81593b50c8",
        "args": {
            "input": {
                "dataconnector": "Oura/queryActivitySummariesAsync",
                "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
                "fields": [],
                "filter": "{\"s3::date\":{\"like\":\"2022-09\"}}",
                "appId": "866fscSq5Ae7bPgUtb6ffB",
                "execId": "8VbqNAgfYtfNHPBosGSyR5",
                "stage": "sandbox"
            },
            "sql": "SELECT * FROM core_athena_tables.oura_activity_summary where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day like '2022-09' order by day desc"
        },
        "source": "SANDBOX",
        "idToken": "eyJraWQiOiJRMDE4RDBpdjdqZmZDcGN4a2VLY2h4c0RoZGVBWVI4aW9FY2hpTEN3WGRjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJmNTMxZjU0MS0yMjU0LTRiNGEtYjQ0YS1mNjQwYzJhMmU2YjciLCJjb2duaXRvOmdyb3VwcyI6WyJERVYiLCJVU0VSIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV93MWZERkNrdFAiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsImNvZ25pdG86dXNlcm5hbWUiOiJ0ZXJvLXRlc3RpbmciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0YWhvbGEiLCJnaXZlbl9uYW1lIjoidGVybyIsIm9yaWdpbl9qdGkiOiIzZDA0MjdmNC0zMDYxLTQzZjctYWY2Yy01ZGIwMzRhZDY0ZmYiLCJhdWQiOiIxaWNtYTdkZXJsOXNpZmk3dWFhZXRvdXNqYSIsImV2ZW50X2lkIjoiNjY3YzBiMjItYWM0Yy00YjI2LWI3ZGItODcxNDk2Y2YzY2UyIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2NjMwNTQwODksImN1c3RvbTpzdGF0dXMiOiIxIiwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjYzMDg4MDU2LCJpYXQiOjE2NjMwODQ0NTYsImp0aSI6Ijc0NTY1MTg5LTNjMzQtNGI3Mi04ZDhjLWIxNGM1N2RlYzcxZCIsImVtYWlsIjoidHJvOTk5OSt0ZXN0M0BnbWFpbC5jb20ifQ.loyHxXrEQQHiHrXzoJjTMFQCmp3sm5kL0LtetTYYPK_TYVoWGe6fZcSP0H2K3WQRLTD1Fw2-H-dXwu0mIH4pzDzamb2ZDxdkpFg3VdSkSUmGgZ7fE93DyNUITPfh2SlqMMpjwl20OJkmmF6YsZYlYM4dMxA29biQrw58DBF_I1L-9w3TvfmzRlGgZvP4nkbR1SqTubLp19WXt8U0sxjBd_5VLflc8_J_iSI053KnPWvF3bqBcjXRTfgUhEouFp-h-Jn-L3VhNguyyzcdp52_BBmvf_0cFA33fVyx9_KU4Yr_gZuFwv4Po9mKJHLMPxaDWMsaHRFPnV6LmHj0F54RxA",
        "fields": []
    }
  }
  */
  const s3PayloadData = {
    "input": {
      "dataconnector": "Oura/queryActivitySummary",
      "userId": "f9ed356c68e4f64c4e3bde86e06ab8d4ac96",
      "fields": [],
      "filter": "{\"s3::date\":{\"=\":\"2022-09-09\"}}",
      "appId": "csd88KWnuft8fHfMrKSBAD",
      "execId": "9iUGJZaa8Q2ofufp1jYwh1",
      "stage": "sandbox"
    },
    "identity": {
      "accountId": "429117803886",
      "cognitoIdentityAuthProvider": "\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP\",\"cognito-idp.us-east-1.amazonaws.com/us-east-1_w1fDFCktP:CognitoSignIn:33e1fecc-caa6-4ac7-b838-9212c3af1f64\"",
      "cognitoIdentityAuthType": "authenticated",
      "cognitoIdentityId": "us-east-1:080e39f5-643b-42d9-bd03-4e55b161cad4",
      "cognitoIdentityPoolId": "us-east-1:1cb638b4-0f0c-4078-9fe0-4dbd3582783d",
      "sourceIp": [
        "73.202.150.58"
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
      "s3Key": "oura/activity/summary",
      "objectName": "summary.json",
      "source": "S3",
      "id": "Oura/queryActivitySummary"
    },
    "payload": {
      "params": {
        "Bucket": "prifina-user",
        "Key": "datamodels/oura/activity/summary/user=id_f9ed356c68e4f64c4e3bde86e06ab8d4ac96/2022-09-09/summary.json",
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
        "s3Key": "oura/activity/summary",
        "objectName": "summary.json",
        "source": "S3",
        "id": "Oura/queryActivitySummary"
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

  it("Parse Athena request payload", () => {
    const res = parsePayload(athenaPayloadData);
    console.log(res);
    expect(Object.keys(res)).toEqual(expect.arrayContaining(expected));

  });
  it("Parse S3 request payload", () => {
    const res = parsePayload(s3PayloadData);
    console.log(res);
    expect(Object.keys(res)).toEqual(expect.arrayContaining(expected));

  });
  it("Parse request S3 payload filter", () => {
    const { filter } = parsePayload(s3PayloadData);
    const { dataDate, filterCondition } = parseFilter(filter);

    expect(filterCondition).toEqual("=");
    expect(dataDate).toEqual(filter["s3::date"]["="]);
  });
  it("Parse request ATHENA payload filter", () => {
    const { filter } = parsePayload(athenaPayloadData);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);

    console.log(dataDate, endDate, startDate);
    expect(filterCondition).toEqual(">=");
    expect(dataDate).not.toEqual(startDate);
    expect(startDate).not.toEqual(endDate);
    // filter condition >=
    expect(dataDate).toEqual(endDate);
  });
  it("Get Mocked Sync data", () => {
    const { filter, format, fields } = parsePayload(s3PayloadData);
    const { dataDate, filterCondition } = parseFilter(filter);
    const res = getMockedData("@dynamic-data/oura-mockups", "SYNC", format, "ActivitySummary", "getActivityMockupData", { filter, filterCondition, dataDate }, ["summary_date", "score"]);
    //console.log(res);
    expect(res.summary_date).toBe(filter["s3::date"]["="]);
  });

  it("Get Mocked ASync data", () => {

    const { filter, format, fields, queryType,
      dataModel,
      mockupFunction,
      mockupModule } = parsePayload(athenaPayloadData);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);
    const res = getMockedData(mockupModule, queryType, format, dataModel, mockupFunction, { filter, filterCondition, startDate, endDate }, fields);
    //console.log(res);
    if (fields.length > 0) {
      expect(res[0]).toBe(fields.join(','));
    }
    const lastEntryDate = res.pop().split(',')[0];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
  });

  it.only("Get sandbox data", async () => {

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