const { parsePayload, parseFilter, getMockedData } = require("../src/data");

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
      "executionId": "f16e4ba2-7bdd-486a-ae41-6634f324e6b2",
      "args": {
        "input": {
          "dataconnector": "Oura/queryReadinessSummariesAsync",
          "userId": "f9ed356c68e4f64c4e3bde86e06ab8d4ac96",
          "fields": [
            "summary_date",
            "score_resting_hr"
          ],
          "filter": "{\"s3::date\":{\">=\":\"2022-09-04\"}}",
          "appId": "4TunCi3rwTFsN814u2BDqa",
          "execId": "jjmKx4y9z3WMSp4Sc2tygp",
          "stage": "sandbox"
        },
        "sql": "SELECT * FROM core_athena_tables.oura_readiness_summary where user='id_f9ed356c68e4f64c4e3bde86e06ab8d4ac96' and day >= '2022-09-04' order by day desc,period asc"
      },

      "source": "SANDBOX",
      "idToken": "eyJraWQiOiJRMDE4RDBpdjdqZmZDcGN4a2VLY2h4c0RoZGVBWVI4aW9FY2hpTEN3WGRjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIzM2UxZmVjYy1jYWE2LTRhYzctYjgzOC05MjEyYzNhZjFmNjQiLCJjb2duaXRvOmdyb3VwcyI6WyJERVYiLCJVU0VSIl0sImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfdzFmREZDa3RQIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJjb2duaXRvOnVzZXJuYW1lIjoiNTMyYzU5NGYtZWFhYy00ZDA5LTkyYWMtMmUwNTYzNWQ0NDQxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibW1sYW1waW5lbiIsImdpdmVuX25hbWUiOiJNYXJrdXMiLCJvcmlnaW5fanRpIjoiYjQxZmE5MmItZDBlOS00NjI3LWJmNzItNjkzMjczMGZiNzZhIiwiYXVkIjoiMWljbWE3ZGVybDlzaWZpN3VhYWV0b3VzamEiLCJldmVudF9pZCI6ImU2NzE1ZmIwLWNmYWQtNGQ5MS1iYmVkLTY5MmQwZWIzMGVkZCIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjYyNjcxNzk4LCJjdXN0b206c3RhdHVzIjoiMSIsImN1c3RvbTpwcmlmaW5hIjoiZjllZDM1NmM2OGU0ZjY0YzRlM2JkZTg2ZTA2YWI4ZDRhYzk2IiwicGhvbmVfbnVtYmVyIjoiKzE2NDY4MDE0MDU0IiwiZXhwIjoxNjYyODU0NDk2LCJpYXQiOjE2NjI4NTA4OTYsImZhbWlseV9uYW1lIjoiTGFtcGluZW4iLCJqdGkiOiJkY2VjNTYyNi1iYzBkLTRiNzctYjQzNC0yZTdmNmU1ZTY3YjMiLCJlbWFpbCI6Im1hcmt1c0BwcmlmaW5hLmNvbSJ9.JtOfsFz4Wmgub5DmzLLbmgSxsCfRiaXF8ZhG-EaV_zjfuv51xi8rf2ORxfNjCByk-un3tgGFYcghDleysqtbskH7KNic8PBKmmXA0RJFIX6hwFS5kLrAgXbgH0KWa40GY9wLuDzflcWrV9k2eX_RY1VWKjbeuNM0CqYsA6jAcevVGJSlsaCe_Mlefr1MEtvaA7beyRc5q34E4nca6s5-psv7B3aILuSY23c4ejFrfllJ6OfHFrziYnq0GkA375eVXmZL6yJjRslHYKT8DbSZVlsMWkgkRPsWJpklNJRoC8-VabjJxmOFJJ8F5tNv81at5wUpfYuMq01eOEW6HSJiDw",
      "fields": [
        "summary_date",
        "score_resting_hr"
      ]
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

  it.only("Get Mocked ASync data", () => {
    const { filter, format, fields } = parsePayload(athenaPayloadData);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);
    const res = getMockedData("@dynamic-data/oura-mockups", "ASYNC", format, "ReadinessSummaryAsync", "getReadinessMockupData", { filter, filterCondition, startDate, endDate }, fields);
    //console.log(res);
    expect(res[0]).toBe(fields.join(','));
    const lastEntryDate = res.pop().split(',')[0];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
  });

});  