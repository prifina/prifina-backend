
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
  const athenaPayloadData = {
    "params": {
      "executionId": "3e8f2cbc-b1ac-4a90-b1b5-91513e7a9dc4",
      "args": {
        "input": {
          "dataconnector": "Garmin/queryDailiesDataAsync",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\">=\":\"2022-09-20\"}}",
          "appId": "x866fscSq5Ae7bPgUtb6ffB",
          "execId": "828upk7qix",
          "stage": "sandbox"
        },
        "sql": "SELECT * FROM core_athena_tables.garmin_dailies_data where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day >= '2022-09-20' order by day desc"
      },
      "source": "SANDBOX",
      "idToken": "eyJraWQiOiJuem9waFdjc0x1ZEdmeE4wXC9TVHJJblJaRjY2c2JsSFl3MjF1TDc1NkVoaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI4NGU3YWI2NS0wNzdjLTQ4NWEtYjBjYS05ZWU1ODE0YjUwNmQiLCJjb2duaXRvOmdyb3VwcyI6WyJVU0VSIiwiREVWIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206aWRlbnRpdHlQb29sIjoiZXUtd2VzdC0xOmI5YzJjNWNjLTZhYzAtNGIxOC05NGNjLTE3Y2MxZWFkN2U5MiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0w5Snp6d3IyViIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6IjlmODc0NDYyLTJlMDctNGI5MS05ZDUxLWFhNzk4OWJiZTVlNyIsInByZWZlcnJlZF91c2VybmFtZSI6InRhaG9sYSIsImdpdmVuX25hbWUiOiJURVJPIiwib3JpZ2luX2p0aSI6ImQ0YmI0Y2E2LTg3ZDMtNDk5OS1hODBmLTg2OWMyNmIxZTQ3YyIsImF1ZCI6IjF2bTVmNTRhaHM5MzFzNTNuYWFxNGdldG45IiwiZXZlbnRfaWQiOiIxOWM0YzU0NC0zN2JjLTQ5NmMtOTA3YS0wMTJlMjQ4MmQyMTgiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY2MTgzNjg3OCwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjYzODYzNDgwLCJpYXQiOjE2NjM4NTk4ODAsImZhbWlseV9uYW1lIjoiQUhPTEEiLCJqdGkiOiIwMzZjZGE3Ni1mYzgyLTQ4ZjUtOTJkOS0xZjA0ZWEyZTMxNjIiLCJlbWFpbCI6InRybzk5OTkrbmV3QGdtYWlsLmNvbSJ9.CQ_DmjDOSWRiBdwBg2aQaGpn47ekkkUViGf3pKnO32lboms7D4Ux3M2HfnOEYJsJNAz1BMJuA1THyrFN8f0Qc5DDs8XHbVhTS-8UgLBDVqRD07W5tM8KguBW_1gbd4Tmgr9fnVxBfOAdPWs4e2Tffyw1-vih1Qxacv9GE1P76ezptbwR6BJuBSfrVDbeyc5jwVwkzFOobuW4NawFzSKFKM6335UDp4_llJUBnveNKVkoeTstlAlxKd7v7N4ddCQZpEqCiZLmoCDdsYhLX6aRNg2VZMDp_9r1LVqRDQCA2m0mfX5zIsVaYGF5GdleGWnNewS9ws5-dgiTJ2SP0YSWPw",
      "fields": [],
      "dataconnector": {
        "partitions": [
          "day",
          "period"
        ],
        "mockupModule": "@dynamic-data/garmin-mockups",
        "dataModel": "DailiesData",
        "orderBy": "day desc",
        "source": "ATHENA",
        "id": "Garmin/queryDailiesDataAsync",
        "mockupFunction": "getDailiesMockupData",
        "mockup": "queryDailiesDataAsync",
        "queryType": "ASYNC",
        "sql": "SELECT * FROM core_athena_tables.garmin_dailies_data"
      }
    }
  }

  const expected = ['dataconnector', 'filter', 'fields', 'format'];
  const expectedAthena = ['dataconnector', 'filter', 'fields', 'format', 'queryType', 'dataModel', 'mockupFunction', 'mockupModule'];

  it("Parse Athena request payload", () => {
    const res = parsePayload(athenaPayloadData);
    console.log(res);
    expect(Object.keys(res)).toEqual(expect.arrayContaining(expectedAthena));

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


  it.only("Get Mocked ASync data", () => {

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
    /*
        console.log(res[0].split('/t')[1]);
        console.log(res[1].split('/t')[1]);
        console.log(res[2].split('/t')[1]);
    */
    //summaryId,calendardate,...
    const lastEntryDate = res.pop().split(',')[1];
    console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
  });

  it("Get async sandbox data", async () => {

    const { filter } = parsePayload(athenaPayloadData);
    const { endDate, } = parseFilter(filter);

    awsUtils.getCredentials.mockResolvedValue({
      accessKeyId: "AKID",
      secretAccessKey: "SECRET",
      region: "us-east-1",
    });
    awsUtils.awsSignedRequest.mockResolvedValue({});

    const res = await getSandboxData(athenaPayloadData);
    console.log(res);
    const jsonContent = res.content
    const lastEntryDate = jsonContent.pop().split(',')[1];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);

  });
});
