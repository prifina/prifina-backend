
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
      "executionId": "65dd983e-a5f7-49bd-be3c-d4a24d8637a0",
      "args": {
        "input": {
          "dataconnector": "Garmin/queryPulseoxDataAsync",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\">=\":\"2022-09-18\"}}",
          "appId": "x866fscSq5Ae7bPgUtb6ffB",
          "execId": "kbxcpq85wj",
          "stage": "sandbox"
        },
        "sql": "SELECT * FROM core_athena_tables.garmin_pulseox_data where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day >= '2022-09-18' order by day desc"
      },
      "source": "SANDBOX",
      "idToken": "eyJraWQiOiJuem9waFdjc0x1ZEdmeE4wXC9TVHJJblJaRjY2c2JsSFl3MjF1TDc1NkVoaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI4NGU3YWI2NS0wNzdjLTQ4NWEtYjBjYS05ZWU1ODE0YjUwNmQiLCJjb2duaXRvOmdyb3VwcyI6WyJVU0VSIiwiREVWIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206aWRlbnRpdHlQb29sIjoiZXUtd2VzdC0xOmI5YzJjNWNjLTZhYzAtNGIxOC05NGNjLTE3Y2MxZWFkN2U5MiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0w5Snp6d3IyViIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6IjlmODc0NDYyLTJlMDctNGI5MS05ZDUxLWFhNzk4OWJiZTVlNyIsInByZWZlcnJlZF91c2VybmFtZSI6InRhaG9sYSIsImdpdmVuX25hbWUiOiJURVJPIiwib3JpZ2luX2p0aSI6ImQ0YmI0Y2E2LTg3ZDMtNDk5OS1hODBmLTg2OWMyNmIxZTQ3YyIsImF1ZCI6IjF2bTVmNTRhaHM5MzFzNTNuYWFxNGdldG45IiwiZXZlbnRfaWQiOiIxOWM0YzU0NC0zN2JjLTQ5NmMtOTA3YS0wMTJlMjQ4MmQyMTgiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY2MTgzNjg3OCwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjYzNzQwNzEwLCJpYXQiOjE2NjM3MzcxMTEsImZhbWlseV9uYW1lIjoiQUhPTEEiLCJqdGkiOiI2ODI1ODAzYi1iNzI3LTRmMzMtYjY5OC0yMWExZmZiOWUyNmIiLCJlbWFpbCI6InRybzk5OTkrbmV3QGdtYWlsLmNvbSJ9.WfzV9Mmj0zVgmmA1M6BpS2hE-1nMurPi7bH10TBIN04asC23Xjr4LzvIjl07ociGMFlhvgnz1ayEYJ5rJdoDrfXL6Ws4qvCOCpv11eS0gHjp7dBa7mQAV9ROngJ8yIohEHEePIz7mJiEfsSkSOlGzRedoZt0vHzzXieWOGkFKNhRv9fWkQmR6mOVfUDvs9LpyhI8iQ5zzjKtncTE3-kpL7p15LX0xg9Zme86NQXBJx3zN-sQvwR44QWk6IEuRkc9z2cPZ9Os4sjVJ3X-TNyFXs9TPY42MblhgLDA9dgVCcHQYGs86aja0edTjyPrGghSWwV5h8mnoQi_QtcyaHs7lA",
      "fields": [],
      "dataconnector": {
        "partitions": [
          "day",
          "period"
        ],
        "mockupModule": "@dynamic-data/garmin-mockups",
        "dataModel": "PulseoxData",
        "orderBy": "day desc",
        "source": "ATHENA",
        "id": "Garmin/queryPulseoxDataAsync",

        "mockupFunction": "getPulseoxMockupData",
        "mockup": "queryPulseoxDataAsync",
        "queryType": "ASYNC",
        "sql": "SELECT * FROM core_athena_tables.garmin_pulseox_data"
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


  it("Get Mocked ASync data", () => {

    const { filter, format, fields, queryType,
      dataModel,
      mockupFunction,
      mockupModule } = parsePayload(athenaPayloadData);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);
    const res = getMockedData(mockupModule, queryType, format, dataModel, mockupFunction, { filter, filterCondition, startDate, endDate }, fields);
    //console.log(res);
    if (fields.length > 0) {
      expect(res[0]).toBe(fields.join('/t'));
    }

    //summaryId,calendardate,...
    const lastEntryDate = res.pop().split('/t')[1];
    console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
  });

  it.only("Get async sandbox data", async () => {

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
    const lastEntryDate = jsonContent.pop().split('/t')[1];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);

  });
});
