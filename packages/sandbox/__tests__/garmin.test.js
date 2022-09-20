
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
      "executionId": "cbb9a7e1-51e8-4974-9329-4131a960d421",
      "args": {
        "input": {
          //"dataconnector": "Garmin/queryDailiesDataAsync",
          // "dataconnector": "Garmin/queryEpochsDataAsync",
          "dataconnector": "Garmin/queryPulseoxDataAsync",
          //"dataconnector": "Garmin/querySleepsDataAsync",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\">=\":\"2022-09-14\"}}",
          "appId": "x866fscSq5Ae7bPgUtb6ffB",
          "execId": "o7qdhasm76",
          "stage": "sandbox"
        },
        "sql": "SELECT * FROM core_athena_tables.garmin_dailies_data where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day >= '2022-09-14' order by day desc"
      },
      "source": "SANDBOX",
      "idToken": "eyJraWQiOiJuem9waFdjc0x1ZEdmeE4wXC9TVHJJblJaRjY2c2JsSFl3MjF1TDc1NkVoaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI4NGU3YWI2NS0wNzdjLTQ4NWEtYjBjYS05ZWU1ODE0YjUwNmQiLCJjb2duaXRvOmdyb3VwcyI6WyJVU0VSIiwiREVWIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206aWRlbnRpdHlQb29sIjoiZXUtd2VzdC0xOmI5YzJjNWNjLTZhYzAtNGIxOC05NGNjLTE3Y2MxZWFkN2U5MiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0w5Snp6d3IyViIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6IjlmODc0NDYyLTJlMDctNGI5MS05ZDUxLWFhNzk4OWJiZTVlNyIsInByZWZlcnJlZF91c2VybmFtZSI6InRhaG9sYSIsImdpdmVuX25hbWUiOiJURVJPIiwib3JpZ2luX2p0aSI6ImQ0YmI0Y2E2LTg3ZDMtNDk5OS1hODBmLTg2OWMyNmIxZTQ3YyIsImF1ZCI6IjF2bTVmNTRhaHM5MzFzNTNuYWFxNGdldG45IiwiZXZlbnRfaWQiOiIxOWM0YzU0NC0zN2JjLTQ5NmMtOTA3YS0wMTJlMjQ4MmQyMTgiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY2MTgzNjg3OCwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjYzNTYyOTE0LCJpYXQiOjE2NjM1NTkzMTQsImZhbWlseV9uYW1lIjoiQUhPTEEiLCJqdGkiOiI4MWE5ZTRiYi04NmFjLTQxYWUtOGMxMS00ZGZiYmNlYjZlM2YiLCJlbWFpbCI6InRybzk5OTkrbmV3QGdtYWlsLmNvbSJ9.BE7y_lKwzcBDRb8NwTLqeI_gz2QZRlFwFEKjmCSDnBBB8WBwUL7ZW0su4O0Uwkt0wrdhUcxtoCHs76EpeO1Mmv58cu9tWwJTVrTUM9Ug0rvdaDeqAtgaLB8AvqNN46oVxFz6gPFOla0iewz8MGDjWbZl6jcNDzSkBiBTF-saEDP84Nq6T0T1qVRM-3XWN1sWH5FIN0wu4lmJCA-Ye28dtqYz8WCa7ubEjffCeHON8ZLc3xwwstIURuNuFRF-L2P2E7khXnQAIEdu0RnR5owWJ6MPmEQFpzVyHUfXLj16VNCMyU0KbBB9SJ--jR3anUNrbPGxBWnFlWzcldoxoir_yg",
      "fields": [],
      "dataconnector": {
        "partitions": [
          "day",
          "period"
        ],
        "mockupModule": "@dynamic-data/garmin-mockups",
        "dataModel": "DailiesDataAsync",
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
    console.log(res);
    if (fields.length > 0) {
      expect(res[0]).toBe(fields.join(','));
    }

    //summaryId,calendardate,...
    const lastEntryDate = res.pop().split(',')[1];
    //console.log(endDate, lastEntryDate);
    expect(lastEntryDate).toBe(endDate);
  });

});
