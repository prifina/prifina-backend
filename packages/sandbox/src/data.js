const {
  awsUtils
} = require("@prifina-backend/shared");
const { getNewDate } = require("@dynamic-data/utils");


const apiRegion = process.env.USER_REGION;
const apiEndpoint = process.env.ENDPOINT;

const mutation = `mutation athenaData($id: String!,$appId: String!,$data: String) {
  athenaData(id: $id,appId:$appId,data: $data) {
    id
    appId
    data
  }
}
`;

function parseFilter(filter) {
  let dataDate = new Date().toISOString().split("T")[0];
  let startDate = dataDate;
  let endDate = dataDate;
  let filterCondition = "="

  if (filter !== "" && filter?.["s3::date"] && filter["s3::date"]?.["="]) {
    dataDate = filter["s3::date"]["="];
  }

  if (filter !== "" && filter?.["s3::date"] && !filter["s3::date"]?.["="]) {

    Object.keys(filter["s3::date"]).forEach((c) => {
      filterCondition = c;
      switch (c) {
        case ">":
          startDate = getNewDate(filter["s3::date"][">"], 1, "DATE");
          break;
        case "<":
          endDate = getNewDate(filter["s3::date"]["<"], -1, "DATE");
          startDate = null;
          break;
        case ">=":
          startDate = filter["s3::date"][">="];
          break;
        case "<=":
          endDate = filter["s3::date"]["<="];
          startDate = null;
          break;
        case "like":
        case "in":
        case "between":
        case "!=":
          break;
      }
    });
  }


  return { dataDate, startDate, endDate, filterCondition }
}
function parsePayload(payload) {

  let dataconnector = "";
  let filter = "";
  let fields = [];
  let format = "JSON"; // CSV
  let queryType = "SYNC";
  let dataModel = "";
  let mockupFunction = "";
  let mockupModule = "";
  //console.log("PAYLOAD ", Object.keys(payload))
  // source ATHENA
  if (payload.hasOwnProperty("params")) {
    dataconnector = payload.params.args.input.dataconnector;
    filter =
      payload.params.args.input.filter.length > 0
        ? JSON.parse(payload.params.args.input.filter)
        : "";
    fields = payload.params.args.input.fields;
    format = "CSV";
    queryType = payload.params.dataconnector.queryType;
    dataModel = payload.params.dataconnector.dataModel;
    mockupFunction = payload.params.dataconnector.mockupFunction;
    mockupModule = payload.params.dataconnector.mockupModule;
  }
  // source S3
  if (payload.hasOwnProperty("input")) {
    dataconnector = payload.input.dataconnector;
    filter =
      payload.input.filter.length > 0 ? JSON.parse(payload.input.filter) : "";
    fields = payload.input.fields;
    format = payload.payload.dataconnector.input;
    queryType = payload.dataconnector.queryType;
    dataModel = payload.dataconnector.dataModel;
    mockupFunction = payload.dataconnector.mockupFunction;
    mockupModule = payload.dataconnector.mockupModule;
  }


  return { dataconnector, filter, fields, format, queryType, dataModel, mockupFunction, mockupModule }
}
function getMockedData(dataConnector, dataType, format, dataModel, mockFunction, filter, fields) {

  console.log(dataConnector, dataType, format, dataModel, mockFunction, filter, fields);
  let jsonContent = undefined;
  let mockupData = {};

  const getData = require(dataConnector)[mockFunction];
  if (dataType === "SYNC") {
    mockupData = getData(dataType, dataModel, filter.dataDate);
    jsonContent = mockupData;

    if (fields.length > 0) {
      let fieldsData = {};

      fields.forEach(key => {
        fieldsData[key] = jsonContent[key];
      });
      jsonContent = fieldsData;
    }
  }
  if (dataType === "ASYNC") {
    const { getModelCSVHeader } = require(dataConnector);
    //console.log("CSV HEADER", getModelCSVHeader, dataModel);
    let mockupDataHeader = getModelCSVHeader(dataModel);
    let startDate = filter.startDate;
    let endDate = filter.endDate;
    const filterCondition = filter.filterCondition;
    jsonContent = [];
    jsonContent.push(mockupDataHeader.join(","));
    //mockupData = getData(dataType, dataModel, filter.dataDate);
    if (filterCondition === ">" || filterCondition === ">=") {
      do {

        mockupData = getData(dataType, dataModel, startDate);
        //console.log("MOCK ", startDate, mockupData);
        //jsonContent.push({ pvm: startDate, data: mockupData });
        const newData = mockupDataHeader
          .map((col) => {
            return mockupData[col];
          })
          .join(",");
        jsonContent.push(newData);
        startDate = getNewDate(startDate, 1, "DATE");
        console.log("LOOP ", startDate);

      } while (startDate <= endDate);

    }
    if (filterCondition === "<" || filterCondition === "<=") {
      // get start date, end date -30 
      startDate = getNewDate(endDate, -30, "DATE");
      do {

        mockupData = getData(dataType, dataModel, startDate);

        //jsonContent.push({ pvm: startDate, data: mockupData });
        const newData = mockupDataHeader
          .map((col) => {
            return mockupData[col];
          })
          .join(",");
        jsonContent.push(newData);
        startDate = getNewDate(startDate, 1, "DATE");
      } while (startDate <= endDate);
    }

    if (fields.length > 0) {
      const header = jsonContent[0].split(",");
      const cols = fields.map((c, i) => {
        return header.findIndex((col) => col === c);
      });
      //console.log("HEADER ", header);
      //console.log("COLS ", cols);
      let fieldsData = [];
      jsonContent.forEach((row) => {
        const r = cols.map((c) => {
          return row.split(",")[c];
        });
        fieldsData.push(r.join(","));
      });
      //console.log("NEW ",fieldsData);
      jsonContent = fieldsData;
    }

  }


  return jsonContent;
}

async function getSandboxData(payload) {

  console.log("ENV ", process.env);

  try {
    const { filter, format, fields, queryType,
      dataModel,
      mockupFunction,
      mockupModule } = parsePayload(payload);
    const { dataDate, startDate, endDate, filterCondition } = parseFilter(filter);
    let mockContent = getMockedData(mockupModule, queryType, format, dataModel, mockupFunction, { filter, filterCondition, startDate, endDate, dataDate }, fields)

    if (queryType === "ASYNC") {
      const credParams = {
        idToken: payload.params.idToken,
        userPoolRegion: process.env.USER_POOL_REGION,
        userPoolId: process.env.USER_POOL_ID,
        userIdPool: process.env.USER_ID_POOL,
      };
      const currentCredentials = await awsUtils.getCredentials(credParams);

      console.log("CREDS ", currentCredentials);
      const post_body = {
        query: mutation,
        operationName: "athenaData",
        variables: {
          id: payload.params.args.input.userId,
          appId: payload.params.args.input.appId,
          data: JSON.stringify({
            content: mockContent,
            dataconnector: payload.params.args.input.dataconnector,
          }),
        },
      };
      await awsUtils.awsSignedRequest({
        request_api: apiEndpoint,
        region: apiRegion,
        //credentials: defaultProvider(),
        credentials: () => {
          return currentCredentials;
        },
        post_body: post_body,
        service: "appsync",
      });
    }
    //console.log("RETURN ", mockContent);
    return {
      content: mockContent,
      next: null,
    };
  } catch (e) {
    console.log("ERR ", e);

    return { error: JSON.stringify(e) };
  }

}
module.exports = {
  parsePayload,
  parseFilter,
  getMockedData,
  getSandboxData
}
/*
"input": {
  "dataconnector": "Oura/queryActivitySummary",
  "userId": "f9ed356c68e4f64c4e3bde86e06ab8d4ac96",
  "fields": [],
  "filter": "{\"s3::date\":{\"=\":\"2022-09-09\"}}",
  "appId": "csd88KWnuft8fHfMrKSBAD",
  "execId": "9iUGJZaa8Q2ofufp1jYwh1",
  "stage": "sandbox"
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

{
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
*/
