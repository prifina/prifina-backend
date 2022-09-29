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
  let mockupContent = undefined;
  let mockupData = {};
  /*
  fields = ['calendardate',
    'starttimeinseconds',
    'durationinseconds',
    'starttimeoffsetinseconds',
    'timeoffsetspo2values',];
    */
  /*
  
    if (dataType === "ASYNC") {
      const mockupDataRow = dataModels[dataModel].data[1].split("\t");
      const mockupDataHeader = dataModels[dataModel].data[0].split("\t");
      mockupDataHeader.forEach((k, i) => {
        mockupData[k] = mockupDataRow[i];
      });
  */

  const getData = require(dataConnector)[mockFunction];
  if (dataType === "SYNC") {
    mockupData = getData(dataModel, filter.dataDate);
    mockupContent = Object.assign({}, mockupData);

    if (fields.length > 0) {
      let fieldsData = {};

      fields.forEach(key => {
        fieldsData[key] = mockupContent[key];
      });
      mockupContent = fieldsData;
    }
  }
  if (dataType === "ASYNC") {

    let startDate = filter.startDate;
    let endDate = filter.endDate;
    const filterCondition = filter.filterCondition;
    mockupContent = [];

    //mockupData = getData(dataType, dataModel, filter.dataDate);
    if (filterCondition === ">" || filterCondition === ">=") {
      do {

        mockupData = getData(dataModel, startDate);
        //console.log("MOCK ", startDate,);
        //mockupContent.push({ pvm: startDate, data: mockupData });
        let newData = Object.assign({}, mockupData);
        if (fields.length > 0) {
          let fieldsData = {};

          fields.forEach(key => {
            fieldsData[key] = mockupData[key];
          });
          newData = fieldsData;
        }
        /*
        const newData = mockupDataHeader
          .map((col) => {
            return mockupData[col];
          })
          .join(",");
          */
        mockupContent.push(newData);
        startDate = getNewDate(startDate, 1, "DATE");
        //console.log("LOOP ", startDate);


      } while (startDate <= endDate);

    }
    if (filterCondition === "<" || filterCondition === "<=") {
      // get start date, end date -30 
      startDate = getNewDate(endDate, -30, "DATE");
      do {

        mockupData = getData(dataModel, startDate);
        let newData = mockupData;
        if (fields.length > 0) {
          let fieldsData = {};

          fields.forEach(key => {
            fieldsData[key] = mockupData[key];
          });
          newData = fieldsData;
        }
        mockupContent.push(newData);
        startDate = getNewDate(startDate, 1, "DATE");
      } while (startDate <= endDate);
    }
    /*
    if (fields.length > 0) {
      const header = mockupContent[0].split(",");
      const cols = fields.map((c, i) => {
        return header.findIndex((col) => col === c);
      });
      //console.log("HEADER ", header);
      //console.log("COLS ", cols);
      let fieldsData = [];
      mockupContent.forEach((row) => {
        const r = cols.map((c) => {
          return row.split(",")[c];
        });
        fieldsData.push(r.join(","));
      });
      //console.log("NEW ",fieldsData);
      mockupContent = fieldsData;
    }
    */

  }

  //  console.log(mockupContent.length, mockupContent[0].calendardate, mockupContent[1].calendardate);

  //console.log("DATA ", mockupContent);
  if (dataType === "ASYNC") {
    const { getModelCSVHeader } = require(dataConnector);
    console.log("CSV HEADER", getModelCSVHeader, dataModel);
    let mockupDataHeader = getModelCSVHeader(dataModel + "Async");
    // console.log(mockupDataHeader);
    const csvData = [];
    let header = [];
    if (fields.length > 0) {
      header = fields.filter((c, i) => {
        return mockupDataHeader.findIndex((col) => col === c);
      });
      csvData.push(header.join('\t'));
    } else {
      csvData.push(mockupDataHeader.join('\t'));
    }
    /*
    const header = mockupContent[0].split(",");
    const cols = fields.map((c, i) => {
      return header.findIndex((col) => col === c);
    });
    */
    //mockupContent.push(mockupDataHeader.join(","));

    //console.log(mockupContent.length, mockupContent[0].calendardate, mockupContent[1].calendardate);

    for (let row = 0; row < mockupContent.length; row++) {
      let rowData = [];
      //console.log(mockupContent[row].calendardate);
      Object.keys(mockupContent[row]).forEach(k => {
        if (isObject(mockupContent[row][k]) || Array.isArray(mockupContent[row][k])) {
          // is array transformation same as json...
          //console.log(JSON.stringify(mockupContent[0][k]).replace(/"/g, "").replace(/:/g, "="));
          //rowData.push(JSON.stringify(mockupContent[row][k]).replace(/"/g, "").replace(/:/g, "="))
        } else {
          rowData.push(mockupContent[row][k])
        }
      });
      //console.log(rowData)
      csvData.push(rowData.join("\t"));
    }
    // console.log(csvData);
    mockupContent = csvData;

  }

  return mockupContent;
}

const isObject = (value) => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
};
/*
"x3a9c8fe-61c8ca74-8340\t2021-12-27\t33600\t1640548980\t7200\t0\t0\t28260\t5340\t60
\t{deep=null,
   light=[{starttimeinseconds=1640548980, endtimeinseconds=1640554560},
   {starttimeinseconds=1640557080, endtimeinseconds=1640559720}, {starttimeinseconds=1640559960, endtimeinseconds=1640560560},
    {starttimeinseconds=1640561700, endtimeinseconds=1640561880}, {starttimeinseconds=1640562120, endtimeinseconds=1640566260}, 
    {starttimeinseconds=1640566320, endtimeinseconds=1640574840}, {starttimeinseconds=1640575020, endtimeinseconds=1640575200},
     {starttimeinseconds=1640575500, endtimeinseconds=1640579640}, {starttimeinseconds=1640580360, endtimeinseconds=1640582640}], 

     rem=[{starttimeinseconds=1640554560, endtimeinseconds=1640557080}, {starttimeinseconds=1640559720, endtimeinseconds=1640559960}, 
      {starttimeinseconds=1640560560, endtimeinseconds=1640561700}, {starttimeinseconds=1640561880, endtimeinseconds=1640562120}, 
      {starttimeinseconds=1640574840, endtimeinseconds=1640575020}, {starttimeinseconds=1640575200, endtimeinseconds=1640575500},
       {starttimeinseconds=1640579640, endtimeinseconds=1640580360}],
        awake=[{starttimeinseconds=1640566260, endtimeinseconds=1640566320}]}

       \tENHANCED_TENTATIVE\t{23040=100, 19200=93, 11520=94, 18180=94, 22020=92, 17160=94, 21000=92, 24840=93, 19980=92, 23820=93, 12300=93,
         22800=96, 11280=91, 18960=92, 21780=94, 17940=93, 13080=95, 16920=94, 20760=91, 24600=93, 19740=93, 23580=100, 12060=94, 
         11040=93, 22560=89, 18720=95, 21540=93, 17700=95, 12840=93, 24360=93, 16680=96, 20520=92, 19500=92, 11820=94, 23340=96,
          18480=94, 10800=95, 22320=85, 21300=91, 17460=96, 12600=92, 24120=92, 20280=92, 16440=94, 11580=92, 19260=92, 23100=98,
           22080=89, 18240=94, 21060=91, 24900=93, 17220=94, 20040=92, 23880=92, 12360=94, 11340=91, 22860=100, 19020=92,
            18000=94, 21840=95, 24660=93, 16980=94, 20820=92, 23640=100, 12120=93, 19800=93, 11100=93, 18780=96, 22620=95,
             17760=95, 21600=94, 24420=94, 20580=92, 16740=95, 12900=91, 19560=92, 23400=98, 11880=94, 18540=93, 10860=92,
              22380=85, 21360=92, 17520=95, 20340=92, 12660=91, 16500=96, 24180=91, 23160=100, 19320=91, 11640=93, 18300=94,
               22140=87, 17280=95, 21120=92, 24960=91, 20100=92, 23940=90, 12420=94, 22920=100, 19080=92, 11400=93, 21900=95,
                18060=94, 17040=91, 20880=92, 24720=92, 19860=93, 23700=100, 12180=94, 11160=93, 22680=98, 18840=95, 21660=95,
                 17820=95, 12960=88, 16800=96, 24480=94, 20640=93, 19620=92, 11940=94, 23460=98, 10920=93, 22440=83, 18600=94,
                  21420=92, 17580=95, 12720=91, 24240=92, 16560=96, 20400=91, 19380=93, 11700=93, 23220=99, 18360=94, 22200=88,
                   25020=91, 21180=90, 17340=95, 24000=91, 20160=92, 12480=94, 11460=93, 22980=100, 19140=92, 18120=95, 21960=94,
                    24780=93, 20940=93, 13260=93, 17100=93, 23760=96, 12240=92, 19920=92, 11220=92, 22740=100, 18900=93, 17880=95,
                     21720=95, 24540=93, 16860=93, 20700=92, 13020=96, 19680=93, 23520=100, 12000=93, 18660=95, 22500=84, 10980=91,
                      21480=92, 17640=95, 20460=93, 24300=92, 12780=91, 16620=96, 23280=98, 19440=93, 11760=93, 18420=94, 10740=93,
                       22260=86, 21240=92, 17400=96, 25080=91, 20220=92, 12540=93, 24060=92}",

                       */

/*
function mergeDeep(...objects) {
  const isObject = obj => obj && typeof obj === "object";

  return objects.reduce((prev, obj) => {
    Object.keys(obj).forEach(key => {
      const pVal = prev[key];
      const oVal = obj[key];

      if (Array.isArray(pVal) && Array.isArray(oVal)) {
        prev[key] = pVal.concat(...oVal);
      } else if (isObject(pVal) && isObject(oVal)) {
        prev[key] = mergeDeep(pVal, oVal);
      } else {
        prev[key] = oVal;
      }
    });

    return prev;
  }, {});
}
*/

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
