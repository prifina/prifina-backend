const {
  awsSignedRequest,
  getCredentials,
  awsGetSignedUrl,
} = require("awsUtils.js");

const { getNewDate } = require("@dynamic-data/utils");
const {
  getActivityMockupData,
  getModelCSVHeader,
  getReadinessMockupData,
  getSleepMockupData,
} = require("@dynamic-data/oura-mockups");
//const OURA =require("@prifina/oura-data");

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

const dataconnectorFunctions = {
  "Oura/queryActivitySummary": {
    dataModel: "ActivitySummary",
    type: "SYNC",
  },
  "Oura/queryActivitySummariesAsync": {
    dataModel: "ActivitySummaryAsync",
    type: "ASYNC",
  },
  "Oura/queryReadinessSummary": {
    dataModel: "ReadinessSummary",
    type: "SYNC",
  },
  "Oura/queryReadinessSummariesAsync": {
    dataModel: "ReadinessSummaryAsync",
    type: "ASYNC",
  },
  "Oura/querySleepSummary": {
    dataModel: "SleepSummary",
    type: "SYNC",
  },
  "Oura/querySleepSummariesAsync": {
    dataModel: "SleepSummaryAsync",
    type: "ASYNC",
  },
};

async function createSandboxQuery(event, context, callback) {
  console.log("Received event ", JSON.stringify(event, 3));
  /*
     {
      "input": {
          "dataconnector": "Oura/queryActivitySummary",
          "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
          "fields": [],
          "filter": "{\"s3::date\":{\"=\":\"2022-01-28\"}}",
          "appId": "866fscSq5Ae7bPgUtb6ffB",
          "execId": "eY27WeQrVA6iZ7Q1Z3A3ik",
          "stage": "sandbox"
      },
    */
  /*
    
    {
      "params": {
          "executionId": "8b2b2500-da05-47c1-b782-d82990c94daf",
          "args": {
              "input": {
                  "dataconnector": "Oura/queryActivitySummariesAsync",
                  "userId": "6145b3af07fa22f66456e20eca49e98bfe35",
                  "fields": [],
                  "filter": "{\"s3::date\":{\">\":\"2022-01-30\"}}",
                  "appId": "866fscSq5Ae7bPgUtb6ffB",
                  "execId": "3ZpynNFrzfgJTqu1piVhVp",
                  "stage": "sandbox"
              },
              "sql": "SELECT * FROM core_athena_tables.oura_activity_summary where user='id_6145b3af07fa22f66456e20eca49e98bfe35' and day > '2022-01-30' order by day desc"
          },
          "source": "SANDBOX",
          "idToken": "eyJraWQiOiJuem9waFdjc0x1ZEdmeE4wXC9TVHJJblJaRjY2c2JsSFl3MjF1TDc1NkVoaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI4NGU3YWI2NS0wNzdjLTQ4NWEtYjBjYS05ZWU1ODE0YjUwNmQiLCJjb2duaXRvOmdyb3VwcyI6WyJVU0VSIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206aWRlbnRpdHlQb29sIjoiZXUtd2VzdC0xOmI5YzJjNWNjLTZhYzAtNGIxOC05NGNjLTE3Y2MxZWFkN2U5MiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0w5Snp6d3IyViIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6IjlmODc0NDYyLTJlMDctNGI5MS05ZDUxLWFhNzk4OWJiZTVlNyIsInByZWZlcnJlZF91c2VybmFtZSI6InRhaG9sYSIsImdpdmVuX25hbWUiOiJURVJPIiwib3JpZ2luX2p0aSI6IjYzMzgwYWU3LTliNzEtNDI0Zi04ZmYxLTRkOWNlNmUzYTc4NiIsImF1ZCI6IjF2bTVmNTRhaHM5MzFzNTNuYWFxNGdldG45IiwiZXZlbnRfaWQiOiIzNGE4MGRmMC00NDI4LTQzZWEtYWU3ZS0xYmY0YzFmZGQwZWIiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY0MzAzNjEyMSwiY3VzdG9tOnByaWZpbmEiOiI2MTQ1YjNhZjA3ZmEyMmY2NjQ1NmUyMGVjYTQ5ZTk4YmZlMzUiLCJwaG9uZV9udW1iZXIiOiIrMzU4NDA3MDc3MTAyIiwiZXhwIjoxNjQzNzg1MTU5LCJpYXQiOjE2NDM3ODE1NTksImZhbWlseV9uYW1lIjoiQUhPTEEiLCJqdGkiOiI1MTUxYjIxMy1lOTk1LTRlZmQtODZhYS03MDhmNDU2NWE0ZTIiLCJlbWFpbCI6InRybzk5OTlAZ21haWwuY29tIn0.u94gJKr3eKOjVOf0SPsJKDvwNTnN8GFL-B5IxJLuT2ATDQ3f0CoRck_7jQVuH5o5o2P3Mno_yHbs35q1qgwlp9syTbh_7LtfIgN9BrnkIU34i__5NHSggdSDKxHC3wWBWZ2MLjA4JlI2VFaeCAz9e6IpRCGAPAFMUlGZ0HB4NI2pa0Xg1Q-YRMVPRcnT41o6sONVUvjFsnapjHs24b2yELSUgEzi4uwnDYvEASFg4CQfSnc_h1-cnyQ-low-4VR45VJTlQvkQE19uVLZGE0iN-qXYYs42CUJeFP-xvHhFnxKM1Chwe3O3p2fTij_-sCfb14R8hZndwOoUJp6o6ilJw",
          "fields": []
      }
  }
    */

  let dataconnector = "";
  let filter = "";
  let fields = [];
  let format = "JSON"; // CSV
  if (event.hasOwnProperty("params")) {
    dataconnector = event.params.args.input.dataconnector;
    filter =
      event.params.args.input.filter.length > 0
        ? JSON.parse(event.params.args.input.filter)
        : "";
    fields = event.params.args.input.fields;
    format = "CSV";
  } else if (event.hasOwnProperty("input")) {
    dataconnector = event.input.dataconnector;
    filter =
      event.input.filter.length > 0 ? JSON.parse(event.input.filter) : "";
    fields = event.input.fields;
    format = event.payload.dataconnector.input;
  }

  const dataModel = dataconnectorFunctions[dataconnector].dataModel;
  const dataType = dataconnectorFunctions[dataconnector].type;

  console.log("DATA ", dataModel, dataType);

  try {
    let jsonContent = [];
    let dataDate = new Date().toISOString().split("T")[0];

    // SYNC == json object...
    if (dataType === "SYNC") {
      if (filter !== "" && filter.hasOwnProperty("s3::date")) {
        dataDate = filter["s3::date"]["="];
      }
      console.log(dataModel);
      //let mockupData = dataModels[dataModel].data;
      //const mockupModel = dataModels[dataModel].mockup;
      let mockupData = {};
      if (dataModel === "ActivitySummary") {
        mockupData = getActivityMockupData(dataType, dataModel, dataDate);
      }
      if (dataModel === "ReadinessSummary") {
        mockupData = getReadinessMockupData(dataType, dataModel, dataDate);
      }
      if (dataModel === "SleepSummary") {
        mockupData = getSleepMockupData(dataType, dataModel, dataDate);
      }

      console.log("MOCKUP ", mockupData);
      //console.log(ActivitySummaryAsync);

      jsonContent = [mockupData];
    }
    if (dataType === "ASYNC") {
      let startDate = dataDate;
      let endDate = dataDate;
      let filterCondition = "=";
      console.log("FILTER ", filter, typeof filter);
      if (filter !== "" && filter.hasOwnProperty("s3::date")) {
        //dataDate = filter["s3::date"]["="];
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

      let mockupDataHeader = getModelCSVHeader(dataModel);
      jsonContent.push(mockupDataHeader.join(","));
      /*
      let mockupDataRow = dataModels[dataModel].data[1].split(",");
      const mockupModel = dataModels[dataModel].mockup;
      let mockupData = {};
      mockupDataHeader.forEach((k, i) => {
        mockupData[k] = mockupDataRow[i];
      });
      */
      let mockupData = {};

      if (filterCondition === ">" || filterCondition === ">=") {
        do {
          if (dataModel === "ActivitySummaryAsync") {
            mockupData = getActivityMockupData(dataType, dataModel, startDate);
          }
          if (dataModel === "ReadinessSummaryAsync") {
            mockupData = getReadinessMockupData(dataType, dataModel, startDate);
          }
          if (dataModel === "SleepSummaryAsync") {
            mockupData = getSleepMockupData(dataType, dataModel, startDate);
          }

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
          //console.log("FLD ",c);
          //console.log("COL ",header.findIndex(col => col === c));
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
      const credParams = {
        idToken: event.params.idToken,
        userPoolRegion: process.env.USER_POOL_REGION,
        userPoolId: process.env.USER_POOL_ID,
        userIdPool: process.env.USER_ID_POOL,
      };

      const currentCredentials = await getCredentials(credParams);

      console.log("CREDS ", currentCredentials);
      const post_body = {
        query: mutation,
        operationName: "athenaData",
        variables: {
          id: event.params.args.input.userId,
          appId: event.params.args.input.appId,
          data: JSON.stringify({
            content: jsonContent,
            dataconnector: event.params.args.input.dataconnector,
          }),
        },
      };
      await awsSignedRequest({
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
    console.log("RETURN ", jsonContent);
    return {
      content: jsonContent,
      next: null,
    };
  } catch (e) {
    console.log("ERR ", e);

    return { error: JSON.stringify(e) };
  }

  //context.done(null, "Success");
}

exports.createSandboxQuery = createSandboxQuery;
