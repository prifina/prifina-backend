const { getNewDate } = require("@dynamic-data/utils");

const isObject = (value) => {
  return typeof value === "object" && value !== null && !Array.isArray(value);
};

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
  //const test = require("@dynamic-data/garmin-mockups");
  //console.log("GARMIN", test);

  const getData = dataConnector[mockFunction];
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
    const { getModelCSVHeader } = dataConnector;
    console.log("CSV HEADER", getModelCSVHeader, dataModel);
    let mockupDataHeader = getModelCSVHeader(dataModel + "Async");
    console.log(mockupDataHeader);
    const csvData = [];
    let header = [];
    if (fields.length > 0) {
      header = fields.filter((c, i) => {
        return mockupDataHeader.findIndex((col) => col === c) > -1;

      });
      csvData.push(header.join(','));
    } else {
      csvData.push(mockupDataHeader.join(','));
    }
    console.log("HEADER ", header, csvData);
    /*
    const header = mockupContent[0].split(",");
    const cols = fields.map((c, i) => {
      return header.findIndex((col) => col === c);
    });
    */
    //mockupContent.push(mockupDataHeader.join(","));

    //console.log(mockupContent.length, mockupContent[0].calendardate, mockupContent[1].calendardate);

    for (let row = 0; row < mockupContent.length; row++) {
      console.log("ROW ", mockupContent[row])
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
      csvData.push(rowData.join(","));
    }
    // console.log(csvData);
    mockupContent = csvData;

  }

  return mockupContent;
}


module.exports = {
  parseFilter,
  parsePayload,
  getMockedData
}