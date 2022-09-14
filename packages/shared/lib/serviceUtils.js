const { ExpectedAttributeValue } = require("@aws-sdk/client-dynamodb");
const {
  getItem,
  updateItem,
  scanItems,
  s3ObjectInfo,
  s3GetObject,
  s3PutObject,
  s3DeleteObject,
  s3DeleteObjects,
  s3CopyObject,
  s3SelectObject,
  ebPutEvents,
  athenaGetQueryExecution,
  athenaGetQueryResults,
  athenaStartQueryExecution,
  s3WriteGetObjectResponse,
} = require("./awsUtils");

const { createNonce } = require("./libUtils");

function addPrifinaUser(data) {
  const createdAt = new Date().toISOString();

  const installedApps = JSON.parse(
    '["Settings","DataConsole","AppMarket","SmartSearch","DisplayApp","ProfileCards","DevConsole"]'
  );

  const params = {
    TableName: "PrifinaUser",
    Key: { id: data.uuid },
    UpdateExpression:
      "set createdAt=:createdAt,installedApps=:installedApps,cognito_id=:prifina,appProfile=:profile ",
    ExpressionAttributeValues: {
      ":createdAt": createdAt,
      ":installedApps": installedApps,
      ":prifina": data.user_id,
      ":profile": { name: data.name, initials: "" },
    },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

function addVerification(data) {
  const createdAt = new Date().toISOString();
  // expires after 1h
  // data.expiration_date=Math.ceil((Date.now() + ( 1 * 60 * 60 * 1000)) / 1000)
  // expires after 5min
  //expires = Math.ceil((Date.now() + 5 * 60 * 1000) / 1000);
  const expires = Math.ceil((Date.now() + 1 * 60 * 60 * 1000) / 1000);

  const params = {
    TableName: "Verifications",
    Key: { user_code: data.user_code },
    UpdateExpression: "set createdAt=:createdAt,expire=:expires",
    ExpressionAttributeValues: { ":createdAt": createdAt, ":expires": expires },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}
function updateNotificationQueue(notificationKey, item, expire = null) {
  // 30mins....
  const ttl = 30;
  const d = Math.ceil(new Date().getTime() / 1000);
  if (expire === null) {
    expire = d + 60 * ttl;
  }
  // expect expire is mins....
  if (expire < d) {
    expire = d + 60 * expire;
  }

  //Math.ceil((new Date().getTime()+(60*60*24*14*1000))/1000),
  const params = {
    TableName: "NotificationQueue",
    Key: { dataSource: notificationKey },
    UpdateExpression: "SET #notification = :notification,#expires=:expires",
    ExpressionAttributeNames: {
      "#expires": "expire",
      "#notification": "notification",
    },
    ExpressionAttributeValues: {
      ":notification": item,
      ":expires": expire,
    },
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}
function getDataSourceUsers(dataSource = null) {
  let params = {
    TableName: "DataSourceStatus",

    ProjectionExpression: "#id",
    //FilterExpression: "#dataSource = :dataSource",
    ExpressionAttributeNames: {
      "#id": "id",
    },
    ExpressionAttributeValues: {},
  };
  if (dataSource) {
    params.FilterExpression = "#dataSource = :dataSource";
    params.ExpressionAttributeNames["#dataSource"] = "dataSource";
    params.ExpressionAttributeValues[":dataSource"] = dataSource;
  }
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return scanItems(params);
}

function updateUserDataSourceStatus(
  prifinaID,
  source,
  sourceUserID = "",
  attrName,
  attrValue
) {
  const d = new Date().toISOString();
  let ExpressionAttributeValues = {
    ":attrValue": attrValue,
    ":updatedAt": d,
  };
  let ExpressionAttributeNames = {
    "#attrName": attrName,
    "#updatedAt": "updatedAt",
  };
  let UpdateExpression = "SET  #attrName= :attrValue,#updatedAt=:updatedAt";
  if (sourceUserID !== "") {
    ExpressionAttributeValues[":sourceUserID"] = sourceUserID;
    ExpressionAttributeNames["#sourceUserID"] = "sourceUserID";
    UpdateExpression += ",#sourceUserID= :sourceUserID";
  }
  const params = {
    TableName: "DataSourceStatus",
    Key: { id: prifinaID, dataSource: source },
    UpdateExpression: UpdateExpression,
    ExpressionAttributeValues: ExpressionAttributeValues,
    ExpressionAttributeNames: ExpressionAttributeNames,
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

function updateUserDataSource(prifinaID, source, status = 1) {
  return new Promise(function (resolve, reject) {
    getItem({
      TableName: "PrifinaUser",
      Key: { id: prifinaID },
    }).then((res, err) => {
      if (err) {
        reject(err);
      } else {
        const d = new Date().toISOString();
        let params = {};
        if (!res.Item.hasOwnProperty("dataSources")) {
          params = {
            TableName: "PrifinaUser",
            Key: { id: prifinaID },
            UpdateExpression:
              "SET #dataSources=:dataSource,#updatedAt=:updatedAt",
            ConditionExpression: "attribute_not_exists(dataSources)",
            ExpressionAttributeNames: {
              "#dataSources": "dataSources",
              "#updatedAt": "modified",
            },
            ExpressionAttributeValues: {
              ":dataSource": { [source]: { status: status } },
              ":updatedAt": d,
            },
          };
        } else {
          params = {
            TableName: "PrifinaUser",
            Key: { id: prifinaID },
            UpdateExpression:
              "SET dataSources.#source = :v,#updatedAt=:updatedAt",
            ExpressionAttributeNames: {
              "#source": source,
              "#updatedAt": "modified",
            },
            ExpressionAttributeValues: {
              ":v": { status: status },
              ":updatedAt": d,
            },
          };
        }
        if (
          (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
          process.env.hasOwnProperty("JEST_WORKER_ID")
        ) {
          console.log("PARAMS", params);
        }

        resolve(updateItem(params));
      }
    });
  });
  /*
  const params = {
    TableName: "PrifinaUser",
    Key: { id: prifinaID },
    UpdateExpression: "SET dataSources.#source = :v,#updatedAt=:updatedAt",
   
    ExpressionAttributeNames: {
      "#source": source,
      "#updatedAt": "modified",
    },
    ExpressionAttributeValues: {
      ":v": { status: status },
      ":updatedAt": d,
    },
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
*/
}

function getS3ObjectInfo(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return new Promise(function (resolve, reject) {
    s3ObjectInfo(params).then(
      (res) => {
        //console.log("RESOLVED ", res);
        if (res) {
          resolve(res);
        } else {
          resolve({});
        }
      },
      (error) => {
        //console.log("REJECTED ", error);
        reject(error);
      }
    );
    /*
    s3ObjectInfo(params, function (err, data) {
      if (err) {
        //console.log(err, err.stack);
        //reject(false);
        if (err.code === "NotFound") {
          resolve({});
        } else {
          reject(err);
        }
      } // an error occurred
      else {
        resolve(data);
      }
    });
    */
  });
}
function deleteS3Object(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3DeleteObject(params);
}

function deleteS3Objects(s3Bucket, s3Keys) {
  let params = {
    Bucket: s3Bucket,
    Delete: { Objects: [] },
  };
  s3Keys.forEach((k) => {
    params.Delete.Objects.push({ Key: k });
  });

  console.log("PARAMS", params.Delete.Objects[0]);

  return s3DeleteObjects(params);
}
function getS3Object(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3GetObject(params);
}
function putS3Object(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
    Body:body,
    ContentType:contentType
  };
  
  Metadata: {
    "Content-Type": "application/json",
    "alt-name": "fitbit-access-tokens",
  },
*/
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3PutObject(params);
}
function copyS3Object(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3CopyObject(params);
}

function selectS3Object(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3SelectObject(params);
}

function writeGetS3ObjectResponse(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3WriteGetObjectResponse(params);
}
function saveUserData(
  dataBucket,
  dataKey,
  data,
  contentType = "application/json"
) {
  return putS3Object({
    Bucket: dataBucket,
    Key: dataKey,
    Body: data,
    ContentType: contentType,
  });
}

function fileExists(bucket, file) {
  const params = {
    Bucket: bucket,
    Key: file,
  };
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return new Promise(function (resolve, reject) {
    s3ObjectInfo(params).then(
      (res) => {
        //console.log("RESOLVED ", res);
        resolve(res);
      },
      (error) => {
        //console.log("REJECTED ", error);
        reject(error);
      }
    );
    /*

    s3ObjectInfo(params, function (err, data) {
      console.log("FILE EXISTS ", data);

      if (err) {
        console.log("FILE ERROR ");
        console.log(err, err.stack);
        //reject(false);
        if (err.code === "NotFound") {
          resolve({});
        } else {
          reject(err);
        }
      } // an error occurred
      else {
        resolve(true);
      }
    });
    */
  });
}

function addNewEvents(params) {
  return ebPutEvents(params);
}
function getDDBItem(params) {
  return getItem(params);
}
function updateDDBItem(params) {
  return updateItem(params);
}
function scanDDBItems(params) {
  return scanItems(params);
}
function getAthenaQueryResults(params) {
  return athenaGetQueryResults(params);
}
function getAthenaQueryExecution(params) {
  return athenaGetQueryExecution(params);
}
function startAthenaQueryExecution(params) {
  return athenaStartQueryExecution(params);
}

function addNotification(data) {
  //const createdAt = new Date().getTime();
  const createdAt = new Date().toISOString();

  const notificationId = createNonce(12);

  const type = data.type;
  const body = data.body;
  const status = data.status;
  const prifinaID = data.prifinaID;
  const eventType = data.event;

  /*
type Notification @aws_iam {
	body: String!
	createdAt: AWSTimestamp!
	notificationId: String!
	owner: String!
	sender: String
	status: Int!
	type: String!
	updatedAt: AWSTimestamp!
}
$util.qr($ctx.args.input.put("createdAt", $util.defaultIfNull($ctx.args.input.createdAt, $util.time.nowEpochMilliSeconds() )))
$util.qr($ctx.args.input.put("updatedAt", $util.defaultIfNull($ctx.args.input.updatedAt, $util.time.nowEpochMilliSeconds() )))
$util.qr($ctx.args.input.put("status", $util.defaultIfNull($ctx.args.input.status, 0)))

## $util.qr($input.put("notificationId", $util.defaultIfNull($input.notificationId, $util.autoId())))

{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": {
  "notificationId":   $util.dynamodb.toDynamoDBJson($util.defaultIfNull($ctx.args.input.notificationId, $util.autoId()))
  },
  "attributeValues": $util.dynamodb.toMapValuesJson($ctx.args.input)
}

*/

  // expires after 1week
  const expire = Math.ceil((Date.now() + 7 * 24 * 60 * 60 * 1000) / 1000);

  const params = {
    TableName: "Notifications",
    Key: { notificationId: notificationId },
    UpdateExpression:
      "SET   #expire= :expire,#type= :type,#event= :event,#body= :body,#status= :status, #owner= :prifinaID,#updatedAt=:updatedAt,#createdAt=:createdAt",
    ExpressionAttributeValues: {
      ":type": type,
      ":event": eventType,
      ":body": body,
      ":status": status,
      ":prifinaID": prifinaID,
      ":updatedAt": createdAt,
      ":createdAt": createdAt,
      ":expire": expire,
    },
    ExpressionAttributeNames: {
      "#type": "type",
      "#event": "event",
      "#body": "body",
      "#status": "status",
      "#owner": "owner",
      "#updatedAt": "updatedAt",
      "#createdAt": "createdAt",
      "#expire": "expire",
    },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

/*
fileExists(
  "prifina-core-352681697435-eu-west-1",
  "integrations/fitbit/9G7RZB.json"
).then((res) => {
  console.log("TEST ", res);
});
*/
module.exports = {
  addPrifinaUser,
  addVerification,
  updateNotificationQueue,
  getDataSourceUsers,
  updateUserDataSource,
  updateUserDataSourceStatus,
  getS3ObjectInfo,
  deleteS3Object,
  deleteS3Objects,
  getS3Object,
  putS3Object,
  copyS3Object,
  selectS3Object,
  saveUserData,
  fileExists,
  addNewEvents,
  getDDBItem,
  updateDDBItem,
  scanDDBItems,
  getAthenaQueryExecution,
  getAthenaQueryResults,
  startAthenaQueryExecution,
  writeGetS3ObjectResponse,
  addNotification,
};
