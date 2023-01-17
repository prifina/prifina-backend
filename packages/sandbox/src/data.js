
const {
  awsUtils
} = require("@prifina-backend/shared");


const { parseFilter, parsePayload, getMockedData } = require("@prifina-backend/utils");


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

      const {
        awsUtils
      } = require("@prifina-backend/shared");

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
  getSandboxData
}
