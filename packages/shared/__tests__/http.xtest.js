

import { server } from './mocks/server';

const { NodeHttpHandler } = require("@aws-sdk/node-http-handler");

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

//const nodeHttpHandler = new NodeHttpHandler();

describe("http", () => {
  it("can send http requests", async () => {
    //"http://localhost:5000/api";

    const client = new NodeHttpHandler();
    const { response } = await client.handle(
      {
        hostname: "localhost",
        method: "GET",
        port: 5000,
        protocol: "https:",
        path: "/api/tasks",
        headers: {},
      },
      {}
    );
    console.log(
      "RESPONSE",
      response.statusCode + " " + response.body.statusMessage
    );

    let responseBody = "";
    try {
      // const res = await nodeHttpHandler.handle(signedHttpRequest);
      const body = await new Promise((resolve, reject) => {
        //let body = "";
        response.body.on("data", (chunk) => {
          responseBody += chunk;
        });
        response.body.on("end", () => {
          client.destroy();
          resolve(responseBody);
        });
        response.body.on("error", (err) => {
          client.destroy();
          reject(err);
        });
      });
      console.log(body);
    } catch (err) {
      console.error("Error:");
      console.error(err);
      client.destroy();
    }
    console.log("BODY ", responseBody);


  });
});  