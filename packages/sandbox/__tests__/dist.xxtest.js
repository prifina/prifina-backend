
const { parseFilter } = require("@prifina-backend/utils");

describe("todo", () => {

  it.todo("something");
  console.log("PARSE ", parseFilter("{\"s3::date\":{\">=\":\"2022-11-24\"}}"));

});  