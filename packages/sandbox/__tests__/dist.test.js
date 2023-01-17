
import TEST from "../dist/esm/index";

describe("todo", () => {

  it.todo("something");
  console.log("PARSE ", TEST.parseFilter("{\"s3::date\":{\">=\":\"2022-11-24\"}}"));

});  