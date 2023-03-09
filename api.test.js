const superTest = require("supertest");
const server = require("./api/server");
const db = require("./data/db-config");
const jwt = require("jsonwebtoken");
const secret = require("./api/secrets");


beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});

beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});
beforeEach(async () => {
  await db.seed.run();
});
afterAll(async () => {
  await db.destroy();
});

it("[0] env ayarları doğru mu?", () => {
  expect(process.env.NODE_ENV).toBe("testing");
});

describe("[POST] api/auth/login", () => {
  it("[1] login oluyor mu?", async () => {
    const response = await superTest(server)
      .post("/api/auth/login")
      .send({ username: "bob", password: "1234" });
    expect(response.status).toBe(200);
  }, 1000);

  it("[2] hatalı bilgilerle login olmuyor", async () => {
    const response = await superTest(server)
      .post("/api/auth/login")
      .send({ username: "Sue", password: "12345" });
    expect(response.status).toBe(401);
  }, 1000);

  it("[6] doğru token var mı?", async () => {
    const res = await superTest(server)
      .post("/api/auth/login")
      .send({ username: "bob", password: "1234" });

    const token = res.body.token;
    let tokenUsername;

    const jwtDecoded = await jwt.verify(
      token,
      secret.JWT_SECRET,
      (err, decodedToken) => {
        tokenUsername = decodedToken.username;
      }
    );
    expect(tokenUsername).toBe("bob");
  }, 1000);
});

describe("[POST] auth/register", () => {
  it("[3] yeni kullanıcı adnı doğru dönüyor", async () => {
    await superTest(server).post("/api/auth/register").send({
      username: "angelinajolie",
      password: "1234",
      role_name: "actrist",
    });
    const newUser = await db("users").where("username", "angelinajolie").first();
    expect(newUser.username).toBe("angelinajolie");
  }, 1000);

  it("[4] status kodu 201 dönüyor mu", async () => {
    const res = await superTest(server)
      .post("/api/auth/register")
      .send({ username: "angelinajolie", password: "1234" });
    expect(res.status).toBe(201);
  }, 1000);

  it("[5] role_name adminse hata mesaji dönüyor mu", async () => {
    let response = await superTest(server).post("/api/auth/register").send({
      username: "angelinajolie",
      password: "12344",
      role_name: "admin",
    });
    expect(response.body.message).toMatch(/admin olamaz/i);
  }, 1000);
});


describe("[GET] /users", () => {
  it("[7] login kullanıcı users'ı alabiliyor mu", async () => {
 const response = await superTest(server)
 .post("/api/auth/login").send({
      username: "bob",
      password: "12344",});
      const token=response.body.token;
      const response2= await superTest(server)
      .get("/api/users").set("authorization",token);
      expect (response2.body[0].username).toBe("bob")
    });

    it("[8] login kullanıcı users'ı alabiliyor mu", async () => {
      const response = await superTest(server)
      .post("/api/auth/login").send({
           username: "bob",
           password: "12344",});
           const token=response.body.token;
           const response2= await superTest(server)
           .get("/api/users/1").set("authorization",token);
           expect (response2.body.username).toBe("bob")
         });
  });